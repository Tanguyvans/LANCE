"""Phase 2 recon split across a sweep agent and per-batch coverage agents.

A single generalist conversation resends the full tool history every turn,
so its context grows quadratically with the topology: it stalls around
15/36 devices on S12 with no save.  This module keeps the same tool
contract and the same validators, but bounds every model context:

- Stage A (sweep): one short agent for the discovery trio only
  (arp_scan, nmap_discovery, read_phase1), no coverage rows.
- Stage B (batches): one agent per small batch of coverage rows, each
  with a batch-scoped ledger, so every context stays O(batch).
- Stage C (merge): deterministic, no model.  Coverage is rebuilt from
  the shared tool ledger, rendered with the existing renderer, and
  validated with the existing recon validator.

A batch agent that scans its targets but fails to save a validated
receipt does not degrade the phase: the receipt is re-derived
deterministically from the shared ledger (flagged
``synthesized_from_ledger``) since Stage C already trusts that ledger
as the source of truth.  A failed batch degrades to
``executed_with_worker_errors`` only when its coverage is really
missing, instead of failing the whole phase.
"""
from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from collections.abc import Callable

from src.agent.core import runtime
from src.agent.core.executor import EvidenceWriteError
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.recon.rendering import render_recon
from src.agent.phases.recon.run import expand_port_spec

log = logging.getLogger(__name__)


RECON_SWEEP_DELIVERABLE = "02_recon_sweep.json"
RECON_BATCH_DELIVERABLE = "02_recon_batch_{:02d}.json"
RECON_DEVICES_PER_BATCH = 6
RECON_BATCH_MAX_TURNS = 20
RECON_BATCH_MAX_TOKENS = 2048


def devices_per_batch() -> int:
    """Batch size for recon coverage agents (operator-overridable)."""
    try:
        value = int(str(os.environ.get("LANCE_RECON_DEVICES_PER_BATCH", "")).strip())
    except (TypeError, ValueError):
        return RECON_DEVICES_PER_BATCH
    return value if value > 0 else RECON_DEVICES_PER_BATCH


def subagents_eligible(pipeline, config) -> bool:
    """Single-agent recon stays for modes the split path does not cover.

    Fan-out also stays off when the coverage plan fits in a single batch:
    one batch agent plus orchestration costs more turns than the generalist
    for zero context benefit. Blind mode (no declared topology) stays
    single-agent since unknown devices cannot be split upfront.
    """
    if getattr(pipeline, "dry_run", False):
        return False
    uses_compact = getattr(pipeline, "_uses_compact_local_moe", lambda: False)()
    if uses_compact:
        return False
    if getattr(pipeline, "decision_policy", "llm") != "llm":
        return False
    if getattr(pipeline, "sealed", False):
        return False
    if getattr(pipeline, "target_network", None):
        return False
    from src.agent.phases.recon.run import ReconPhase
    from src.agent.tools.graph_tools import _scenario_topology as topology
    nodes = (topology or {}).get("nodes", []) or []
    return len(ReconPhase._recon_scan_plan(nodes)) > devices_per_batch()


def split_recon_batches(plan_rows: list[dict], per_batch: int | None = None) -> list[list[dict]]:
    """Split coverage rows into ordered batches of at most ``per_batch``."""
    size = per_batch if per_batch and per_batch > 0 else devices_per_batch()
    return [list(plan_rows[index:index + size]) for index in range(0, len(plan_rows), size)]


def _scan_success(result: object) -> bool:
    """Mirror the contract guard: which ledger results count as success."""
    if str(result).startswith("Error"):
        return False
    try:
        payload = json.loads(result) if isinstance(result, str) else result
    except (TypeError, ValueError, json.JSONDecodeError):
        return True
    if not isinstance(payload, dict):
        return True
    return not (
        payload.get("ok") is False
        or bool(payload.get("error"))
        or payload.get("status") == "ERROR"
        or payload.get("return_code") not in (None, 0)
    )


def merge_recon_progress(
    plan_rows: list[dict],
    ledger_entries: list[dict],
    target_subnets: list[str],
) -> dict:
    """Rebuild the coverage ledger deterministically from tool history.

    Mirrors the live contract guard (success counting, two-strike failed
    probes, discovery trio) so the merge and the agents agree on what
    ``ready_to_save`` means.  Returns the same progress schema the
    renderer consumes.
    """
    expected = {str(item.get("target")): item for item in plan_rows if item.get("target")}
    covered: dict[str, set[int]] = defaultdict(set)
    failed: dict[str, set[int]] = defaultdict(set)
    failure_counts: dict[tuple[str, tuple[int, ...]], int] = defaultdict(int)
    completed = {"arp_scan": False, "nmap_discovery": set(), "read_phase1": False}

    for entry in ledger_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("phase") not in (None, 2, "2"):
            continue
        tool = entry.get("tool", "")
        args = entry.get("args", {}) or {}
        if not isinstance(args, dict):
            continue
        result = entry.get("result", "")
        success = _scan_success(result)
        if tool == "arp_scan" and success:
            completed["arp_scan"] = True
        elif tool == "nmap_discovery":
            target = str(args.get("target", ""))
            if success and target in target_subnets:
                completed["nmap_discovery"].add(target)
        elif tool == "read_deliverable":
            if success and args.get("filename") == "01_graph_analysis.md":
                completed["read_phase1"] = True
        elif tool == "nmap_scan":
            target = str(args.get("target", "")).strip()
            if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target):
                continue
            if target not in expected:
                continue
            requested = expand_port_spec(str(args.get("ports", "")))
            if success:
                covered[target].update(requested)
            else:
                signature = (target, tuple(sorted(requested)))
                failure_counts[signature] += 1
                if failure_counts[signature] >= 2:
                    covered[target].update(requested)
                    failed[target].update(requested)

    missing: list[dict] = []
    if not completed["arp_scan"]:
        missing.append({"requirement": "local_discovery", "tool": "arp_scan"})
    for subnet in target_subnets:
        if subnet not in completed["nmap_discovery"]:
            missing.append({
                "requirement": "subnet_discovery",
                "target": subnet,
                "tool": "nmap_discovery",
            })
    if not completed["read_phase1"]:
        missing.append({
            "requirement": "phase1_context",
            "filename": "01_graph_analysis.md",
            "tool": "read_deliverable",
        })
    targets = []
    for target, item in expected.items():
        required = expand_port_spec(str(item.get("ports", "")))
        targets.append({
            "target": target,
            "device_id": item.get("device_id", target),
            "role": item.get("role", "unknown"),
            "required_ports": sorted(required),
            "covered_ports": sorted(required & covered.get(target, set())),
            "failed_ports": sorted(required & failed.get(target, set())),
            "missing_ports": sorted(required - covered.get(target, set())),
        })
        absent = sorted(required - covered.get(target, set()))
        if absent:
            missing.append({
                "requirement": "minimum_port_coverage",
                "target": target,
                "missing_ports": absent,
                "suggested_tool": "nmap_scan",
            })
    return {
        "schema_version": "1",
        "completed": {
            "local_discovery": completed["arp_scan"],
            "subnet_discovery": all(
                subnet in completed["nmap_discovery"] for subnet in target_subnets
            ),
            "phase1_context": completed["read_phase1"],
        },
        "targets": targets,
        "missing_requirements": missing,
        "next_requirement": missing[0] if missing else None,
        "ready_to_save": not missing,
    }


def _capture_save_receipts(device_tools: list[dict]) -> tuple[list[dict], list[dict]]:
    """Wrap save_deliverable calls to retain their receipts for accounting."""
    receipts: list[dict] = []
    captured = []
    for tool in device_tools:
        if tool.get("name") != "save_deliverable":
            captured.append(tool)
            continue
        original = tool["function"]

        def capture(*args, _original=original, **kwargs):
            raw = _original(*args, **kwargs)
            try:
                receipt = json.loads(raw) if isinstance(raw, str) else raw
            except (TypeError, ValueError, json.JSONDecodeError):
                receipt = None
            if isinstance(receipt, dict):
                receipts.append(receipt)
            return raw

        captured.append({**tool, "function": capture})
    return captured, receipts


def _read_ledger_entries(run_dir) -> list[dict]:
    """Return parsed phase-2 tool ledger rows (best effort, never raises)."""
    try:
        lines = (run_dir / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    entries = []
    for line in lines:
        try:
            entry = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _batch_receipt_ok(run_dir, filename: str) -> bool:
    """A batch handshake counts when its file parses as JSON."""
    try:
        json.loads((run_dir / filename).read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return False
    return True


def _synthesize_batch_receipt(
    run_dir, deliverable: str, index: int,
    batch_rows: list[dict], target_subnets: list[str],
) -> bool:
    """Re-derive a missing batch receipt from the shared tool ledger.

    Returns True when a flagged receipt was written.  The batch-scoped
    check only requires this batch's own port coverage (the discovery
    trio belongs to the sweep stage); anything really missing keeps its
    worker error so the phase still degrades honestly.
    """
    from pathlib import Path

    try:
        progress = merge_recon_progress(
            batch_rows, _read_ledger_entries(run_dir), target_subnets)
    except Exception:
        log.debug("Batch %02d ledger receipt unavailable", index, exc_info=True)
        return False
    batch_targets = {
        str(row.get("target")) for row in batch_rows if row.get("target")
    }
    outstanding = [
        item for item in progress.get("missing_requirements", [])
        if item.get("requirement") == "minimum_port_coverage"
        and str(item.get("target")) in batch_targets
    ]
    if outstanding:
        return False
    by_target = {
        str(row.get("target")): row for row in progress.get("targets", [])
    }
    receipt = {
        "batch": f"{index:02d}",
        "status": "coverage recorded",
        "synthesized_from_ledger": True,
        "devices": [
            {
                "target": target,
                "device_id": by_target.get(target, {}).get("device_id", target),
                "covered_ports": by_target.get(target, {}).get("covered_ports", []),
                "failed_ports": by_target.get(target, {}).get("failed_ports", []),
            }
            for target in sorted(batch_targets)
        ],
        "note": (
            "Batch agent produced no validated receipt; coverage derived "
            "deterministically from the shared tool ledger."
        ),
    }
    try:
        Path(run_dir, deliverable).write_text(
            json.dumps(receipt, indent=2), encoding="utf-8")
    except OSError:
        log.debug("Batch %02d ledger receipt write failed", index, exc_info=True)
        return False
    return True


def run_recon_subagents(pipeline, config, tools: list[dict], stream_callback=None) -> str | None:
    """Sweep, per-batch coverage agents, then deterministic merge.

    Returns a terminal status string, or ``None`` when the topology has
    no coverage plan (caller falls back to the single-agent path).
    """
    from src.agent.tools import graph_tools

    topology = graph_tools._scenario_topology or {}
    nodes = topology.get("nodes", []) if isinstance(topology, dict) else []
    plan_rows = pipeline._recon_scan_plan(nodes)
    if not plan_rows:
        return None
    target_subnets = [
        value for value in str(pipeline.context.get("target_subnet", "")).split()
        if value
    ]
    emit = stream_callback
    if emit:
        emit({
            "type": "phase_start", "phase": config.phase, "name": config.name,
            "description": getattr(config, "description", ""),
            "deliverable": config.deliverable_file,
        })
    usage_before = pipeline.tracker.summary()
    pipeline.tracker.start_phase(config.name)
    errors: list[str] = []

    def check_stop() -> bool:
        stop_event = getattr(pipeline, "_stop_event", None)
        return stop_event is not None and stop_event.is_set()

    def run_agent(
        *, name: str, prompt_template: str, deliverable: str,
        agent_nodes: list[dict] | None, variables: dict,
        require_baseline: bool = True,
    ) -> bool:
        """Run one short agent with a batch-scoped contract; False on error."""
        batch_config = runtime.AgentConfig(
            name=name, phase=config.phase, prompt_template=prompt_template,
            deliverable_file=deliverable, tools=[],
            validator="json_valid",
        )
        agent_tools = pipeline._apply_deliverable_transaction(
            list(tools), batch_config, emit,
        )
        agent_tools = pipeline._apply_recon_tool_contract(
            agent_tools, nodes=agent_nodes, require_baseline=require_baseline,
        )
        agent_tools, receipts = _capture_save_receipts(agent_tools)
        pipeline.tracker.start_phase(name)
        try:
            pipeline.provider.chat_with_tools(
                system_prompt=runtime.load_prompt(prompt_template, variables),
                user_message=variables.get(
                    "user_message",
                    f"Complete recon {name}, then call save_deliverable('{deliverable}', ...).",
                ),
                tools=agent_tools,
                max_turns=RECON_BATCH_MAX_TURNS,
                max_tokens=RECON_BATCH_MAX_TOKENS,
                cost_tracker=pipeline.tracker,
                stream_callback=pipeline._model_stream_callback(
                    emit, phase=config.phase, agent=name,
                ),
                required_tool="save_deliverable",
                terminate_after_tool="save_deliverable",
                stop_event=getattr(pipeline, "_stop_event", None),
            )
        finally:
            try:
                pipeline.tracker.end_phase()
            except Exception:
                log.debug("Could not close tracker for %s", name, exc_info=True)
        promoted = bool(receipts) and _batch_receipt_ok(pipeline.run_dir, deliverable)
        if not promoted:
            log.warning("Recon %s produced no validated batch receipt", name)
        return promoted

    def base_variables() -> dict:
        return {
            **pipeline.context,
            "target_subnet": " ".join(target_subnets),
            "turn_budget": RECON_BATCH_MAX_TURNS,
            "available_skills": pipeline._filter_skills(config),
        }

    try:
        # Stage A: discovery trio only, no coverage rows.
        sweep_variables = {
            **base_variables(),
            "expected_deliverable": RECON_SWEEP_DELIVERABLE,
        }
        sweep_ok = run_agent(
            name="recon_sweep", prompt_template="recon_sweep",
            deliverable=RECON_SWEEP_DELIVERABLE, agent_nodes=[],
            variables=sweep_variables,
        )
        if not sweep_ok:
            errors.append("recon_sweep: no validated sweep receipt")
        if check_stop():
            return _finish("stopped", errors, usage_before, emit, pipeline, config)

        # Stage B: coverage batches with fresh contexts.
        node_by_target = {}
        for node in nodes:
            if isinstance(node, dict) and node.get("ip"):
                node_by_target.setdefault(str(node["ip"]), node)
        batches = split_recon_batches(plan_rows)
        for index, batch_rows in enumerate(batches, 1):
            if check_stop():
                return _finish("stopped", errors, usage_before, emit, pipeline, config)
            batch_nodes = [
                node_by_target[str(row["target"])]
                for row in batch_rows if str(row["target"]) in node_by_target
            ]
            deliverable = RECON_BATCH_DELIVERABLE.format(index)
            targets_text = "\n".join(
                f"- {row.get('device_id', row['target'])} ({row['target']}, "
                f"{row.get('role', 'unknown')}): ports {row.get('ports', '')}"
                for row in batch_rows
            )
            batch_variables = {
                **base_variables(),
                "batch_id": f"{index:02d}",
                "batch_targets": targets_text,
                "nmap_scan_groups": pipeline._build_nmap_groups(batch_nodes),
                "expected_deliverable": deliverable,
            }
            print(f"  [+] Recon batch {index}/{len(batches)} ({len(batch_rows)} devices)")
            try:
                ok = run_agent(
                    name=f"recon_batch_{index:02d}", prompt_template="recon_batch",
                    deliverable=deliverable, agent_nodes=batch_nodes,
                    variables=batch_variables, require_baseline=False,
                )
            except (BudgetExceeded, EvidenceWriteError):
                raise
            except Exception as exc:
                log.exception("Recon batch %d failed; merging available evidence", index)
                if _synthesize_batch_receipt(
                        pipeline.run_dir, deliverable, index,
                        batch_rows, target_subnets):
                    log.info("Recon batch %02d receipt synthesized from ledger",
                             index)
                else:
                    errors.append(f"recon_batch_{index:02d}: {exc}")
                continue
            if not ok:
                if _synthesize_batch_receipt(
                        pipeline.run_dir, deliverable, index,
                        batch_rows, target_subnets):
                    log.info("Recon batch %02d receipt synthesized from ledger",
                             index)
                else:
                    errors.append(
                        f"recon_batch_{index:02d}: no validated batch receipt")

        # Stage C: deterministic merge from the shared ledger.
        projection = pipeline._build_recon_evidence_projection()
        progress = merge_recon_progress(
            plan_rows, _read_ledger_entries(pipeline.run_dir), target_subnets,
        )
        if not progress["ready_to_save"]:
            missing = progress["missing_requirements"]
            return _finish(
                f"failed:recorded reconnaissance incomplete "
                f"({len(missing)} missing requirements)",
                errors + [f"missing: {json.dumps(missing[:5], ensure_ascii=False)}"],
                usage_before, emit, pipeline, config,
            )
        try:
            content = render_recon(projection, progress)
        except ValueError as exc:
            return _finish(f"failed:{exc}", errors, usage_before, emit, pipeline, config)
        (pipeline.run_dir / config.deliverable_file).write_text(content, encoding="utf-8")
        validator = pipeline._validator("recon_markdown")
        valid, message = validator(config.deliverable_file)
        if not valid:
            return _finish(f"failed:{message}", errors, usage_before, emit, pipeline, config)
        try:
            pipeline._reconcile_phase2_attack_surface(projection)
        except Exception as exc:
            log.warning("Phase 2 reconciliation failed: %s", exc)
        if errors:
            return _finish(
                "executed_with_worker_errors", errors,
                usage_before, emit, pipeline, config,
            )
        return _finish("completed", [], usage_before, emit, pipeline, config)
    finally:
        try:
            pipeline.tracker.end_phase()
        except Exception:
            log.debug("Could not close recon tracker", exc_info=True)


def _finish(
    status: str, errors: list[str], usage_before: dict,
    emit: Callable | None, pipeline, config,
) -> str:
    """Emit the terminal phase event with real cost/turn deltas."""
    usage_after = pipeline.tracker.summary()
    event = {
        "type": "phase_done",
        "phase": config.phase,
        "name": config.name,
        "status": status,
        "deliverable": config.deliverable_file,
        "cost_usd": round(usage_after["total_cost_usd"] - usage_before["total_cost_usd"], 4),
        "turns": usage_after["total_turns"] - usage_before["total_turns"],
    }
    if emit:
        emit(event)
    if status.startswith("failed"):
        log.error("Phase 2 recon sub-agents FAILED: %s", status)
    return status
