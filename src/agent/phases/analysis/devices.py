"""Device prompt preparation, model invocations and coordinated outcomes."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import logging
import os
import time
from src.agent.core import runtime
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.core.executor import EvidenceWriteError
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.analysis import block_recovery
from src.agent.phases.analysis.evidence import bound_scan_evidence
from src.agent.phases.analysis.prompts import ROLE_SPECIFIC_RULES
from src.agent.phases.analysis.context import (
    AnalysisContext, ScanResult, DeviceResult, DeviceAnalysisResult,
)

log = logging.getLogger(__name__)

PHASE3_RECOVERY_GRACE_S = 180.0


def recovery_grace_s() -> float:
    """Bounded extra time for Phase 3 block recovery (operator-overridable)."""
    try:
        value = float(str(os.environ.get("LANCE_PHASE3_RECOVERY_GRACE_S", "")).strip())
    except (TypeError, ValueError):
        return PHASE3_RECOVERY_GRACE_S
    return value if value > 0 else PHASE3_RECOVERY_GRACE_S


def _recovery_deadline(device_deadline: float | None, context: AnalysisContext) -> float | None:
    """Extend the device deadline with a bounded recovery grace.

    The main device call may consume its whole budget looping on tool
    searches; block recovery still needs one bounded model invocation to
    synthesize the deliverable from observations. The grace never exceeds
    the run cap.
    """
    if device_deadline is None:
        return None
    extended = device_deadline + recovery_grace_s()
    if context.max_duration_s is not None and context.run_started is not None:
        extended = min(extended, context.run_started + context.max_duration_s)
    return extended


def analysis_worker_count(context: AnalysisContext, device_count: int) -> int:
    if context.experiment_scope == "analysis-verification":
        return 1
    if context.local_moe or getattr(context.provider, "provider", "") == "ollama-umons":
        return 1
    configured = os.environ.get("LANCE_PHASE3_WORKERS", "").strip()
    if configured.isdigit() and int(configured) > 0:
        return min(int(configured), max(1, device_count))
    if device_count >= 12:
        return min(2, device_count)
    return max(1, min(device_count, 6))


def project_scan(profile, scan_data: dict, device_id: str) -> dict:
    if not profile.routed_tools:
        return scan_data
    from src.agent.phases.analysis.compact import CompactAnalysisPhase
    compact = CompactAnalysisPhase._compact_phase3_scan_results(scan_data)
    compact["_evidence_projection"]["full_scan_artifact"] = f"03_scans/{device_id}.json"
    return compact


@dataclass(frozen=True)
class AnalysisSetup:
    tools: list[dict]
    phase4_catalog: list[str]
    timeout_s: float


@dataclass(frozen=True)
class DevicePrompt:
    variables: dict
    scan_data: dict
    memo_evidence: dict


def prepare_analysis(context: AnalysisContext) -> AnalysisSetup:
    # Limited, protocol-aware tool access. Device analyzers may perform
    # bounded application checks but cannot open a general shell.
    skill_tools = [t for t in runtime.SKILL_TOOLS if t["name"] == "cve_search"]
    analysis_tool_names = {
        "curl_headers", "http_get", "http_request", "redis_cmd", "tcp_send",
        "udp_send", "mtls_request", "tls_inspect",
    }
    available_recon_tools, _ = runtime.filter_unavailable_tools(runtime.RECON_TOOLS)
    recon_limited = [t for t in available_recon_tools if t["name"] in analysis_tool_names]
    analysis_candidates = context.services.apply_tool_policy(
        recon_limited + skill_tools + runtime.DELIVERABLE_TOOLS, 3
    )
    analysis_tools = [
        context.services.wrap_tool(t, phase=3, agent="vuln_analysis", config=context.config)
        for t in analysis_candidates
    ]
    phase4_tool_catalog = sorted({
        str(tool.get("name"))
        for tool in [*available_recon_tools, *runtime.SKILL_TOOLS, *runtime.DELIVERABLE_TOOLS]
        if tool.get("name") and not (
            context.sealed and tool.get("name") in runtime.SEALED_FORBIDDEN_TOOLS
        )
    })

    try:
        phase3_timeout_s = max(30.0, float(os.environ.get("LANCE_PHASE3_DEVICE_TIMEOUT_S", "240")))
    except (TypeError, ValueError):
        phase3_timeout_s = 240.0
    if context.analysis_limits:
        phase3_timeout_s = context.analysis_limits["device_timeout_s"]
    return AnalysisSetup(analysis_tools, phase4_tool_catalog, phase3_timeout_s)


def build_device_prompt(context: AnalysisContext, scan: ScanResult, device: dict) -> DevicePrompt:
    scanner_results = scan.observations
    device_id = device["id"]
    device_ip = device.get("ip", "unknown")
    device_type = device.get("type", "unknown")
    device_role = device.get("role", device_type)
    services = device.get("services", [])
    services_str = ", ".join(
        f"{s.get('name', 'unknown')}:{s.get('port', '?')}"
        for s in services
    )
    try:
        device_detail = json.loads(runtime.get_device_info(device_id))
    except Exception as exc:
        # A missing graph record should not cancel every sibling agent.
        log.warning("No detailed graph record for %s: %s", device_id, exc)
        device_detail = device
    device_os = device_detail.get("os_version", device_detail.get("firmware", "unknown"))

    scan_data = scanner_results.get(device_id, {})
    deliverable_file = f"03_device_{device_id}.json"

    # Compact models receive a bounded projection with an artifact
    # reference. Full models receive the complete scanner evidence, with
    # only verbose raw output bounded so heavy devices (e.g. routers)
    # fit the per-device time budget. Deterministic findings travel
    # separately in full and are never cut here.
    scan_for_prompt = project_scan(
        context.profile, scan_data, device_id
    )
    if not context.profile.routed_tools:
        scan_for_prompt = bound_scan_evidence(scan_for_prompt)

    variables = {**context.variables}
    if device.get("public_context"):
        variables["scenario_context"] = "Public inventory context: " + device["public_context"]
    variables["device_id"] = device_id
    variables["device_ip"] = device_ip
    variables["device_type"] = device_type
    variables["device_role"] = device_role
    variables["device_services"] = services_str
    variables["device_os"] = device_os
    variables["expected_deliverable"] = deliverable_file
    variables["scan_results"] = json.dumps(scan_for_prompt, separators=(',', ':'), ensure_ascii=False)
    variables["trivial_findings"] = json.dumps(
        scan_data.get("findings", []), separators=(',', ':'), ensure_ascii=False
    )

    # Inject network position context so the agent can reason about lateral movement
    from src.agent.tools.graph_tools import get_network_neighbors
    nbrs = get_network_neighbors(device_id)

    def _fmt_neighbor(n: dict) -> str:
        svcs = ", ".join(
            f"{s.get('name','?')}:{s.get('port','?')}"
            for s in n.get("services", [])
        )
        return f"{n.get('id', '?')} ({n.get('ip', '?')}){' [' + svcs + ']' if svcs else ''}"

    upstream_str = ", ".join(_fmt_neighbor(n) for n in nbrs["upstream"]) or "none (entry point)"
    downstream_str = ", ".join(_fmt_neighbor(n) for n in nbrs["downstream"]) or "none (dead end)"
    variables["network_neighbors_upstream"] = upstream_str
    variables["network_neighbors_downstream"] = downstream_str
    variables["network_role"] = nbrs["role"]
    variables["role_specific_rules"] = ROLE_SPECIFIC_RULES.get(
        device_role,
        "- No specific priority rules defined for this role. Follow general best practices."
    )
    local_context = {
        "device": {
            "id": device_id,
            "ip": device_ip,
            "type": device_type,
            "role": device_role,
            "os": device_os,
            "services": services,
            "neighbors": {
                "upstream": upstream_str,
                "downstream": downstream_str,
                "role": nbrs["role"],
            },
        },
        "scanner_projection": scan_for_prompt,
        "deterministic_findings": scan_data.get("findings", []),
        "canonical_json": deliverable_file,
        "full_scan_artifact": f"03_scans/{device_id}.json",
    }
    return DevicePrompt(variables, scan_data, local_context)


def analyze_local_memo(context: AnalysisContext, device: dict, prompt: DevicePrompt) -> None:
    device_id = str(device["id"])
    device_ip = device.get("ip", "unknown")
    local_context = prompt.memo_evidence
    local_prompt = (
        "You are a Phase 3 device analyst for a local small model. "
        "Produce a concise evidence-based analyst memo, not JSON and not a tool call. "
        "Do not claim that you saved anything. The deterministic scanner has already "
        "written the canonical JSON file; your complete memo will be preserved as a "
        "sidecar artifact. Discuss likely vulnerabilities, rejected/uncertain CVEs, "
        "and any useful nuance. Only call a CVE applicable when both the detected "
        "product/version and vulnerable range are explicit in the supplied evidence. "
        "Never invent facts.\n\nEVIDENCE:\n"
        + json.dumps(local_context, ensure_ascii=False)
    )
    context.tracker.start_phase(f"analyze_{device_id}")
    result_text = context.provider.chat_with_tools(
        system_prompt=local_prompt,
        user_message=f"Write the Phase 3 analyst memo for {device_id} now.",
        tools=[],
        max_turns=context.profile.phase3_local_max_turns,
        max_tokens=context.profile.phase3_local_max_tokens,
        cost_tracker=context.tracker,
        stream_callback=context.services.model_callback(
            context.emit, phase=3, agent=f"analyze_{device_id}"
        ),
        repeat_guard=False,
        stop_event=context.stop_event,
    )
    analysis_text = ""
    if result_text and result_text.strip() not in {
        "(max turns reached)", "(malformed tool call JSON — max retries)",
    }:
        analysis_text = result_text.strip()
        if _looks_unusable_model_memo(analysis_text):
            log.warning(
                "Phase 3 local memo for %s appears unusable; keeping canonical JSON only",
                device_id,
            )
        else:
            sidecar = context.run_dir / f"03_device_{device_id}_analysis.md"
            sidecar.write_text(analysis_text + "\n", encoding="utf-8")
            context.services.model_callback(
                None, phase=3, agent=f"analyze_{device_id}_result"
            )({"type": "text_chunk", "text": analysis_text})
    usage = context.tracker.end_phase()
    if not analysis_text or _looks_unusable_model_memo(analysis_text):
        raise RuntimeError(
            "missing_validated_deliverable: no usable Phase 3 analysis memo"
        )
    if usage:
        print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns")
    if context.emit:
        context.emit({
            "type": "device_done", "device_id": device_id,
            "device_ip": device_ip, "phase": 3,
            "turns": usage.turns if usage else 0,
            "run_dir": str(context.run_dir),
        })
    return


def capture_device_tools(device_tools: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    save_receipts: list[dict] = []
    observations: list[dict] = []
    captured_tools = []
    for tool in device_tools:
        if tool.get("name") != "save_deliverable":
            original_fn = tool["function"]

            def record_observation_call(*args, _original=original_fn,
                                        _name=str(tool.get("name")), **kwargs):
                raw_result = _original(*args, **kwargs)
                try:
                    block_recovery.record_observation(
                        observations, _name,
                        raw_result if isinstance(raw_result, str)
                        else json.dumps(raw_result, ensure_ascii=False, default=str),
                        kwargs=kwargs,
                    )
                except Exception:
                    log.debug("Could not retain Phase 3 observation", exc_info=True)
                return raw_result

            captured_tools.append({**tool, "function": record_observation_call})
            continue
        original_save = tool["function"]

        def capture_save(*args, _original=original_save, **kwargs):
            raw_receipt = _original(*args, **kwargs)
            try:
                receipt = json.loads(raw_receipt) if isinstance(raw_receipt, str) else raw_receipt
            except (TypeError, ValueError, json.JSONDecodeError):
                receipt = None
            if isinstance(receipt, dict):
                save_receipts.append(receipt)
            return raw_receipt

        captured_tools.append({**tool, "function": capture_save})
    return captured_tools, save_receipts, observations


def analyze_full_device(
    context: AnalysisContext, setup: AnalysisSetup, device: dict, prompt: DevicePrompt,
) -> None:
    device_id = str(device["id"])
    device_ip = device.get("ip", "unknown")
    scan_data = prompt.scan_data
    variables = prompt.variables
    deliverable_file = variables["expected_deliverable"]
    analysis_tools = setup.tools
    phase4_tool_catalog = setup.phase4_catalog
    phase3_timeout_s = setup.timeout_s
    allowed_tool_names = runtime.phase3_tool_names(
        context.profile, device, scan_data
    )

    device_config = runtime.AgentConfig(
        name=f"analyze_{device_id}",
        phase=3,
        prompt_template="analyze_device",
        deliverable_file=deliverable_file,
        tools=[],
        validator="json_device_vulns",
    )
    device_tools = context.services.save_transaction(
        [
            tool for tool in analysis_tools
            if tool.get("name") in allowed_tool_names
        ],
        device_config,
        context.emit,
    )
    device_tools, save_receipts, observations = capture_device_tools(device_tools)
    variables["phase3_allowed_tools"] = ", ".join(
        sorted({
            str(tool.get("name")) for tool in device_tools
            if tool.get("name")
        })
    )
    variables["phase4_tool_catalog"] = ", ".join(phase4_tool_catalog)
    system_prompt = runtime.load_prompt("analyze_device", variables)
    device_deadline = time.monotonic() + phase3_timeout_s
    if context.max_duration_s is not None and context.run_started is not None:
        device_deadline = min(device_deadline, context.run_started + context.max_duration_s)
    full_completion: dict = {}
    context.tracker.start_phase(f"analyze_{device_id}")
    result_text = context.provider.chat_with_tools(
        system_prompt=system_prompt,
        user_message=(
            f"Review scan results for {device_id} ({device_ip}). "
            f"Add confirmed CVE, data exposure, authorization, identity, update, and protocol findings. "
            f"Then call save_deliverable('{deliverable_file}', json_content)."
        ),
        tools=device_tools,
        max_turns=context.profile.phase3_max_turns,
        max_tokens=context.profile.phase3_max_tokens,
        cost_tracker=context.tracker,
        stream_callback=context.services.model_callback(
            context.emit, phase=3, agent=f"analyze_{device_id}"
        ),
        required_tool="save_deliverable",
        terminate_after_tool="save_deliverable",
        # Reserve the final turns for a required save and its validation repair.
        # This uses the existing turn, deadline and cost bounds.
        finalize_required_tool_on_stall=context.profile.name == "full",
        stop_event=context.stop_event,
        deadline=device_deadline,
        completion_metadata=full_completion,
    )
    usage = context.tracker.end_phase()
    promoted, validation_error = context.services.promoted_deliverable(
        device_id, deliverable_file, save_receipts[-1] if save_receipts else None
    )
    if context.profile.name == "full" and block_recovery.is_truncation(full_completion):
        # A parseable save in a cut-short response is not a completed analysis.
        promoted = False
    if not promoted:
        if (context.profile.name == "full"
                and block_recovery.is_truncation(full_completion)):
            log.warning(
                "Phase 3 analysis for %s truncated on the output budget; "
                "attempting bounded block recovery",
                device_id,
            )
            context.services.recover_device(
                device=device,
                scan_data=scan_data,
                deliverable_file=deliverable_file,
                device_tools=device_tools,
                save_receipts=save_receipts,
                observations=observations,
                deadline=_recovery_deadline(device_deadline, context),
                stream_callback=context.emit,
            )
            promoted, validation_error = context.services.promoted_deliverable(
                device_id, deliverable_file,
                save_receipts[-1] if save_receipts else None,
            )
            if promoted:
                if usage:
                    print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns (block recovery)")
                if context.emit:
                    context.emit({
                        "type": "device_done", "device_id": device_id,
                        "device_ip": device_ip, "phase": 3,
                        "turns": usage.turns if usage else 0,
                        "run_dir": str(context.run_dir),
                        "recovered_from_truncation": True,
                    })
                return
            raise RuntimeError(validation_error)
        log.warning(
            "Phase 3 analysis for %s did not produce a validated promoted deliverable; "
            "scanner findings remain canonical",
            device_id,
        )
        raise RuntimeError(validation_error)
    if usage:
        print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns")
    if context.emit:
        context.emit({
            "type": "device_done", "device_id": device_id,
            "device_ip": device_ip, "phase": 3,
            "turns": usage.turns if usage else 0,
            "run_dir": str(context.run_dir),
        })


def analyze_device(context, setup, scan, device) -> None:
    prompt = build_device_prompt(context, scan, device)
    device_id = str(device["id"])
    device_ip = device.get("ip", "unknown")
    print(f"  [+] Analyzing: {device_id} ({device_ip})")
    if context.emit:
        context.emit({"type": "device_start", "device_id": device_id,
                      "device_ip": device_ip, "phase": 3})
    if context.compact_local:
        analyze_local_memo(context, device, prompt)
    else:
        analyze_full_device(context, setup, device, prompt)


def analyze_devices(context: AnalysisContext, scan: ScanResult) -> DeviceAnalysisResult:
    if scan.skipped:
        return DeviceAnalysisResult()
    if context.decision_policy == "rules":
        return DeviceAnalysisResult(
            tuple(DeviceResult(str(device.get("id", ""))) for device in scan.devices), 1,
        )
    print(f"\n{'=' * 60}\nPHASE 3b: LLM ANALYSIS ({len(scan.devices)} devices)\n{'=' * 60}\n")
    setup = prepare_analysis(context)
    worker_count = analysis_worker_count(context, len(scan.devices))
    if worker_count == 1 and len(scan.devices) > 1:
        log.info("Phase 3: serial device analysis (provider=%s, workers=1)",
                 getattr(context.provider, "provider", "unknown"))

    def worker(indexed_device) -> DeviceResult:
        if context.experiment_scope:
            context.services.check_limits()
        index, device = indexed_device
        device_id = str(device.get("id") or "unknown")
        if worker_count > 1 and index > 0:
            time.sleep(min(index * 2, 6))
        try:
            analyze_device(context, setup, scan, device)
            return DeviceResult(device_id)
        except (BudgetExceeded, EvidenceWriteError):
            raise
        except Exception as exc:
            if context.experiment_scope:
                context.services.check_limits()
            log.exception("Phase 3 analysis failed for %s; keeping scanner fallback", device_id)
            cause = "truncated_output" if str(exc).startswith("truncated_output:") else None
            context.services.persist_findings(device, scan.observations)
            if context.emit:
                context.emit({
                    "type": "device_done", "device_id": device_id,
                    "device_ip": device.get("ip", "unknown"), "phase": 3,
                    "turns": 0, "error": str(exc), **({"cause": cause} if cause else {}),
                })
            return DeviceResult(device_id, str(exc), cause)
        finally:
            # Terminal exceptions propagate too, after closing this thread's
            # usage. Completed invocations have already closed their phase.
            try:
                context.tracker.end_phase()
            except Exception:
                log.debug("Could not close Phase 3 tracker for %s", device_id, exc_info=True)

    # Workers own only their device outcome; the coordinator builds accounting.
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        outcomes = tuple(pool.map(worker, enumerate(scan.devices)))
    return DeviceAnalysisResult(outcomes, worker_count)
