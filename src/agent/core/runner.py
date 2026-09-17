"""Model/tool execution, deliverable transactions and event forwarding."""
from __future__ import annotations
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from uuid import uuid4
import json
import logging
from src.agent.phases.intrusion.compact import COMPACT_INTRUSION_COMPLETION_TOOL
from src.agent.core import runtime
from src.agent.core.provider_diagnostics import (
    append_event,
    sanitize_event,
    warn_diagnostic_failure,
)
from src.agent.artifacts import (
    is_private_agent_artifact,
    is_private_agent_artifact_path,
    resolve_run_artifact,
)
from src.agent.tools.deliverable import bind_deliverable_tool


log = logging.getLogger(__name__)


class AgentRunner:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _validator(self, name: str) -> Callable[[str], tuple[bool, str]]:
        """Capture this run's directory; validators never consult mutable globals."""
        validator = runtime.VALIDATORS.get(name, runtime.VALIDATORS["default"])
        root = self.run_dir.resolve()

        def validate(filename: str) -> tuple[bool, str]:
            return validator(filename, output_dir=root)

        return validate

    def _model_stream_callback(
        self,
        downstream: Callable[[dict], None] | None,
        *,
        phase: int | str,
        agent: str,
    ) -> Callable[[dict], None]:
        """Archive complete model text chunks while forwarding live events."""
        def callback(event: dict) -> None:
            if isinstance(event, dict) and event.get("type") == "provider_diagnostic":
                record = sanitize_event(
                    event,
                    provider=getattr(self.provider, "provider", "unknown"),
                    model=getattr(self.provider, "model", "unknown"),
                    invocation_id=event.get("invocation_id"),
                    known_tools={
                        name for name in event.get("_known_tools", [])
                        if isinstance(name, str) and len(name) <= 96
                    },
                    phase=phase,
                    agent=agent,
                    run_id=getattr(self.run_dir, "name", None),
                )
                if record is not None:
                    # Provider names are normalised by the provider-side
                    # emitter; the callback remains the confidentiality
                    # boundary and never forwards this sidecar event.
                    if not append_event(self.run_dir, record, lock=self._artifact_log_lock):
                        warn_diagnostic_failure("write")
                return
            if event.get("type") == "text_chunk" and event.get("text"):
                record = {
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "phase": phase,
                    "agent": agent,
                    "text": event["text"],
                }
                with self._artifact_log_lock:
                    with (self.run_dir / "model_outputs.jsonl").open(
                        "a", encoding="utf-8"
                    ) as handle:
                        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            if downstream:
                downstream(event)
        # Provider diagnostics are an internal side-channel of this adapter;
        # direct provider callers retain the exact legacy event stream.
        callback._provider_diagnostics = True
        return callback

    def _apply_deliverable_transaction(
        self,
        tools: list[dict],
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> list[dict]:
        """Validate and archive every model submission before final promotion.

        Invalid attempts remain immutable evidence and are returned to the model
        as tool errors. The terminal tool therefore only ends the same
        conversation after a structurally valid submission.
        """
        wrapped: list[dict] = []
        for tool in tools:
            tool = bind_deliverable_tool(tool, self.run_dir)
            if tool["name"] != "save_deliverable":
                wrapped.append(tool)
                continue

            original = tool["function"]

            def transactional_save(
                filename: str | None = None,
                content: str = "",
                *,
                _original=original,
            ) -> str:
                target = filename or config.deliverable_file
                if target != config.deliverable_file:
                    return json.dumps({
                        "ok": False,
                        "error_kind": "unexpected_deliverable",
                        "error": (
                            f"This phase must save '{config.deliverable_file}', "
                            f"not '{target}'."
                        ),
                    })
                if not isinstance(content, str) or not content.strip():
                    return json.dumps({
                        "ok": False,
                        "error_kind": "empty_deliverable",
                        "error": "Deliverable content must be non-empty.",
                    })

                normalized = runtime._extract_json(content) if target.endswith(".json") else content
                strict_compact_graph = (
                    config.name == "graph_analysis"
                    and self._uses_compact_local_moe()
                )
                strict_compact_recon = (
                    config.name == "recon" and self._uses_compact_local_moe()
                )
                if strict_compact_graph:
                    normalized = self._render_compact_graph_markdown()
                elif strict_compact_recon:
                    normalized = self._finalize_compact_recon_markdown(normalized)
                safe_name = target.replace("/", "__").replace("\\", "__")
                attempt_dir = resolve_run_artifact(self.run_dir, f".attempts/{safe_name}")
                attempt_dir.mkdir(parents=True, exist_ok=True)
                suffix = Path(target).suffix or ".txt"
                attempt_path = attempt_dir / f"attempt-{uuid4().hex}{suffix}"
                attempt_path.write_text(normalized, encoding="utf-8")
                attempt_ref = attempt_path.relative_to(self.run_dir).as_posix()

                validator_fn = self._validator(config.validator)
                valid, validation_error = validator_fn(attempt_ref)
                if valid and config.name == "graph_analysis":
                    projection = self._build_graph_evidence_projection()
                    declared_ids = {
                        str(node.get("id")) for node in projection.get("nodes", [])
                        if isinstance(node, dict) and node.get("id")
                    }
                    covered_ids = set(projection.get("device_coverage", {}))
                    missing_coverage = sorted(declared_ids - covered_ids)
                    if missing_coverage:
                        valid, validation_error = False, (
                            "Graph evidence lacks per-device facts. Reuse "
                            "get_attack_surface coverage and call get_device_info "
                            "only for missing nodes: " + ", ".join(missing_coverage)
                        )
                    elif strict_compact_graph:
                        valid, validation_error = self._validate_compact_graph_projection(
                            normalized, projection
                        )
                elif valid and strict_compact_recon:
                    projection = json.loads(
                        (self.run_dir / "02_recon_evidence.json").read_text(
                            encoding="utf-8"
                        )
                    )
                    valid, validation_error = self._validate_compact_recon_projection(
                        normalized, projection
                    )
                entry = {
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "phase": config.phase,
                    "agent": config.name,
                    "filename": target,
                    "validator": config.validator,
                    "attempt_ref": attempt_ref,
                    "size": len(normalized),
                    "valid": valid,
                    "validation_error": None if valid else validation_error,
                }
                with self._artifact_log_lock:
                    with (self.run_dir / "deliverable_attempts.jsonl").open(
                        "a", encoding="utf-8"
                    ) as handle:
                        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
                if stream_callback:
                    stream_callback({"type": "deliverable_attempt", **entry})
                if not valid:
                    error_payload = {
                        "ok": False,
                        "error_kind": "deliverable_validation",
                        "error": validation_error,
                        "attempt_ref": attempt_ref,
                        "instruction": (
                            "Repair this archived draft and call save_deliverable "
                            "again. Do not repeat reconnaissance calls."
                        ),
                    }
                    if config.name == "recon":
                        projection = self._build_recon_evidence_projection()
                        error_payload["repair_context"] = {
                            "device_count": projection["device_count"],
                            "markdown_service_rows": projection["markdown_service_rows"],
                        }
                    return json.dumps(error_payload, ensure_ascii=False)

                result = _original(filename=target, content=normalized)
                try:
                    payload = json.loads(result)
                except (TypeError, ValueError, json.JSONDecodeError):
                    return result
                if isinstance(payload, dict):
                    payload["attempt_ref"] = attempt_ref
                    payload["validated"] = True
                    if (
                        config.name == "intrusion"
                        and payload.get("status") == "saved"
                        and payload.get("ok") is not False
                        and not payload.get("error")
                    ):
                        self._full_intrusion_saved = True
                return json.dumps(payload, ensure_ascii=False)

            wrapped.append({**tool, "function": transactional_save})
        return wrapped

    def _run_agent(self, config: runtime.AgentConfig, stream_callback: Callable[[dict], None] | None = None) -> str:
        """Run a single agent phase."""
        if config.name == "intrusion":
            self._compact_intrusion_runtime_tools = None
            self._phase5_pending_event = None
            self._phase5_terminal_status = None
            self._full_intrusion_saved = False
        # Set skill filter for this phase (hard filtering)
        filter_tags = config.skill_filter.get("tags") if config.skill_filter else None
        runtime.set_skill_filter(filter_tags)

        tools = self._resolve_tools(config)
        tools = runtime.filter_profile_tools(self.execution_profile, config.phase, tools)
        max_turns, max_tokens = self.execution_profile.limits_for_phase(
            config.phase, config.max_turns, config.max_tokens
        )
        local_intrusion_memo = (
            config.name == "intrusion" and self._uses_compact_local_moe()
        )
        full_intrusion = config.name == "intrusion" and self.execution_profile.name == "full"
        compact_local_recon = (
            config.name == "recon" and self._uses_compact_local_moe()
        )
        if local_intrusion_memo:
            tools = self._ensure_compact_intrusion_tools(
                tools, phase=config.phase, agent=config.name
            )
            tools = [tool for tool in tools if tool.get("name") != "save_deliverable"]
        tools = self._apply_deliverable_transaction(tools, config, stream_callback)
        # Full-profile Phase 1 keeps its autonomous report composition, but a
        # provider output truncation (finish_reason=length) with no validated
        # save is recoverable from the recorded graph observations. Compact
        # mode keeps its deterministic rendering and never enters this path.
        full_graph = (
            config.name == "graph_analysis"
            and self.execution_profile.name == "full"
            and not self._uses_compact_local_moe()
        )
        graph_completion: dict = {}
        if full_graph:
            # The provider records each response's finish_reason before
            # executing that response's tool calls, so the gate sees the
            # proposing response: a truncated response's save is rejected
            # before the transaction (never archived, promoted, or
            # validated), while every other save passes through untouched.
            tools = self._apply_truncated_save_gate(tools, graph_completion)
        if local_intrusion_memo:
            tools = self._apply_compact_intrusion_tool_contract(
                tools, phase=config.phase, agent=config.name
            )
            self._compact_intrusion_runtime_tools = tools

        # Build prompt variables
        variables = {**self.context}
        variables["previous_deliverables"] = self._list_previous_deliverables()
        variables["expected_deliverable"] = config.deliverable_file
        variables["available_skills"] = self._filter_skills(config)
        variables["turn_budget"] = max_turns
        variables["intrusion_campaign_stop_turn"] = max(1, int(max_turns * 0.875))
        variables["intrusion_completion_turn"] = max(1, int(max_turns * 0.9))
        if config.name == "intrusion":
            variables["intrusion_tool_guidance"] = (
                "- read_deliverable(filename) — read Phase 3/4 deliverables and the intrusion context\n"
                "- ssh_exec(ip, user, password, command) — run a shell command on a compromised host\n"
                "- udp_send(host, port, payload, encoding=\"hex\", recv_bytes=4096, timeout=5) — bounded CoAP/SNMP/BACnet UDP probe\n"
                "- tcp_send(host, port, payload_hex, recv_bytes=4096, timeout=10) — bounded OPC-UA/other protocol request\n"
                "- http_request(url, method, headers, body, follow_redirects=False) — bounded API/OTA/cloud request\n"
                "- modbus_scan(target, skip_discovery=true) — bounded Modbus protocol access check\n"
                "- try_credential(ip, service, user, password) — test credentials on ssh|http|ftp|mqtt|telnet|redis|mysql"
            )
            variables["intrusion_recon_tool_restriction"] = ", curl_headers, mqtt_listen"
            variables["intrusion_entry_validation"] = ""
            if local_intrusion_memo:
                variables["intrusion_tool_guidance"] = (
                    "- read_deliverable(filename) — read only the intrusion context\n"
                    "- mqtt_listen(broker, topic, count, timeout) — validate anonymous MQTT entry points\n"
                    "- http_get(url) / curl_headers(url) — validate HTTP entry points and exposed content\n"
                    "- udp_send(host, port, payload, encoding=\"hex\", recv_bytes=4096, timeout=5) — validate CoAP (5683) or SNMP (161) UDP entry points\n"
                    "- nmap_scan(target, ports=\"502\", scripts=\"modbus-discover\", skip_discovery=true) — validate Modbus entry points read-only\n"
                    "- ssh_login(command_string) — validate SSH entry points with the recovered source credential\n"
                    "- ssh_exec(ip, user, password, command) — run a shell command on a compromised host\n"
                    "- try_credential(ip, service, user, password) — test recovered credentials on a target\n"
                    "- telnet_connect(host, port=23, timeout=3) / ftp_list(url) — validate Telnet/FTP targets"
                )
                variables["intrusion_recon_tool_restriction"] = ""
                variables["intrusion_entry_validation"] = (
                    "## Compact entry validation — mandatory before credential reuse\n\n"
                    "- Perform exactly one service-appropriate probe for every entry point in 05_intrusion_context.json: "
                    "mqtt_listen for MQTT, http_get/curl_headers for HTTP, udp_send on the exact port for CoAP/SNMP, nmap_scan with ports=502 and scripts=modbus-discover for Modbus, telnet_connect for Telnet, and ssh_login "
                    "with the recovered source credential for SSH.\n"
                    "- Complete all entry-point probes before credential reuse. Then use try_credential against "
                    "every target with every recovered credential. "
                    "These are authorized Phase 5 actions, not Phase 2 scanning."
                )
                variables["intrusion_save_tool"] = (
                    f"- {COMPACT_INTRUSION_COMPLETION_TOOL}(summary=<short campaign summary>)"
                )
                variables[
                    "intrusion_completion_rule"
                ] = "Finish with one successful complete_intrusion_campaign call. The tool validates the ledger and commits 05_intrusion.json. If it returns ok=false, continue with the required Phase 5 tools and retry only after making progress."
                variables["intrusion_final_phase_title"] = "Complete compact campaign"
                variables[
                    "intrusion_final_instruction"
                ] = "Call complete_intrusion_campaign after reading 05_intrusion_context.json and performing the required service-appropriate action for every listed target/service. Do not stop before the tool reports success."
            else:
                variables["intrusion_save_tool"] = "- save_deliverable(filename=\"05_intrusion.json\", content=<full JSON>)"
                variables["intrusion_completion_rule"] = "Finish with one successful save_deliverable call. If it returns ok=false, repair the archived draft and retry without repeating data gathering."
                variables["intrusion_final_phase_title"] = "Save results"
                variables[
                    "intrusion_final_instruction"
                ] = "Call save_deliverable with the full JSON. Do not stop before the tool reports success."

        # Recon remains model-driven: the expert calls every tool itself.  The
        # contract only constrains its tool surface and prevents completion
        # until the mandatory discovery/read/scan ledger is satisfied.
        if config.name == "recon" and not self.dry_run:
            tools = self._apply_recon_tool_contract(tools)

        # Inject deliverable template if one exists
        template_path = runtime.AGENT_DIR / "templates" / config.deliverable_file
        if template_path.exists():
            template = template_path.read_text(encoding="utf-8")
            template = template.replace("{{run_date}}", datetime.now().astimezone().date().isoformat())
            template = template.replace("{{model}}", self.provider.model)
            variables["deliverable_template"] = template

        # Load and compose prompt
        prompt_template = (
            "intrusion_compact" if local_intrusion_memo
            else ("recon_compact" if compact_local_recon else config.prompt_template)
        )
        system_prompt = runtime.load_prompt(prompt_template, variables)

        # Print header
        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: {config.name.upper()}")
        print(f"  {config.description}")
        print(f"  Tools: {config.tools}")
        print(f"  Deliverable: {config.deliverable_file}")
        print(f"{'=' * 60}\n")

        if stream_callback:
            stream_callback({
                "type": "phase_start",
                "phase": config.phase,
                "name": config.name,
                "description": getattr(config, "description", ""),
                "deliverable": config.deliverable_file,
            })

        # If this phase has device sub-agents, run scanner + LLM analysis (Phase 3a+3b)
        if config.has_device_agents:
            self._run_phase3(config, stream_callback)

        # If this phase uses deterministic aggregation, skip the LLM and merge directly
        if config.deterministic_aggregation:
            self._aggregate_device_vulns(config, stream_callback)
            validator_fn = self._validator(config.validator)
            valid, msg = validator_fn(config.deliverable_file)
            if valid and config.name == "vuln_analysis":
                status = getattr(self, "_phase3_execution_status", None) or "completed"
            else:
                status = "completed" if valid else f"failed:{msg}"
            if valid:
                log.info("Phase %d deterministic aggregation validated: %s", config.phase, msg)
                print(f"  Deliverable validated: {config.deliverable_file}")
            else:
                log.error("Phase %d deterministic aggregation FAILED: %s", config.phase, msg)
                print(f"  Deliverable FAILED validation: {msg}")
            if stream_callback:
                stream_callback({
                    "type": "phase_done",
                    "phase": config.phase,
                    "name": config.name,
                    "status": status,
                    "deliverable": config.deliverable_file,
                    "cost_usd": 0,
                    "turns": 0,
                })
            return status

        # If this phase has exploit sub-agents, run them and skip the LLM aggregator
        if config.has_exploit_agents:
            self._run_exploit_agents(config, stream_callback)
            # Check for newly discovered hosts and run a mini analysis cycle if found
            new_hosts = self._collect_new_hosts()
            if new_hosts and not self.dry_run:
                self._run_discovery_followup(new_hosts, config, stream_callback)
            # Deterministic aggregation already wrote 04_exploitation.json
            validator_fn = self._validator(config.validator)
            valid, msg = validator_fn(config.deliverable_file)
            if valid:
                status = getattr(self, "_phase4_execution_status", None) or "completed"
            else:
                status = f"failed:{msg}"
            if valid:
                log.info("Phase %d exploit aggregation validated: %s", config.phase, msg)
                print(f"  Deliverable validated: {config.deliverable_file}")
            else:
                log.error("Phase %d exploit aggregation FAILED: %s", config.phase, msg)
                print(f"  Deliverable FAILED validation: {msg}")
            if stream_callback:
                stream_callback({
                    "type": "phase_done",
                    "phase": config.phase,
                    "name": config.name,
                    "status": status,
                    "deliverable": config.deliverable_file,
                    "cost_usd": 0,
                    "turns": 0,
                })
            return status

        # Run agent with cost tracking
        self.tracker.start_phase(config.name)
        try:
            result_text = self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=config.user_message,
                tools=tools,
                max_turns=max_turns,
                max_tokens=max_tokens,
                cost_tracker=self.tracker,
                stream_callback=self._model_stream_callback(
                    stream_callback, phase=config.phase, agent=config.name
                ),
                required_tool=(
                    COMPACT_INTRUSION_COMPLETION_TOOL if local_intrusion_memo
                    else "save_deliverable"
                ),
                terminate_after_tool=(
                    COMPACT_INTRUSION_COMPLETION_TOOL if local_intrusion_memo
                    else "save_deliverable"
                ),
                terminate_on_unavailable_tools=None,
                strict_required_tool=local_intrusion_memo or compact_local_recon,
                force_tool_on_stall=local_intrusion_memo or compact_local_recon,
                force_completion_on_recon_ready=compact_local_recon,
                reopen_intrusion_tools_on_contract_error=local_intrusion_memo,
                recover_required_tool_on_stall=local_intrusion_memo,
                **({"finalize_required_tool_on_stall": True} if full_intrusion else {}),
                # Recon has its own topology-aware progress contract.  The generic
                # save-only cycle guard can otherwise deadlock it after an early save.
                repeat_guard=config.name != "recon",
                stop_event=self._stop_event,
                # Caller-owned truncation metadata is only needed for the
                # full-profile Phase 1 recovery gate below.
                **({"completion_metadata": graph_completion} if full_graph else {}),
            )
        except Exception as exc:
            if not local_intrusion_memo:
                raise
            # A local proxy outage must not strand Phase 5 inside the provider
            # loop. The authoritative tool ledger is reconciled immediately by
            # _ensure_intrusion_deliverable after this method returns.
            log.warning("Compact Phase 5 model call failed; switching to ledger recovery: %s", exc)
            result_text = f"(compact local-MoE call failed: {type(exc).__name__})"
        # Compact local models sometimes stop immediately after the last
        # successful action and omit the required terminal tool call. The
        # guarded controller helper commits it only when the ledger is complete.
        if local_intrusion_memo:
            self._invoke_compact_intrusion_completion(tools, stream_callback)
        # usage will be recorded after validation

        # Validate deliverable
        # Compact local output is synthesized by the existing ledger-backed
        # completion tool, not accepted as a model submission. Keep that
        # completion contract distinct from the model's structural validator.
        validator_name = "json_valid" if local_intrusion_memo else config.validator
        validator_fn = self._validator(validator_name)
        valid, msg = validator_fn(config.deliverable_file)
        if full_intrusion and valid and not self._full_intrusion_saved:
            valid, msg = False, "Accepted Phase 5 submission not found in this execution"
        recovered_compact_recon = False
        if not valid and compact_local_recon:
            recovered_compact_recon = self._recover_compact_recon_deliverable(
                config, tools, stream_callback
            )
            if recovered_compact_recon:
                valid, msg = validator_fn(config.deliverable_file)

        recovered_full_graph = False
        graph_recovery_stopped = False
        if not valid and full_graph:
            # Budget exhaustion keeps its original cause: it propagates to
            # the run so the outcome is budget_exceeded, never truncation.
            recovered_full_graph, full_graph_recovery_error = (
                self._recover_truncated_full_graph(
                    config, tools, stream_callback,
                    completion=graph_completion,
                )
            )
            if recovered_full_graph:
                valid, msg = validator_fn(config.deliverable_file)
                if not valid:
                    recovered_full_graph = False
                    full_graph_recovery_error = (
                        f"failed: recovered file failed revalidation: {msg}"
                    )
            if not recovered_full_graph:
                if full_graph_recovery_error.startswith("stopped:"):
                    # A stop aborts recovery with its own cause: never a
                    # truncation diagnosis and never a success.
                    graph_recovery_stopped = True
                    msg = full_graph_recovery_error
                elif full_graph_recovery_error.startswith("failed:"):
                    # Recovery was attempted after an observed truncation and
                    # failed: report the explicit truncation cause instead of
                    # only the missing-file diagnosis.
                    msg = (
                        "truncated_output: full Phase 1 graph response truncated "
                        "(finish_reason=length) with no validated save; bounded "
                        "save-only recovery failed: "
                        f"{full_graph_recovery_error[len('failed:'):].strip()}"
                    )

        if recovered_full_graph:
            status = "completed:recovered"
        elif graph_recovery_stopped:
            status = "stopped"
        else:
            status = (
                "completed:synthesized"
                if recovered_compact_recon
                else ("completed" if valid else f"failed:{msg}")
            )
        if full_intrusion and self._stop_event is not None and self._stop_event.is_set():
            status = "stopped"
        # Compact reconciliation keeps its existing completion contract.
        # Full Phase 5 defers its event below until reconciliation has recorded
        # the final outcome, with the original usage attached.
        defer_compact_intrusion_done = (
            config.phase == 5
            and local_intrusion_memo
            and not valid
        )

        if hasattr(self, "tracker") and self.tracker:
            self.tracker.record_validation_result(success=valid)

        usage = self.tracker.end_phase()
        if usage and not (defer_compact_intrusion_done or full_intrusion):
            print(
                f"\n  Phase {config.phase} done: {usage.turns} turns, "
                f"${usage.cost_usd():.4f}"
            )
        elif defer_compact_intrusion_done or full_intrusion:
            print(
                f"\n  Phase {config.phase} model pass ended; "
                "reconciliation pending"
            )

        if valid:
            log.info("Phase %d deliverable validated: %s", config.phase, msg)
            print(f"  Deliverable validated: {config.deliverable_file}")
        else:
            log.error("Phase %d deliverable FAILED: %s", config.phase, msg)
            if not defer_compact_intrusion_done:
                print(f"  Deliverable FAILED validation: {msg}")
                print(f"  LLM final output: {result_text[:500]}")

        if config.name == "recon":
            projection = self._build_recon_evidence_projection()
            self._reconcile_phase2_attack_surface(projection)

        if not defer_compact_intrusion_done:
            terminal_event = {
                "type": "phase_done",
                "phase": config.phase,
                "name": config.name,
                "status": status,
                "deliverable": config.deliverable_file,
                "cost_usd": round(usage.cost_usd(), 4) if usage else 0,
                "turns": usage.turns if usage else 0,
            }
            if full_intrusion:
                # Reconciliation owns the terminal outcome. Keep real usage
                # here so its single event cannot erase the phase's cost.
                self._phase5_pending_event = terminal_event
            elif stream_callback:
                stream_callback(terminal_event)

        return status

    def _uses_local_moe(self) -> bool:
        """Return whether the active model uses the bounded local MoE runtime."""
        return (
            getattr(self.provider, "provider", "") == "local-moe"
            or str(getattr(self.provider, "model", "")).startswith(
                ("lance-moe", "expert-")
            )
        )

    def _uses_compact_local_moe(self) -> bool:
        """Return whether compact small-model orchestration is active locally.

        Local execution alone must not downgrade an explicit/full-capability
        profile. Future local models resolved as ``full`` still need the normal
        tool-driven agents; only GPU queue serialization remains provider-bound.
        """
        return self.execution_profile.routed_tools and self._uses_local_moe()

    def _resolve_tools(self, config: runtime.AgentConfig) -> list[dict]:
        """Resolve tool references to actual tool definitions.

        Supports two resolution modes:
          1. Group name (e.g. "graph", "recon") → expand entire group
          2. Individual tool name (e.g. "nmap_scan") → find in any group

        Tool functions are wrapped to log calls and results to tool_calls.jsonl.
        """
        tools = []
        seen_names: set[str] = set()

        for ref in config.tools:
            if ref == "recon" and self.dry_run:
                continue

            # Try group resolution first
            if ref in runtime.TOOL_GROUPS:
                for tool in runtime.TOOL_GROUPS[ref]:
                    if self.sealed and tool["name"] in runtime.SEALED_FORBIDDEN_TOOLS:
                        continue
                    if tool["name"] not in seen_names:
                        tools.append(self._wrap_tool(tool, phase=config.phase, agent=config.name))
                        seen_names.add(tool["name"])
                continue

            # Fall back to individual tool name lookup
            for group in runtime.TOOL_GROUPS.values():
                for tool in group:
                    if self.sealed and tool["name"] in runtime.SEALED_FORBIDDEN_TOOLS:
                        continue
                    if tool["name"] == ref and ref not in seen_names:
                        tools.append(self._wrap_tool(tool, phase=config.phase, agent=config.name))
                        seen_names.add(ref)
                        break

        tools = self._apply_scenario_tool_policy(tools, config.phase)
        tools, unavailable = runtime.filter_unavailable_tools(tools)
        if unavailable:
            log.info(
                "Phase %s: hiding unavailable tools: %s",
                config.phase,
                ", ".join(sorted(unavailable)),
            )
        return tools

    def _apply_scenario_tool_policy(
        self, tools: list[dict], phase: int | str | None
    ) -> list[dict]:
        """Apply a manual scenario allowlist after normal tool resolution."""
        try:
            phase_number = int(phase) if phase is not None else None
        except (TypeError, ValueError):
            phase_number = None
        phase_name = {
            2: "recon",
            3: "recon",
            4: "verification",
            5: "intrusion",
        }.get(phase_number)
        if phase_name is None:
            return tools
        allowed = runtime.tool_policy_for_phase(self.scenario_tool_policy, phase_name)
        if allowed is None:
            return tools
        allowed.update(runtime.INTERNAL_TOOLS)
        return [tool for tool in tools if tool.get("name") in allowed]

    def _wrap_tool(self, tool: dict, *, phase=None, agent=None) -> dict:
        from src.agent.core.executor import wrap_tool
        return wrap_tool(self, tool, phase=phase, agent=agent)

    def _filter_skills(self, config: runtime.AgentConfig) -> str:
        """Filter skills by tag intersection with config.skill_filter.

        Returns a formatted string listing matching skills for prompt injection.
        """
        if not config.skill_filter:
            return ""

        filter_tags = set(config.skill_filter.get("tags", []))
        if not filter_tags:
            return ""

        matched = [
            skill for skill in runtime.get_skills_metadata()
            if set(skill.get("tags", [])) & filter_tags
        ]

        if not matched:
            return "No matching skills for this phase."

        lines = []
        for s in matched:
            tags_str = ", ".join(s["tags"])
            lines.append(f"- **{s['name']}**: {s['description']} (tags: {tags_str})")

        return "\n".join(lines)

    def _list_previous_deliverables(self) -> str:
        """List available deliverables for prompt variable.

        Visibility matches the deliverable-tool boundary in
        :mod:`src.agent.artifacts`: the same predicate hides laboratory
        setup/verification internals here so the prompt listing cannot drift
        from what ``read_deliverable`` refuses.
        """
        if not self.run_dir.exists():
            return "None (first phase)"
        files = sorted(
            f.name for f in self.run_dir.glob("*")
            if (
                f.is_file()
                and not f.name.startswith(".")
                and not is_private_agent_artifact(f.name)
                and not is_private_agent_artifact_path(f)
            )
        )
        return ", ".join(files) if files else "None (first phase)"
