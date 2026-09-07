"""Verification phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
from pathlib import Path
import json
import threading
import logging
from src.agent.phases.verification.contract import (
    COMPACT_PHASE4_DEFAULT_MAX_WORKERS,
    _phase4_apply_verification_contract,
    _phase4_local_verification_tools,
    _phase4_requirement_matches,
    _phase4_verification_plan,
)
from src.agent.phases.verification.prompts import EXPLOIT_INSTRUCTIONS
from src.agent.phases.verification.evidence import (
    _exploit_relpath,
    _make_test_entry,
    _tool_records_for_vuln,
)
from src.agent.core import runtime


log = logging.getLogger(__name__)


class VerificationPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _run_exploit_agents(
        self,
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Run per-vuln exploit micro-agents in parallel, then aggregate results."""
        import threading
        import time as _time
        from concurrent.futures import CancelledError, ThreadPoolExecutor, wait

        # 1. Read the Phase 3 vulnerability queue
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        if not vuln_path.exists():
            log.warning("Phase 4: 03_vuln_analysis.json not found — skipping exploit agents")
            return
        vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
        all_vulns = vuln_data.get("vulnerabilities", [])

        # 2. Build exploit tasks for canonical findings. Direct compact
        # observations remain in the detection queue, but are deliberately
        # not sent to exploit agents because they do not need an intrusive
        # verification to be useful and scoring them as exploitation would
        # reintroduce the compact hallucination problem.
        exploit_tasks: list[dict] = []
        skipped_candidates: list[dict] = []
        for vuln in all_vulns:
            if self._uses_compact_local_moe() and vuln.get("compact_detection_only"):
                skipped_candidates.append({
                    "vuln_id": vuln.get("id", ""),
                    "reason": (
                        "direct compact observation retained for detection; "
                        "exploitation deferred"
                    ),
                })
                continue
            category = runtime.exploit_category(str(vuln.get("type") or "")) or "data_access"
            requirement = _phase4_verification_plan(vuln, compact=self._uses_compact_local_moe())
            exploit_tasks.append({
                "vuln": vuln,
                "category": category,
                "verification": requirement,
            })

        self._phase4_schedule = {
            "candidate_count": len(all_vulns),
            "scheduled_count": len(exploit_tasks),
            "scheduled_vuln_ids": [
                task["vuln"].get("id", "") for task in exploit_tasks
            ],
            "skipped_count": len(skipped_candidates),
            "skipped_candidates": skipped_candidates,
        }
        self._phase4_execution_status = None
        if not exploit_tasks:
            self._phase4_execution_status = "skipped:no_safely_exploitable_candidates"
            log.info("Phase 4: no safely exploitable candidates — skipping agents")
            self._aggregate_exploit_results()
            return

        self._exploit_tool_context = threading.local()
        tools = self._resolve_tools(config)

        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: EXPLOIT SUB-AGENTS (PARALLEL)")
        print(f"  Launching {len(exploit_tasks)} exploit micro-agents")
        print(f"{'=' * 60}\n")

        # Per-device locks to avoid concurrent connections to same host
        # All profiles must observe the run-level stop signal.
        # Full workers used to ignore it while their provider loop was probing.
        stop_event = getattr(self, "_stop_event", None)
        from collections import defaultdict
        device_locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
        _locks_guard = threading.Lock()
        worker_errors: list[str] = []
        worker_error_lock = threading.Lock()

        def _stop_requested() -> bool:
            return bool(stop_event is not None and stop_event.is_set())

        def _record_worker_error(message: str) -> None:
            with worker_error_lock:
                worker_errors.append(message)

        def _get_device_lock(device_ip: str) -> threading.Lock:
            with _locks_guard:
                return device_locks[device_ip]

        def _run_single_exploit(task: dict):
            vuln = task["vuln"]
            category = task["category"]
            vuln_id = vuln.get("id", "VULN-???")
            vuln_type = vuln.get("type", "unknown")
            device_id = vuln.get("device_id", "unknown")
            device_ip = vuln.get("device_ip", "unknown")
            service = vuln.get("service", "unknown")
            port = vuln.get("port", 0)
            severity = vuln.get("severity", "MEDIUM")
            details = vuln.get("details", "")
            evidence = vuln.get("evidence", "")
            requirement = task.get("verification") or _phase4_verification_plan(vuln, compact=self._uses_compact_local_moe())
            required_probe_tool = str(requirement.get("tool") or "")

            deliverable_file = str(_exploit_relpath(device_id, vuln_type, vuln_id))
            deliverable_path = self.run_dir / deliverable_file

            # Build exploit instructions with variable substitution
            cat_instructions = EXPLOIT_INSTRUCTIONS.get(category, {})
            service_key = "http" if service == "https" else service
            instructions = cat_instructions.get(service_key, cat_instructions.get("default", ""))
            instructions = instructions.replace("{ip}", device_ip)
            instructions = instructions.replace("{port}", str(port))
            # Build URL for data_access category
            if service in ("http", "https") and port:
                url = f"http://{device_ip}:{port}" if port != 80 else f"http://{device_ip}"
            else:
                url = f"http://{device_ip}"
            instructions = instructions.replace("{url}", url)

            variables = {**self.context}
            variables["device_id"] = device_id
            variables["device_ip"] = device_ip
            variables["vuln_id"] = vuln_id
            variables["vuln_type"] = vuln_type
            variables["vuln_severity"] = severity
            variables["service"] = service
            variables["port"] = str(port) if port else "0"
            variables["vuln_details"] = details
            variables["vuln_evidence"] = evidence[:500]
            variables["exploit_instructions"] = instructions
            variables["required_verification"] = json.dumps(requirement, ensure_ascii=False)
            variables["expected_deliverable"] = deliverable_file
            variables["phase4_profile_guidance"] = (
                "Full profile: use the required service-specific probe as guidance, while retaining autonomous tool selection and additional relevant verification steps; ground every verdict in the tool ledger."
                if not self.execution_profile.routed_tools else
                "Compact profile: use the exposed service-specific tools, start with the "
                "required probe, and stop once direct proof is sufficient."
            )
            runtime.set_expected_deliverable(deliverable_file)
            variables["available_skills"] = ""

            phase_name = f"exploit_{device_id}_{vuln_type}"
            exploit_config = runtime.AgentConfig(
                name=phase_name,
                phase=4,
                prompt_template="exploit_device_vuln",
                deliverable_file=deliverable_file,
                tools=[],
                validator="json_exploit_result",
            )
            exploit_tools = self._apply_deliverable_transaction(
                tools, exploit_config, stream_callback
            )

            print(f"  [+] Starting: {phase_name} ({device_ip})")
            if stream_callback:
                stream_callback({
                    "type": "exploit_start",
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vuln_type": vuln_type,
                    "vuln_id": vuln_id,
                    "phase": 4,
                })

            # Acquire per-device lock to avoid concurrent connections
            lock = _get_device_lock(device_ip)
            with lock:
                self._exploit_tool_context.vulnerability = {
                    "vuln_id": vuln_id,
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vuln_type": vuln_type,
                    "service": service,
                    "port": port,
                    "protocol": vuln.get("protocol", ""),
                    "endpoint": vuln.get("endpoint", ""),
                    "product": vuln.get("product", ""),
                }
                self.tracker.start_phase(phase_name)
                result_text = ""
                provider_error = ""
                try:
                    compact_local_moe = self._uses_compact_local_moe()
                    if self.execution_profile.routed_tools:
                        # Compact accepts a narrow, service-specific surface
                        # and a mandatory fresh probe before it can save.
                        verification_tools = _phase4_local_verification_tools(
                            exploit_tools, category=category, service=service,
                            include_deliverable=not compact_local_moe,
                        )
                        exposed = {tool.get("name") for tool in verification_tools}
                        if required_probe_tool not in exposed:
                            verification_tools = verification_tools + [
                                tool for tool in exploit_tools
                                if tool.get("name") == required_probe_tool
                            ]
                        if required_probe_tool:
                            allowed_probe_names = {required_probe_tool, "save_deliverable"}
                            verification_tools = [
                                tool for tool in verification_tools
                                if tool.get("name") in allowed_probe_names
                            ]
                        verification_tools = _phase4_apply_verification_contract(
                            verification_tools, requirement
                        )
                    else:
                        # Full keeps the complete Phase 4 surface. The
                        # service-specific requirement is guidance, not a
                        # harness-enforced route or stopping condition.
                        verification_tools = exploit_tools
                    variables["phase4_allowed_tools"] = ", ".join(sorted({
                        str(tool.get("name")) for tool in verification_tools if tool.get("name")
                    }))
                    system_prompt = runtime.load_prompt("exploit_device_vuln", variables)
                    if compact_local_moe:
                        try:
                            result_text = self.provider.chat_with_tools(
                                system_prompt=runtime.load_prompt(
                                    "exploit_device_vuln_memo",
                                    {
                                        **variables,
                                        "device": device_id,
                                        "vulnerability": vuln_type,
                                        "exploit_instructions": instructions,
                                    },
                                ),
                                user_message=(
                                    f"Verify {vuln_type} on {device_id} ({device_ip}). "
                                    f"Service: {service} port {port}. Use tools if needed, then summarize."
                                ),
                                tools=verification_tools,
                                max_turns=self.execution_profile.phase4_local_max_turns,
                                max_tokens=self.execution_profile.phase4_local_max_tokens,
                                cost_tracker=self.tracker,
                                stream_callback=self._model_stream_callback(
                                    stream_callback, phase=4, agent=phase_name
                                ),
                                required_tool=required_probe_tool or None,
                                strict_required_tool=bool(required_probe_tool),
                                force_tool_on_stall=True,
                                recover_required_tool_on_stall=True,
                                repeat_guard=True,
                                terminate_on_unavailable_tools={"save_deliverable"},
                                stop_event=stop_event,
                            )
                        except Exception as exc:
                            provider_error = f"{type(exc).__name__}: {exc}"
                            result_text = ""
                            log.warning(
                                "Compact Phase 4 provider call failed for %s; running fallback probe: %s",
                                vuln_id, provider_error,
                            )
                        if _stop_requested():
                            return
                        records = _tool_records_for_vuln(self.run_dir, vuln_id)
                        required_observed = any(
                            _phase4_requirement_matches(
                                requirement, str(record.get("tool") or ""),
                                record.get("args") or {},
                            )
                            for record in records
                        )
                        if not required_observed:
                            fallback_tool = next(
                                (
                                    tool for tool in verification_tools
                                    if tool.get("name") == required_probe_tool
                                    and callable(tool.get("function"))
                                ),
                                None,
                            )
                            fallback_args = dict(requirement.get("args_hint") or {})
                            if fallback_tool is not None and fallback_args:
                                try:
                                    fallback_tool["function"](**fallback_args)
                                except Exception as exc:
                                    log.warning(
                                        "Compact Phase 4 fallback probe failed for %s: %s",
                                        vuln_id,
                                        exc,
                                    )
                                records = _tool_records_for_vuln(self.run_dir, vuln_id)
                                required_observed = any(
                                    _phase4_requirement_matches(
                                        requirement, str(record.get("tool") or ""),
                                        record.get("args") or {},
                                    )
                                    for record in records
                                )
                        result = runtime._synthesize_exploit_result(vuln, records, result_text, compact=True)
                        if not required_observed:
                            result.update({
                                "status": "ERROR",
                                "evidence": (
                                    f"Required Phase 4 probe was not observed: "
                                    f"{required_probe_tool} against {device_ip}"
                                ),
                                "evidence_level": 0,
                                "tool_used": required_probe_tool,
                            })
                        if provider_error:
                            result["evidence"] = (
                                f"Provider Phase 4 error ({provider_error}); "
                                f"{result.get('evidence', '')}"
                            ).strip()
                        deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                        deliverable_path.write_text(
                            json.dumps(result, indent=2, ensure_ascii=False),
                            encoding="utf-8",
                        )
                    else:
                        result_text = self.provider.chat_with_tools(
                            system_prompt=system_prompt,
                            user_message=(
                                f"Exploit {vuln_type} on {device_id} ({device_ip}). "
                                f"Service: {service} port {port}. "
                                f"Call save_deliverable('{deliverable_file}', json_content) when done."
                            ),
                            tools=verification_tools,
                            max_turns=self.execution_profile.phase4_max_turns,
                            max_tokens=self.execution_profile.phase4_max_tokens,
                            cost_tracker=self.tracker,
                            stream_callback=self._model_stream_callback(
                                stream_callback, phase=4, agent=phase_name
                            ),
                            max_data_tool_calls=self.execution_profile.phase4_max_data_tool_calls,
                            force_completion_on_phase4_conclusive=True,
                            required_tool="save_deliverable",
                            terminate_after_tool="save_deliverable",
                            stop_event=stop_event,
                        )
                        if not deliverable_path.exists():
                            # The provider may be forced into completion-only
                            # mode by the data budget before it emits a valid
                            # save. Preserve the observed tool evidence rather
                            # than leaving Phase 4 without a per-vuln artifact.
                            records = _tool_records_for_vuln(self.run_dir, vuln_id)
                            result = runtime._synthesize_exploit_result(
                                vuln, records, result_text, compact=False
                            )
                            deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                            deliverable_path.write_text(
                                json.dumps(result, indent=2, ensure_ascii=False),
                                encoding="utf-8",
                            )
                except Exception as exc:
                    message = f"{phase_name}: {exc}"
                    _record_worker_error(message)
                    log.exception("Exploit agent failed: %s", phase_name)
                    deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                    error_result = {
                        "vuln_id": vuln_id,
                        "device_id": device_id,
                        "device_ip": device_ip,
                        "vuln_type": vuln_type,
                        "severity": severity,
                        "service": service,
                        "port": port,
                        "status": "ERROR",
                        "evidence": f"Exploit agent error: {exc}",
                        "evidence_level": 0,
                        "tool_used": "",
                        "tools_used": [],
                        "evidence_refs": [],
                        "data_extracted": [],
                        "description": "Exploit agent raised before producing a verdict",
                    }
                    deliverable_path.write_text(
                        json.dumps(error_result, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                finally:
                    self._exploit_tool_context.vulnerability = None


            usage = self.tracker.end_phase()
            if usage:
                print(f"  [+] Done: {phase_name} in {usage.turns} turns")
            if stream_callback:
                stream_callback({
                    "type": "exploit_done", "device_id": device_id,
                    "vuln_type": vuln_type, "vuln_id": vuln_id, "phase": 4,
                    "turns": usage.turns if usage else 0,
                })

            # Safety net: if still no file, write ERROR result
            if not deliverable_path.exists():
                log.warning("Exploit %s: no output — saving ERROR result", phase_name)
                deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                error_result = {
                    "vuln_id": vuln_id,
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "service": service,
                    "port": port,
                    "status": "ERROR",
                    "evidence": "Exploit agent produced no output",
                    "evidence_level": 0,
                    "tool_used": "",
                    "data_extracted": [],
                    "description": "Exploit agent failed to produce output",
                }
                deliverable_path.write_text(json.dumps(error_result, indent=2), encoding="utf-8")

            # Trigger local disbalance computation after exploit
            if deliverable_path.exists():
                try:
                    result_data = json.loads(deliverable_path.read_text(encoding="utf-8"))
                    exploit_status = result_data.get("status", "")
                    if exploit_status.upper() in ("CONFIRMED", "EXPLOITED", "COMPROMISED"):
                        runtime.trigger_disbalance_on_exploit(
                            device_id=device_id,
                            exploit_status=exploit_status,
                            vuln_type=vuln_type,
                            device_ip=device_ip,
                        )
                except (json.JSONDecodeError, OSError):
                    pass  # Non-fatal: disbalance is informational

        # Launch exploit agents with small stagger to avoid API rate limits
        def _run_with_stagger(args):
            idx, task = args
            if idx > 0:
                delay = min(idx * 0.5, 5)  # 0.5s stagger, max 5s
                if stop_event is not None:
                    if stop_event.wait(delay):
                        return
                else:
                    _time.sleep(delay)
            from src.agent.tools.runtime import tool_stop_context
            with tool_stop_context(stop_event):
                _run_single_exploit(task)

        max_workers = (
            COMPACT_PHASE4_DEFAULT_MAX_WORKERS
            if self._uses_compact_local_moe()
            else 8
        )
        pool = ThreadPoolExecutor(max_workers=max(1, min(len(exploit_tasks), max_workers)))
        futures = [
            pool.submit(_run_with_stagger, item)
            for item in enumerate(exploit_tasks)
        ]
        pending = set(futures)
        try:
            while pending:
                if _stop_requested():
                    for future in pending:
                        future.cancel()
                done, pending = wait(pending, timeout=0.25)
                for future in done:
                    try:
                        future.result()
                    except CancelledError:
                        pass
                    except Exception as exc:
                        _record_worker_error(f"phase4 worker: {exc}")
        finally:
            pool.shutdown(wait=True, cancel_futures=True)

        if _stop_requested():
            self._phase4_execution_status = "stopped"

        if worker_errors and self._phase4_execution_status is None:
            self._phase4_execution_status = "executed_with_worker_errors"
            log.warning(
                "Phase 4 completed with %d worker error(s): %s",
                len(worker_errors),
                "; ".join(worker_errors[:3]),
            )

        print(f"\n{'=' * 60}")
        print(f"  All {len(exploit_tasks)} exploit agents finished.")
        print(f"{'=' * 60}\n")

        # 3. Deterministic aggregation
        self._aggregate_exploit_results()

    def _collect_new_hosts(self) -> list[dict]:
        """Collect hosts discovered during Phase 4 exploitation that were not in the original scan.

        Reads new_hosts_discovered from all Phase 4 exploit output files.
        Returns deduplicated list of {"ip": str, "open_ports": [...], "discovered_via": str}.
        For scenario runs, only returns hosts within the scenario's expected subnets.
        """
        import ipaddress as _ip

        new_hosts: list[dict] = []
        seen_ips: set[str] = set()
        for f in self.run_dir.glob("04_exploits/**/*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for h in data.get("new_hosts_discovered", []):
                    ip = h.get("ip", "").strip()
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        new_hosts.append(h)
            except Exception:
                pass

        if new_hosts and self.scenario_id is not None:
            from src.agent.tools.graph_tools import _scenario_topology
            subnets = (_scenario_topology or {}).get("subnets", [])
            if subnets:
                try:
                    nets = [_ip.ip_network(s, strict=False) for s in subnets]
                    filtered = []
                    for h in new_hosts:
                        try:
                            addr = _ip.ip_address(h["ip"])
                            if any(addr in n for n in nets):
                                filtered.append(h)
                            else:
                                log.info("Excluding out-of-scope discovered host %s (not in %s)", h["ip"], subnets)
                        except ValueError:
                            filtered.append(h)
                    new_hosts = filtered
                except Exception:
                    pass

        if new_hosts:
            log.info("Phase 4 discovered %d new host(s): %s", len(new_hosts), [h["ip"] for h in new_hosts])
        return new_hosts

    def _aggregate_exploit_results(self) -> None:
        """Merge Phase 3 findings + Phase 4 exploit results into 04_exploitation.json.

        Phase 3 `confirmed` findings are trusted over Phase 4 FAILED/ERROR —
        when the exploit agent can't reproduce a directly-observed vuln
        (e.g. ssh_audit [fail] lines), we keep the Phase 3 evidence.
        """
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        if not vuln_path.exists():
            return

        all_vulns = json.loads(vuln_path.read_text(encoding="utf-8")).get("vulnerabilities", [])
        tests: list[dict] = []
        refs_by_vuln: dict[str, list[str]] = {}
        tools_by_vuln: dict[str, list[str]] = {}
        records_by_vuln: dict[str, list[dict]] = {}
        tool_log = self.run_dir / "tool_calls.jsonl"
        if tool_log.is_file():
            try:
                tool_lines = tool_log.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError) as exc:
                log.warning("Unable to read Phase 4 tool provenance: %s", exc)
                tool_lines = []
            for line in tool_lines:
                try:
                    record = json.loads(line)
                except (json.JSONDecodeError, TypeError):
                    continue
                vuln_id = str(record.get("vuln_id", "")).strip()
                evidence_ref = str(record.get("evidence_ref", "")).strip()
                tool_name = str(record.get("tool", "")).strip()
                if vuln_id:
                    records_by_vuln.setdefault(vuln_id, []).append(record)
                if vuln_id and evidence_ref:
                    refs_by_vuln.setdefault(vuln_id, []).append(evidence_ref)
                if vuln_id and tool_name and tool_name != "save_deliverable":
                    tools_by_vuln.setdefault(vuln_id, []).append(tool_name)

        phase4_schedule = getattr(self, "_phase4_schedule", {})
        if "scheduled_vuln_ids" in phase4_schedule:
            scheduled_ids = set(phase4_schedule.get("scheduled_vuln_ids") or [])
        else:
            scheduled_ids = {str(vuln.get("id", "")) for vuln in all_vulns}
        skipped_by_vuln = {
            str(item.get("vuln_id", "")): str(item.get("reason", "not_scheduled"))
            for item in phase4_schedule.get("skipped_candidates", [])
            if str(item.get("vuln_id", ""))
        }

        for vuln in all_vulns:
            exploit_file = self.run_dir / _exploit_relpath(
                vuln.get("device_id", "unknown"),
                vuln.get("type", ""),
                vuln.get("id", "VULN-???"),
            )
            vuln_id = str(vuln.get("id", ""))
            if vuln_id and vuln_id not in scheduled_ids:
                tests.append(_make_test_entry(
                    vuln,
                    status="SKIPPED",
                    evidence=f"Skipped Phase 4 exploit agent: {skipped_by_vuln.get(vuln_id, 'not_scheduled')}",
                    evidence_level=0,
                ))
                continue
            tests.append(self._resolve_exploit_verdict(
                vuln, exploit_file,
                evidence_refs=refs_by_vuln.get(vuln_id, []),
                tools_used=tools_by_vuln.get(vuln_id, []),
                tool_records=records_by_vuln.get(vuln_id, []),
            ))

        executed_tests = [
            test for test in tests if test.get("vuln_id", "") in scheduled_ids
        ]
        confirmed = sum(1 for test in executed_tests if test["status"] == "CONFIRMED")
        failed = sum(1 for test in executed_tests if test["status"] == "FAILED")
        errors = len(executed_tests) - confirmed - failed

        out_path = self.run_dir / "04_exploitation.json"
        out_path.write_text(
            json.dumps(
                {
                    "summary": {
                        "total_tested": getattr(
                            self, "_phase4_schedule", {}
                        ).get("scheduled_count", len(tests)),
                        "candidate_count": getattr(
                            self, "_phase4_schedule", {}
                        ).get("candidate_count", len(tests)),
                        "skipped_count": getattr(
                            self, "_phase4_schedule", {}
                        ).get("skipped_count", 0),
                        "execution_state": (
                            getattr(self, "_phase4_execution_status", None)
                            or "executed"
                        ),
                        "confirmed": confirmed,
                        "not_exploitable": failed,
                        "errors": errors,
                    },
                    "scheduling": getattr(self, "_phase4_schedule", {}),
                    "tests": tests,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        log.info("Aggregated %d exploit results → %s", len(tests), out_path)
        print(f"  Aggregated: {len(tests)} results → 04_exploitation.json "
              f"({confirmed} confirmed, {failed} failed, {errors} errors)")

    def _resolve_exploit_verdict(
        self,
        vuln: dict,
        exploit_file: Path,
        *,
        evidence_refs: list[str] | None = None,
        tools_used: list[str] | None = None,
        tool_records: list[dict] | None = None,
    ) -> dict:
        """Return a single aggregated test entry for one Phase 3 finding."""
        if not exploit_file.exists():
            # Fallback: the exploit agent may have saved with a different VULN-ID.
            # Scan for any {vuln_type}_VULN-*.json in the device directory.
            device_dir = exploit_file.parent
            vuln_type_prefix = exploit_file.name.split("_VULN-")[0]
            candidates = sorted(device_dir.glob(f"{vuln_type_prefix}_VULN-*.json"))
            if candidates:
                # Pick the candidate with the highest evidence_level to avoid
                # collisions when the same vuln_type has multiple findings on a device.
                best = candidates[0]
                best_level = -1
                for c in candidates:
                    try:
                        c_level = json.loads(c.read_text(encoding="utf-8")).get("evidence_level", 0)
                    except Exception:
                        c_level = 0
                    if c_level > best_level:
                        best_level = c_level
                        best = c
                exploit_file = best
            else:
                if tool_records:
                    semantic_result = runtime._synthesize_exploit_result(vuln, tool_records, compact=self._uses_compact_local_moe())
                    semantic_status = str(semantic_result.get("status", "ERROR")).upper()
                    final_status = "CONFIRMED" if semantic_status == "EXPLOITED" else semantic_status
                    if final_status not in {"CONFIRMED", "FAILED", "ERROR"}:
                        final_status = "ERROR"
                    return _make_test_entry(vuln, status=final_status, result=semantic_result)
                return _make_test_entry(
                    vuln,
                    status="ERROR",
                    evidence="No Phase 4 exploit result was produced",
                    evidence_level=0,
                )

        try:
            result = json.loads(exploit_file.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("Failed to parse exploit result %s: %s", exploit_file, e)
            return _make_test_entry(
                vuln,
                status="ERROR",
                evidence=f"Failed to parse: {e}",
                evidence_level=0,
            )

        result = dict(result)
        result["evidence_refs"] = list(dict.fromkeys([
            *(str(value).strip() for value in (result.get("evidence_refs") or [])),
            *(str(value).strip() for value in (evidence_refs or [])),
        ]))
        result["tools_used"] = list(dict.fromkeys([
            *(str(value).strip() for value in (result.get("tools_used") or [])),
            *(str(value).strip() for value in (tools_used or [])),
        ]))
        status = str(result.get("status", "ERROR")).upper()
        semantic_result = runtime._synthesize_exploit_result(vuln, tool_records or [], compact=self._uses_compact_local_moe())
        semantic_status = str(semantic_result.get("status", "ERROR")).upper()
        if status == "EXPLOITED" and semantic_status == "EXPLOITED":
            return _make_test_entry(
                vuln,
                status="CONFIRMED",
                result={**result, **semantic_result},
            )
        if status == "EXPLOITED" and (
            not runtime._has_positive_exploit_evidence(result)
            or semantic_status != "EXPLOITED"
        ):
            log.warning("Downgrading unsupported EXPLOITED verdict for %s", vuln.get("id"))
            return _make_test_entry(
                vuln,
                status=semantic_status if semantic_status in {"FAILED", "ERROR"} else "ERROR",
                result={**result, **semantic_result},
                evidence=(
                    "Unsupported EXPLOITED verdict: no matching positive tool evidence. "
                    + str(semantic_result.get("evidence") or result.get("evidence", ""))
                ),
                evidence_level=int(semantic_result.get("evidence_level", 0) or 0),
            )
        if status in {"CONFIRMED", "COMPROMISED"}:
            if semantic_status == "EXPLOITED":
                return _make_test_entry(
                    vuln,
                    status="CONFIRMED",
                    result={**result, **semantic_result},
                )
            status = semantic_status if semantic_status in {"FAILED", "ERROR"} else "ERROR"
            result = {**result, **semantic_result}
        final_status = "CONFIRMED" if status == "EXPLOITED" else status
        if final_status not in {"CONFIRMED", "FAILED", "ERROR"}:
            final_status = "ERROR"
        return _make_test_entry(vuln, status=final_status, result=result)


def run(context, config, stream_callback=None):
    return context._run_agent(config, stream_callback)
