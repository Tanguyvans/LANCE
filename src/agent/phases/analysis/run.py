"""Analysis phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
import json
import os
import re
import logging
import time
from copy import deepcopy
from src.agent.phases.analysis import block_recovery
from src.agent.core import runtime
from src.agent.core.provider_transport import deadline_remaining
from src.agent.cost_tracker import BudgetExceeded
from src.agent.core.executor import EvidenceWriteError, check_execution_limits


from src.agent.phases.analysis.context import (
    AnalysisContext, AnalysisServices, AnalysisExecutionResult,
    DeviceAnalysisResult, ScanResult, save_execution_status,
)
from src.agent.phases.analysis.scan import scan_phase
from src.agent.phases.analysis.devices import analyze_devices, analysis_worker_count, project_scan
from src.agent.phases.analysis.aggregation import aggregate, capture_context as capture_aggregation_context
from src.agent.phases.contracts import PhaseConsumption, PhaseResult, PhaseStatus

log = logging.getLogger(__name__)


class AnalysisPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _phase3_worker_count(self, device_count: int) -> int:
        """Limit local MoE and UMONS device analysis to one in-flight worker."""
        from types import SimpleNamespace
        return analysis_worker_count(SimpleNamespace(
            provider=self.provider, local_moe=self._uses_local_moe(),
            experiment_scope=self.experiment_scope,
        ), device_count)

    def _phase3_scan_results_for_prompt(self, scan_data: dict, device_id: str) -> dict:
        return project_scan(self.execution_profile, scan_data, device_id)

    @staticmethod
    def _parse_phase3_tool_result(raw_result) -> dict:
        if isinstance(raw_result, dict):
            return raw_result
        if isinstance(raw_result, str):
            try:
                parsed = json.loads(raw_result)
                return parsed if isinstance(parsed, dict) else {"stdout": raw_result}
            except (TypeError, ValueError, json.JSONDecodeError):
                return {"stdout": raw_result}
        return {"stdout": str(raw_result)}

    @staticmethod
    def _phase3_port_from_entry(entry: dict, text: str) -> int | None:
        kwargs = entry.get("kwargs")
        kwargs = kwargs if isinstance(kwargs, dict) else {}
        ports = kwargs.get("ports")
        if isinstance(ports, int):
            return ports
        if isinstance(ports, str):
            match = re.search(r"\d+", ports)
            if match:
                return int(match.group(0))
        match = re.search(r"\b(\d{1,5})/(?:tcp|udp)\b", text, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _extract_phase3_software_versions(text: str) -> list[dict[str, str]]:
        """Extract explicit product/version observations suitable for CVE lookup."""
        patterns = [
            ("OpenSSH", r"\bOpenSSH[_\s-]+(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("Dropbear", r"\bDropbear(?:[_\s-]+sshd)?[_\s-]+(?P<version>\d{4}\.\d+(?:[A-Za-z0-9._~:+-]*))"),
            ("Mosquitto", r"\bmosquitto(?:\s+version)?\s+(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("nginx", r"\bnginx(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("Apache httpd", r"\b(?:Apache(?:\s+httpd)?|httpd)(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("lighttpd", r"\blighttpd(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("Redis", r"\bredis_version[:=](?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("Redis", r"\bRedis(?:\s+server)?(?:\s+v=|/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("MySQL", r"\bMySQL(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("MariaDB", r"\bMariaDB(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("OpenWrt", r"\bOpenWrt(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("uHTTPd", r"\buHTTPd(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
            ("vsftpd", r"\bvsftpd(?:/|\s+)(?P<version>\d+(?:\.\d+)+(?:[A-Za-z0-9._~:+-]*))"),
        ]
        found: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for product, pattern in patterns:
            for match in re.finditer(pattern, text, flags=re.IGNORECASE):
                version = match.group("version").strip().strip(";,)")
                key = (product.casefold(), version.casefold())
                if key in seen:
                    continue
                seen.add(key)
                line_start = text.rfind("\n", 0, match.start()) + 1
                line_end = text.find("\n", match.end())
                if line_end == -1:
                    line_end = len(text)
                excerpt = text[line_start:line_end].strip()
                found.append({
                    "product": product,
                    "version": version,
                    "query": f"{product} {version}",
                    "evidence": excerpt[:300],
                })
        return found

    def _phase3_version_queries_for_device(
        self,
        device: dict,
        scan_data: dict,
    ) -> list[dict]:
        """Build deduplicated cve_search queries from explicit scanner versions."""
        device_id = device.get("id", "")
        services = device.get("services", [])
        port_services = {
            service.get("port"): service
            for service in services
            if isinstance(service, dict) and service.get("port") is not None
        }
        queries: list[dict] = []
        seen: set[str] = set()
        scan_results = scan_data.get("scan_results", {})
        if not isinstance(scan_results, dict):
            return queries
        for service_key, entries in scan_results.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                parsed = self._parse_phase3_tool_result(entry.get("result", ""))
                stdout = str(parsed.get("stdout") or "")
                stderr = str(parsed.get("stderr") or "")
                text = "\n".join(part for part in (stdout, stderr) if part)
                if not text:
                    continue
                port = self._phase3_port_from_entry(entry, text)
                svc_meta = port_services.get(port, {}) if port is not None else {}
                service_name = (
                    svc_meta.get("name")
                    or svc_meta.get("service")
                    or str(service_key).split(":", 1)[0]
                )
                protocol = svc_meta.get("protocol", "tcp")
                for observation in self._extract_phase3_software_versions(text):
                    query = observation["query"]
                    dedupe_key = f"{device_id}:{service_name}:{port}:{query}".casefold()
                    if dedupe_key in seen:
                        continue
                    seen.add(dedupe_key)
                    queries.append({
                        **observation,
                        "device_id": device_id,
                        "device_ip": device.get("ip", ""),
                        "service": service_name,
                        "port": port,
                        "protocol": protocol,
                        "source_tool": entry.get("tool", ""),
                    })
        return queries

    @staticmethod
    def _phase3_compatible_cve_items(raw_result) -> list[dict]:
        try:
            results = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        except (TypeError, ValueError, json.JSONDecodeError):
            return []
        if not isinstance(results, list):
            return []
        compatible: list[dict] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            compatibility = item.get("compatibility")
            compatibility = compatibility if isinstance(compatibility, dict) else {}
            status = str(
                compatibility.get("status")
                or item.get("compatibility_status")
                or metadata.get("compatibility_status")
                or ""
            ).casefold()
            cve_id = str(
                item.get("cve_id") or item.get("id")
                or metadata.get("cve_id") or metadata.get("id") or ""
            ).upper()
            if status == "compatible" and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                compatible.append(item)
        return compatible

    def _append_phase3_cve_finding(
        self,
        scanner_results: dict[str, dict],
        query_info: dict,
        cve_item: dict,
        evidence_ref: str,
    ) -> bool:
        metadata = cve_item.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        compatibility = cve_item.get("compatibility")
        compatibility = compatibility if isinstance(compatibility, dict) else {}
        cve_id = str(
            cve_item.get("cve_id") or cve_item.get("id")
            or metadata.get("cve_id") or metadata.get("id")
        ).upper()
        severity = str(
            cve_item.get("severity")
            or metadata.get("severity")
            or "MEDIUM"
        ).upper()
        description = str(
            cve_item.get("description")
            or metadata.get("description")
            or cve_item.get("document")
            or metadata.get("document")
            or ""
        )
        reason = str(
            compatibility.get("reason")
            or cve_item.get("compatibility_reason")
            or metadata.get("compatibility_reason")
            or "version range classified as compatible"
        )
        device_id = str(query_info.get("device_id", ""))
        findings = scanner_results.setdefault(device_id, {}).setdefault("findings", [])
        finding = {
            "id": f"{device_id}-cve-{cve_id}",
            "device_id": device_id,
            "device_ip": query_info.get("device_ip", ""),
            "type": "known_cve",
            "severity": severity,
            "service": query_info.get("service", ""),
            "port": query_info.get("port"),
            "protocol": query_info.get("protocol", "tcp"),
            "endpoint": "",
            "product": query_info.get("product", ""),
            "version": query_info.get("version", ""),
            "details": f"{cve_id}: {description[:240]}".strip(),
            "evidence": (
                f"Detected {query_info.get('query')} in {query_info.get('source_tool')}; "
                f"cve_search returned compatible: {reason}"
            ),
            "evidence_ref": evidence_ref,
            "evidence_refs": [evidence_ref],
            "cve_ids": [cve_id],
            "cve_validation": {
                "query": query_info.get("query", ""),
                "observed_product": query_info.get("product", ""),
                "observed_version": query_info.get("version", ""),
                "compatibility_status": "compatible",
                "compatibility_reason": reason,
            },
            "exploitation_status": "suspected",
        }
        if not any(
            existing.get("type") == "known_cve"
            and cve_id in [str(value).upper() for value in existing.get("cve_ids", [])]
            and existing.get("service") == finding["service"]
            and existing.get("port") == finding["port"]
            for existing in findings
            if isinstance(existing, dict)
        ):
            findings.append(finding)
            return True
        return False

    def _persist_phase3_device_findings(
        self,
        device: dict,
        scanner_results: dict[str, dict],
    ) -> None:
        device_id = device.get("id", "")
        data = scanner_results.get(device_id, {})
        findings = data.get("findings", [])
        fallback_path = self.run_dir / f"03_device_{device_id}.json"
        fallback = {
            "device_id": device_id,
            "device_ip": device.get("ip", ""),
            "vulnerabilities": findings if isinstance(findings, list) else [],
            "summary": {
                "total": len(findings) if isinstance(findings, list) else 0,
                "by_severity": {
                    severity: sum(
                        1 for finding in findings
                        if isinstance(finding, dict)
                        and str(finding.get("severity", "")).upper() == severity
                    )
                    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                } if isinstance(findings, list) else {},
            },
        }
        fallback_path.write_text(json.dumps(fallback, indent=2, ensure_ascii=False), encoding="utf-8")

    def _phase3_promoted_deliverable(
        self, device_id: str, filename: str, receipt: object,
    ) -> tuple[bool, str]:
        """Accept only this worker's valid transaction whose promotion is intact."""
        final_path = self.run_dir / filename
        if not isinstance(receipt, dict) or receipt.get("validated") is not True:
            return False, f"missing_validated_deliverable: no valid save receipt for {device_id}"
        if receipt.get("status") != "saved" or receipt.get("ok") is False or receipt.get("error"):
            return False, f"missing_validated_deliverable: save promotion failed for {device_id}"
        attempt_ref = receipt.get("attempt_ref")
        if not isinstance(attempt_ref, str) or not attempt_ref:
            return False, f"missing_validated_deliverable: save receipt has no attempt for {device_id}"
        attempt_path = self.run_dir / attempt_ref
        try:
            root = os.path.realpath(self.run_dir)
            if os.path.commonpath((root, os.path.realpath(attempt_path))) != root:
                return False, f"missing_validated_deliverable: invalid attempt path for {device_id}"
            if not attempt_path.is_file() or not final_path.is_file():
                return False, f"missing_validated_deliverable: promoted file is missing for {device_id}"
            if attempt_path.read_bytes() != final_path.read_bytes():
                return False, f"missing_validated_deliverable: promoted file changed for {device_id}"
        except OSError:
            return False, f"missing_validated_deliverable: promoted file is unreadable for {device_id}"
        return True, ""

    def _phase3_recovery_guard(
        self, device_id: str, total: int, done: int, *, deadline: float | None,
    ) -> None:
        """Enforce the shared stop/deadline/budget before another recovery call."""
        if getattr(self, "experiment_scope", None):
            check_execution_limits(self)
        stop_event = getattr(self, "_stop_event", None)
        if stop_event is not None and stop_event.is_set():
            raise RuntimeError(
                f"truncated_output: block recovery stopped for {device_id} "
                f"({done}/{total} blocks valid)"
            )
        try:
            deadline_remaining(deadline)
        except TimeoutError:
            raise RuntimeError(
                f"truncated_output: block recovery deadline exceeded for {device_id} "
                f"({done}/{total} blocks valid)"
            ) from None
        try:
            self.tracker.check_budget()
        except BudgetExceeded:
            raise RuntimeError(
                f"truncated_output: block recovery budget exceeded for {device_id} "
                f"({done}/{total} blocks valid)"
            ) from None

    def _read_validated_phase3_block(
        self,
        device: dict,
        spec: dict,
        block_receipts: list[dict],
        *,
        device_ports: set[int],
        device_services: set[str],
        finish_reason: str | None,
    ) -> dict:
        """Accept one saved block only after promotion and attribution checks."""
        device_id = str(device.get("id") or "")
        sidecar = str(spec["sidecar"])
        if finish_reason not in ("tool_calls", "stop"):
            raise RuntimeError(
                f"missing_validated_deliverable: incomplete block response "
                f"for {device_id} (finish_reason={finish_reason})"
            )
        if not block_receipts:
            raise RuntimeError(
                f"missing_validated_deliverable: no block save for {device_id} "
                f"(finish_reason={finish_reason})"
            )
        promoted, promotion_error = self._phase3_promoted_deliverable(
            device_id, sidecar, block_receipts[-1]
        )
        if not promoted:
            raise RuntimeError(promotion_error)
        try:
            data = json.loads((self.run_dir / sidecar).read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"missing_validated_deliverable: unreadable block sidecar {sidecar}: {exc}"
            ) from exc
        valid, validation_error = block_recovery.validate_block_payload(
            data,
            device_id=device_id,
            device_ip=str(device.get("ip") or ""),
            spec=spec,
            device_ports=device_ports,
            device_services=device_services,
        )
        if not valid:
            raise RuntimeError(
                f"missing_validated_deliverable: rejected block sidecar {sidecar}: "
                f"{validation_error}"
            )
        return data

    def _run_phase3_block(
        self,
        device: dict,
        scan_data: dict,
        spec: dict,
        caps: dict,
        observations: list[dict],
        *,
        deadline: float | None,
        stream_callback: Callable[[dict], None] | None,
    ) -> dict:
        """Finalize one block with save-only calls; retry only this block."""
        device_id = str(device.get("id") or "")
        device_ip = str(device.get("ip") or "")
        total = max(1, int(caps.get("total_blocks", 1)))
        services = [s for s in device.get("services", []) if isinstance(s, dict)]
        device_ports = {
            s["port"] for s in services
            if isinstance(s.get("port"), int) and not isinstance(s.get("port"), bool)
        }
        device_services = {
            str(s.get("name") or s.get("service") or "") for s in services
        } - {""}
        scoped = block_recovery.scope_scan_for_block(scan_data, spec)
        automated_summary = "\n".join(
            f"- {finding.get('id', '?')} | {finding.get('type', '?')} | "
            f"{finding.get('severity', '?')} | {finding.get('service', '')} | "
            f"{finding.get('port', '')}"
            for finding in scoped["findings"]
            if isinstance(finding, dict)
        ) or "No automated findings in scope."
        scan_json = json.dumps(scoped["scan_results"], ensure_ascii=False)
        if len(scan_json) > 12000:
            scan_json = scan_json[:12000] + '\n[truncated: see 03_scans/{}.json]'.format(device_id)
        block_services = ", ".join(
            f"{entry['name']}:{entry['port']}" if entry["name"] and entry["port"] is not None
            else entry["name"] or f"port {entry['port']}"
            for entry in spec["services"]
        ) or "general scope (no declared services)"
        variables = {
            "device_id": device_id,
            "device_ip": device_ip,
            "block_index": spec["index"] + 1,
            "block_count": total,
            "block_id_prefix": block_recovery.block_id_prefix(device_id, spec["index"]),
            "block_services": block_services,
            "allowed_services": ", ".join(spec["service_names"]) or "any declared service",
            "allowed_ports": ", ".join(str(port) for port in spec["ports"]) or "any declared port",
            "expected_block_file": spec["sidecar"],
            "scan_results": scan_json,
            "automated_findings_summary": automated_summary,
            "prior_observations": block_recovery.render_observations(observations, spec),
        }
        system_prompt = runtime.load_prompt("analyze_device_block", variables)
        save_base = next(
            (tool for tool in runtime.DELIVERABLE_TOOLS if tool.get("name") == "save_deliverable"),
            None,
        )
        if save_base is None:
            raise RuntimeError(
                f"truncated_output: save tool unavailable for {device_id} block recovery"
            )
        block_agent = f"analyze_{device_id}_block{spec['index']}"
        block_config = runtime.AgentConfig(
            name=block_agent,
            phase=3,
            prompt_template="analyze_device_block",
            deliverable_file=str(spec["sidecar"]),
            tools=[],
            validator="json_device_vulns",
        )
        block_tools = self._apply_deliverable_transaction(
            [self._wrap_tool(dict(save_base), phase=3, agent=block_agent)],
            block_config,
            stream_callback,
        )
        block_receipts: list[dict] = []
        wrapped: list[dict] = []
        for tool in block_tools:
            if tool.get("name") != "save_deliverable":
                wrapped.append(tool)
                continue
            original_save = tool["function"]

            def capture_block_save(*args, _original=original_save, **kwargs):
                raw_receipt = _original(*args, **kwargs)
                try:
                    receipt = json.loads(raw_receipt) if isinstance(raw_receipt, str) else raw_receipt
                except (TypeError, ValueError, json.JSONDecodeError):
                    receipt = None
                if isinstance(receipt, dict):
                    block_receipts.append(receipt)
                return raw_receipt

            wrapped.append({**tool, "function": capture_block_save})
        block_tools = wrapped

        last_error = "no attempt made"
        for attempt in range(1, caps["max_attempts"] + 1):
            self._phase3_recovery_guard(
                device_id, total, spec["index"], deadline=deadline
            )
            block_completion: dict = {}
            block_receipts.clear()
            self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Finalize block {spec['index'] + 1} for {device_id} ({device_ip}) "
                    f"covering {block_services}. Then call save_deliverable("
                    f"'{spec['sidecar']}', json_content)."
                    + (f" Previous block attempt was rejected: {last_error[:800]}. Repair this block only."
                       if attempt > 1 else "")
                ),
                tools=block_tools,
                max_turns=caps["max_turns"],
                max_tokens=caps["max_tokens"],
                cost_tracker=self.tracker,
                stream_callback=self._model_stream_callback(
                    stream_callback, phase=3, agent=block_agent
                ),
                required_tool="save_deliverable",
                terminate_after_tool="save_deliverable",
                stop_event=self._stop_event,
                deadline=deadline,
                completion_metadata=block_completion,
            )
            self._phase3_recovery_guard(
                device_id, total, spec["index"], deadline=deadline
            )
            try:
                return self._read_validated_phase3_block(
                    device, spec, block_receipts,
                    device_ports=device_ports,
                    device_services=device_services,
                    finish_reason=block_completion.get("finish_reason"),
                )
            except (BudgetExceeded, EvidenceWriteError):
                raise
            except RuntimeError as exc:
                last_error = str(exc)
                if block_completion.get("finish_reason") == "length":
                    last_error += " [finish_reason=length]"
                log.warning(
                    "Phase 3 block %s for %s attempt %d/%d failed: %s",
                    spec["sidecar"], device_id, attempt, caps["max_attempts"], last_error,
                )
        raise RuntimeError(
            f"truncated_output: block {spec['index'] + 1}/{total} incomplete for "
            f"{device_id} after {caps['max_attempts']} attempts ({last_error}); "
            f"valid blocks preserved under {block_recovery.BLOCK_DIR}/"
        )

    def _recover_truncated_phase3_device(
        self,
        *,
        device: dict,
        scan_data: dict,
        deliverable_file: str,
        device_tools: list[dict],
        save_receipts: list[dict],
        observations: list[dict],
        deadline: float | None,
        stream_callback: Callable[[dict], None] | None,
    ) -> None:
        """Rebuild one truncated device from validated per-service blocks.

        Raises RuntimeError with a ``truncated_output:`` cause when any
        required block is missing or invalid. Scanner fallback and valid
        sidecars are preserved by the caller; nothing here declares success
        without every block validated and the assembled deliverable promoted.
        """
        device_id = str(device.get("id") or "")
        caps = getattr(self, "experiment_analysis_limits", {}).get("block_recovery") or block_recovery.block_config()
        specs = block_recovery.derive_blocks(
            device,
            max_blocks=caps["max_blocks"],
            services_per_block=caps["services_per_block"],
        )
        caps = {**caps, "total_blocks": len(specs)}
        self._phase3_recovery_guard(device_id, len(specs), 0, deadline=deadline)
        self.tracker.start_phase(f"analyze_{device_id}_blocks")
        try:
            payloads: list[dict] = []
            block_failures: list[str] = []
            for position, spec in enumerate(specs):
                try:
                    payloads.append(
                        self._run_phase3_block(
                            device, scan_data, spec, caps, observations,
                            deadline=deadline, stream_callback=stream_callback,
                        )
                    )
                except (BudgetExceeded, EvidenceWriteError):
                    raise
                except RuntimeError as exc:
                    # Keep attempting sibling blocks so valid sidecars are
                    # preserved; the device still fails as incomplete below.
                    block_failures.append(str(exc))
                    log.warning(
                        "Phase 3 block recovery skipping %s for %s: %s",
                        spec["sidecar"], device_id, exc,
                    )
                    try:
                        self._phase3_recovery_guard(
                            device_id, len(specs), position + 1, deadline=deadline
                        )
                    except (BudgetExceeded, EvidenceWriteError):
                        raise
                    except RuntimeError:
                        block_failures.append(
                            "truncated_output: block recovery aborted by stop/deadline/budget"
                        )
                        break
            if block_failures:
                raise RuntimeError(
                    f"truncated_output: incomplete block recovery for {device_id} "
                    f"({len(payloads)}/{len(specs)} blocks valid): {block_failures[0]}"
                )
            automated = scan_data.get("findings", []) if isinstance(scan_data, dict) else []
            self._phase3_recovery_guard(
                device_id, len(specs), len(payloads), deadline=deadline
            )
            try:
                assembled = block_recovery.assemble_device_deliverable(
                    device, automated if isinstance(automated, list) else [], payloads
                )
            except ValueError as exc:
                raise RuntimeError(
                    f"truncated_output: cannot assemble {device_id} from blocks: {exc}"
                ) from exc
            device_save = next(
                (tool["function"] for tool in device_tools
                 if tool.get("name") == "save_deliverable"),
                None,
            )
            if device_save is None:
                raise RuntimeError(
                    f"truncated_output: save tool unavailable for {device_id} assembly"
                )
            raw_receipt = device_save(
                filename=deliverable_file,
                content=json.dumps(assembled, ensure_ascii=False),
            )
            try:
                receipt = json.loads(raw_receipt) if isinstance(raw_receipt, str) else raw_receipt
            except (TypeError, ValueError, json.JSONDecodeError):
                receipt = None
            if isinstance(receipt, dict):
                save_receipts.append(receipt)
            promoted, promotion_error = self._phase3_promoted_deliverable(
                device_id, deliverable_file, receipt if isinstance(receipt, dict) else None
            )
            if not promoted:
                raise RuntimeError(promotion_error)
            log.info(
                "Phase 3 block recovery completed for %s (%d blocks)",
                device_id, len(specs),
            )
        finally:
            self.tracker.end_phase()

    def _run_phase3(self, config, stream_callback=None) -> AnalysisExecutionResult:
        """Compatibility entry for custom LLM aggregators and device tests."""
        self._phase3_execution_status = None
        execution = run_execution(build_context(self, config, stream_callback))
        self._phase3_execution_status = (
            execution.run_verdict.value if execution.run_verdict is PhaseStatus.WORKER_ERRORS else None
        )
        return execution


def build_context(run, config, stream_callback=None) -> AnalysisContext:
    """Capture the effective phase provider/profile after any model override.

    Transaction and recovery services are incremental adapters.
    They still use the run engine; the ordinary phase stages accept only this
    explicit context. Its lifetime is one phase invocation.
    """
    return AnalysisContext(
        run_dir=run.run_dir, config=config, provider=run.provider,
        tracker=run.tracker, profile=run.execution_profile,
        services=AnalysisServices(
            wrap_tool=run._wrap_tool,
            apply_tool_policy=run._apply_scenario_tool_policy,
            save_transaction=run._apply_deliverable_transaction,
            model_callback=run._model_stream_callback,
            discover_surface=run._discover_attack_surface,
            persist_findings=run._persist_phase3_device_findings,
            promoted_deliverable=run._phase3_promoted_deliverable,
            recover_device=run._recover_truncated_phase3_device,
            validate_cves=run._run_phase3_local_cve_validation,
            check_limits=lambda: check_execution_limits(run),
            validate=run._validator(config.validator),
        ),
        variables=dict(run.context), compact_local=run._uses_compact_local_moe(),
        local_moe=run._uses_local_moe(), dry_run=run.dry_run, sealed=run.sealed,
        target_network=run.target_network, stop_event=run._stop_event,
        decision_policy=run.decision_policy, benchmark_split=run.benchmark_split,
        experiment_scope=run.experiment_scope,
        tool_policy=deepcopy(run.scenario_tool_policy),
        analysis_limits=dict(getattr(run, "experiment_analysis_limits", None) or {}),
        max_duration_s=run.max_duration_s, run_started=getattr(run, "_run_started", None),
        emit=stream_callback, tokens_before=run.tracker.total_tokens(),
        cost_before=run.tracker.total_cost(),
        turns_before=run.tracker.summary()["total_turns"],
    )


def run_execution(context: AnalysisContext) -> AnalysisExecutionResult:
    save_execution_status(context)
    if context.config.has_device_agents:
        scan = scan_phase(context)
        analysis = analyze_devices(context, scan)
    else:
        # Custom deterministic configurations can aggregate existing files.
        scan = ScanResult([], {}, skipped=context.dry_run)
        analysis = DeviceAnalysisResult()
    execution = AnalysisExecutionResult(scan, analysis)
    save_execution_status(context, execution, finished=True)
    if not scan.skipped and context.decision_policy != "rules":
        print(f"\n{'=' * 60}\n  All {len(scan.devices)} analysis agents finished.\n{'=' * 60}\n")
    return execution


def _consumption(context: AnalysisContext) -> PhaseConsumption:
    usage = context.tracker.summary()
    return PhaseConsumption(
        input_tokens=usage["total_input_tokens"] - context.tokens_before[0],
        output_tokens=usage["total_output_tokens"] - context.tokens_before[1],
        cost_usd=usage["total_cost_usd"] - context.cost_before,
        duration_s=time.monotonic() - context.started_monotonic,
        turns=usage["total_turns"] - context.turns_before,
    )


def aggregate_phase(
    context: AnalysisContext, execution: AnalysisExecutionResult,
) -> PhaseResult:
    errors = list(execution.scan.scanner_errors)
    if execution.scan.surface_error:
        errors.append(execution.scan.surface_error)
    errors.extend(f"{device.device_id}: {device.error}"
                  for device in execution.analysis.devices if device.error is not None)
    artifacts = ["03_phase3_status.json"]
    if execution.scan.skipped:
        return PhaseResult(
            PhaseStatus.SKIPPED,
            artifacts=tuple(name for name in artifacts if (context.run_dir / name).is_file()),
            errors=tuple(errors), consumption=_consumption(context),
        )
    aggregate(capture_aggregation_context(
        context.run_dir, compact_local=context.compact_local,
        decision_policy=context.decision_policy, benchmark_split=context.benchmark_split,
    ))
    if context.decision_policy == "rules":
        context.tracker.start_phase("rules_validate_3")
    try:
        valid, message = context.services.validate(context.config.deliverable_file)
        if context.decision_policy == "rules":
            context.tracker.record_validation_result(valid)
    finally:
        if context.decision_policy == "rules":
            context.tracker.end_phase()
    status = execution.run_verdict if valid else PhaseStatus.FAILED
    if not valid:
        errors.append(message)
        log.error("Phase 3 deterministic aggregation FAILED: %s", message)
    else:
        log.info("Phase 3 deterministic aggregation validated: %s", message)
        artifacts.append(context.config.deliverable_file)
    for device in execution.scan.devices:
        device_id = str(device.get("id") or "")
        artifacts.extend((f"03_device_{device_id}.json", f"03_scans/{device_id}.json",
                          f"03_device_{device_id}_analysis.md"))
    return PhaseResult(
        status, artifacts=tuple(name for name in artifacts if (context.run_dir / name).is_file()),
        errors=tuple(errors), reason=message if not valid else None,
        consumption=_consumption(context),
    )


def execute(context: AnalysisContext) -> PhaseResult:
    config = context.config
    if context.emit:
        context.emit({
            "type": "phase_start", "phase": 3, "name": config.name,
            "description": config.description, "deliverable": config.deliverable_file,
        })
    if context.decision_policy == "rules":
        context.tracker.start_phase("rules_analysis")
    try:
        execution = run_execution(context)
    finally:
        if context.decision_policy == "rules":
            context.tracker.end_phase()
    result = aggregate_phase(context, execution)
    if context.emit:
        # Include every worker, including rejected or interrupted analyses.
        context.emit({
            "type": "phase_done", "phase": 3, "name": config.name,
            "status": result.legacy_status, "deliverable": config.deliverable_file,
            "cost_usd": result.consumption.cost_usd,
            "turns": result.consumption.turns,
        })
    return result


def run(run, config, stream_callback=None) -> PhaseResult | str:
    # Custom legacy configurations can still ask for a model master aggregator.
    if not config.deterministic_aggregation and run.decision_policy != "rules":
        return run._run_agent(config, stream_callback)
    run._phase3_execution_status = None
    result = execute(build_context(run, config, stream_callback))
    # execute() already applied run_verdict in aggregate_phase: only work
    # left undone degrades here.
    run._phase3_execution_status = (
        result.status.value if result.status is PhaseStatus.WORKER_ERRORS else None
    )
    return result
