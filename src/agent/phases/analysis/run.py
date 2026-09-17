"""Analysis phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit
import json
import os
import re
import logging
from src.agent.phases.analysis.prompts import ROLE_SPECIFIC_RULES
from src.agent.phases.analysis import block_recovery
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.core import runtime
from src.agent.core.provider_transport import deadline_remaining
from src.agent.cost_tracker import BudgetExceeded


log = logging.getLogger(__name__)


class AnalysisPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _phase3_worker_count(self, device_count: int) -> int:
        """Limit local MoE and UMONS device analysis to one in-flight worker."""
        # Use the active provider, including a Phase 3 model override. The
        # UMONS run with four workers exhausted every 240s device deadline;
        # serialize this provider without changing its prompts or deadline.
        if self._uses_local_moe() or getattr(self.provider, "provider", "") == "ollama-umons":
            return 1
        configured = os.environ.get("LANCE_PHASE3_WORKERS", "").strip()
        if configured.isdigit() and int(configured) > 0:
            return min(int(configured), max(1, device_count))
        # Keep extended scenarios moving without one request per device.
        if device_count >= 12:
            return min(2, device_count)
        return max(1, min(device_count, 6))

    def _phase3_scan_results_for_prompt(
        self, scan_data: dict, device_id: str
    ) -> dict:
        """Keep complete Phase 3 evidence for full, project it for compact."""
        if not self.execution_profile.routed_tools:
            return scan_data
        compact = self._compact_phase3_scan_results(scan_data)
        compact["_evidence_projection"]["full_scan_artifact"] = (
            f"03_scans/{device_id}.json"
        )
        return compact

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
        caps = block_recovery.block_config()
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

    def _run_phase3(
        self,
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Phase 3 split: 3a (deterministic scanner) → 3b (LLM analysis) → 3c (merge)."""
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

        # This is run-local state consumed by deterministic aggregation; never
        # infer it from an older status artifact.
        self._phase3_execution_status = None
        phase3_status_path = self.run_dir / "03_phase3_status.json"
        phase3_status = {
            "status": "running",
            "started_at": datetime.now().astimezone().isoformat(),
            "devices_total": 0,
            "devices_analyzed": 0,
            "devices_failed": [],
            "scanner_errors": [],
            "worker_count": 0,
        }

        def _save_phase3_status() -> None:
            phase3_status_path.write_text(
                json.dumps(phase3_status, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        _save_phase3_status()

        # --- Phase 3a: Deterministic scanning ---
        try:
            surface = json.loads(runtime.get_attack_surface())
        except Exception as exc:
            log.exception("Could not load Phase 3 attack surface: %s", exc)
            surface = []
            phase3_status["surface_error"] = str(exc)
        if isinstance(surface, dict):
            # Discovery mode returns {"note": ..., "target_network": ...} — no pre-defined nodes
            surface = surface.get("nodes", [])

        # Discovery/blind mode: no pre-defined topology — actively discover the
        # attack surface by nmap-scanning the target network, then register the
        # hosts so get_attack_surface(), get_device_info() and
        # get_network_neighbors() resolve them for Phase 3b agents.
        if self.target_network and not surface:
            surface = self._discover_attack_surface(self.target_network, stream_callback)
            from src.agent.tools.graph_tools import update_discovery_hosts
            update_discovery_hosts(surface)
            # Initialize weighted graph for disbalance computation
            runtime.init_weighted_graph()

        phase3_status["devices_total"] = len(surface)
        if self.dry_run:
            log.info("Dry run: skipping Phase 3a scanner")
            print("  [dry-run] Skipping scanner")
            phase3_status["status"] = "skipped"
            phase3_status["finished_at"] = datetime.now().astimezone().isoformat()
            _save_phase3_status()
            return

        scanner_kwargs = {"compact": self._uses_compact_local_moe()}
        recon_policy = runtime.tool_policy_for_phase(
            self.scenario_tool_policy, "recon"
        )
        if recon_policy is not None:
            scanner_kwargs["allowed_tool_names"] = recon_policy
        try:
            scanner_results = runtime.run_scanner(
                self.run_dir, surface, stream_callback,
                stop_event=self._stop_event,
                **scanner_kwargs,
            )
        except Exception as exc:
            log.exception("Phase 3 scanner failed globally; preserving per-device fallbacks")
            scanner_results = {}
            phase3_status["scanner_errors"] = [str(exc)]
            for device in surface:
                scanner_results[device.get("id", "")] = {
                    "scan_results": {}, "findings": [], "error": str(exc),
                }
                self._persist_phase3_device_findings(device, scanner_results)
        phase3_status["scanner_errors"].extend(
            str(data.get("error")) for data in scanner_results.values()
            if isinstance(data, dict) and data.get("error")
        )

        # S16 enrollment returns the authorized disposable client identity.
        # Use that in-memory bundle for one bounded mTLS request against the
        # API; this avoids guessing filesystem paths or inventing a revoked
        # certificate. The response itself is enough to prove the contract.
        pki_enrollment = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "pki_enrollment_server"),
            None,
        )
        pki_mtls = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "pki_mtls_server"),
            None,
        )
        if pki_enrollment and pki_mtls:
            try:
                enrollment_data = scanner_results.get(pki_enrollment.get("id", ""), {})
                enrollment_entries = [
                    entry
                    for values in (enrollment_data.get("scan_results", {}) or {}).values()
                    if isinstance(values, list)
                    for entry in values
                    if entry.get("tool") == "http_request"
                ]
                bundle = None
                for entry in enrollment_entries:
                    result = json.loads(str(entry.get("result") or ""))
                    if result.get("status_code") != 201:
                        continue
                    payload = json.loads(str(result.get("body") or ""))
                    if payload.get("certificate_pem") and payload.get("private_key_pem"):
                        bundle = payload
                        break
                if bundle:
                    from src.agent.tools.recon_tools import mtls_request
                    mtls_url = f"https://{pki_mtls.get('ip', '')}:8443/device/status"
                    mtls_result = mtls_request(
                        url=mtls_url,
                        certificate_pem=str(bundle["certificate_pem"]),
                        private_key_pem=str(bundle["private_key_pem"]),
                        method="GET",
                    )
                    mtls_id = pki_mtls.get("id", "")
                    mtls_data = scanner_results.setdefault(
                        mtls_id, {"scan_results": {}, "findings": []}
                    )
                    mtls_data.setdefault("scan_results", {}).setdefault("pki_mtls", []).append({
                        "tool": "mtls_request",
                        "kwargs": {"url": mtls_url, "method": "GET"},
                        "result": mtls_result,
                        "evidence_phase": 3,
                        "authoritative": True,
                    })
                    from src.agent.scanner import extract_findings
                    mtls_data["findings"] = extract_findings(
                        mtls_data["scan_results"], pki_mtls,
                        compact=self._uses_compact_local_moe(),
                    )
                    (self.run_dir / "03_scans" / f"{mtls_id}.json").write_text(
                        json.dumps(mtls_data["scan_results"], indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    self._persist_phase3_device_findings(pki_mtls, scanner_results)
            except (OSError, TypeError, ValueError, json.JSONDecodeError, KeyError) as exc:
                log.warning("S16 bounded mTLS probe unavailable: %s", exc)

        # Cross-device simulator checks for S17/S18. These are deliberately
        # derived from evidence already returned by the bounded probes: no
        # guessed signing secret, filesystem path, or out-of-scope target is
        # introduced by the harness.
        def _append_bounded_http_probe(
            device: dict, kwargs: dict, result: str, *, service_key: str = "bounded"
        ) -> None:
            device_id = str(device.get("id") or "")
            if not device_id:
                return
            data = scanner_results.setdefault(
                device_id, {"scan_results": {}, "findings": []}
            )
            data.setdefault("scan_results", {}).setdefault(service_key, []).append({
                "tool": "http_request",
                "kwargs": kwargs,
                "result": result,
                "evidence_phase": 3,
                "authoritative": True,
            })
            from src.agent.scanner import extract_findings
            data["findings"] = extract_findings(
                data["scan_results"], device,
                compact=self._uses_compact_local_moe(),
            )
            (self.run_dir / "03_scans" / f"{device_id}.json").write_text(
                json.dumps(data["scan_results"], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            self._persist_phase3_device_findings(device, scanner_results)

        ota_repository = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "ota_repository"),
            None,
        )
        ota_devices = [
            device for device in surface
            if str(device.get("role") or "").casefold() == "ota_device"
        ]
        if ota_repository and ota_devices:
            try:
                from src.agent.tools.recon_tools import http_request
                repo_data = scanner_results.get(ota_repository.get("id", ""), {})
                repo_entries = [
                    entry
                    for values in (repo_data.get("scan_results", {}) or {}).values()
                    if isinstance(values, list)
                    for entry in values
                    if entry.get("tool") == "http_request"
                ]
                fixtures: dict[str, dict] = {}
                for entry in repo_entries:
                    kwargs = entry.get("kwargs") or {}
                    if urlsplit(str(kwargs.get("url") or "")).path != "/firmware":
                        continue
                    try:
                        result = json.loads(str(entry.get("result") or ""))
                        body = json.loads(str(result.get("body") or ""))
                    except (TypeError, ValueError, json.JSONDecodeError):
                        continue
                    for item in body.get("artifacts", []):
                        if isinstance(item, dict) and item.get("version") and item.get("payload") and item.get("signature"):
                            fixtures[str(item["version"])] = item
                old = fixtures.get("1")
                current = fixtures.get("2")
                if old and current:
                    device_a = next(
                        (device for device in ota_devices
                         if str(device.get("id") or "").endswith("device-a")),
                        ota_devices[0],
                    )
                    device_b = next(
                        (device for device in ota_devices
                         if str(device.get("id") or "").endswith("device-b")),
                        None,
                    )
                    base_url = lambda device: f"http://{device.get('ip', '')}:8080/install"
                    # The vulnerable device signs payload bytes only. Test the
                    # metadata mutation, then rollback, and restore v2.
                    metadata_body = json.dumps({
                        "version": "999", "payload": old["payload"], "signature": old["signature"],
                    })
                    metadata_kwargs = {
                        "url": base_url(device_a), "method": "POST",
                        "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "metadata"},
                        "body": metadata_body, "follow_redirects": False,
                    }
                    _append_bounded_http_probe(device_a, metadata_kwargs, http_request(**metadata_kwargs), service_key="ota_cross_device")
                    rollback_body = json.dumps({
                        "version": old["version"], "payload": old["payload"], "signature": old["signature"],
                    })
                    rollback_kwargs = {
                        "url": base_url(device_a), "method": "POST",
                        "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "rollback"},
                        "body": rollback_body, "follow_redirects": False,
                    }
                    _append_bounded_http_probe(device_a, rollback_kwargs, http_request(**rollback_kwargs), service_key="ota_cross_device")
                    restore_kwargs = {
                        "url": base_url(device_a), "method": "POST",
                        "headers": {"Content-Type": "application/json", "X-Benchmark-OTA-Test": "restore"},
                        "body": json.dumps(current), "follow_redirects": False,
                    }
                    _append_bounded_http_probe(device_a, restore_kwargs, http_request(**restore_kwargs), service_key="ota_cross_device")
                    if device_b:
                        cross_kwargs = {
                            "url": base_url(device_b), "method": "POST",
                            "headers": {
                                "Content-Type": "application/json",
                                "X-Benchmark-Cross-Device": "s17-device-a",
                            },
                            "body": json.dumps(current), "follow_redirects": False,
                        }
                        _append_bounded_http_probe(device_b, cross_kwargs, http_request(**cross_kwargs), service_key="ota_cross_device")
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                log.warning("S17 bounded OTA probes unavailable: %s", exc)

        cloud_metadata = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "cloud_metadata_server"),
            None,
        )
        cloud_control = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "cloud_control_plane"),
            None,
        )
        for cloud_web in surface:
            if (
                str(cloud_web.get("role") or "").casefold() != "cloud_web_server"
                or not cloud_metadata or not cloud_control
            ):
                continue
            try:
                from src.agent.tools.recon_tools import http_request
                web_data = scanner_results.get(cloud_web.get("id", ""), {})
                fetch_entry = next(
                    (
                        entry for values in (web_data.get("scan_results", {}) or {}).values()
                        if isinstance(values, list)
                        for entry in values
                        if entry.get("tool") == "http_request"
                        and urlsplit(str((entry.get("kwargs") or {}).get("url") or "")).path == "/fetch"
                    ),
                    None,
                )
                if fetch_entry:
                    fetch_result = json.loads(str(fetch_entry.get("result") or ""))
                    fetch_body = json.loads(str(fetch_result.get("body") or ""))
                    metadata_body = str(fetch_body.get("body") or "")
                    metadata_payload = json.loads(metadata_body)
                    token = str(metadata_payload.get("access_token") or "")
                    if fetch_result.get("status_code") == 200 and token and metadata_payload.get("scope") == "object-admin":
                        metadata_kwargs = {
                            "url": f"http://{cloud_metadata.get('ip', '')}:8080/credentials",
                            "method": "GET",
                            "headers": {"X-Benchmark-Vantage": "ssrf"},
                            "follow_redirects": False,
                        }
                        _append_bounded_http_probe(
                            cloud_metadata, metadata_kwargs,
                            json.dumps({"status_code": 200, "body": metadata_body}),
                            service_key="cloud_ssrf",
                        )
                        control_kwargs = {
                            "url": f"http://{cloud_control.get('ip', '')}:8080/bucket/city-secrets",
                            "method": "GET",
                            "headers": {"Authorization": f"Bearer {token}"},
                            "follow_redirects": False,
                        }
                        _append_bounded_http_probe(
                            cloud_control, control_kwargs,
                            http_request(**control_kwargs),
                            service_key="cloud_ssrf",
                        )
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                log.warning("S18 bounded SSRF/IAM probes unavailable: %s", exc)

        if self._uses_compact_local_moe():
            self._run_phase3_local_cve_validation(
                scanner_results, surface, stream_callback
            )

        # --- Phase 3b: LLM analysis micro-agents (per device) ---
        print(f"\n{'=' * 60}")
        print(f"PHASE 3b: LLM ANALYSIS ({len(surface)} devices)")
        print(f"{'=' * 60}\n")

        # Limited, protocol-aware tool access. Device analyzers may perform
        # bounded application checks but cannot open a general shell.
        skill_tools = [t for t in runtime.SKILL_TOOLS if t["name"] == "cve_search"]
        analysis_tool_names = {
            "curl_headers", "http_get", "http_request", "redis_cmd", "tcp_send",
            "udp_send", "mtls_request", "tls_inspect",
        }
        available_recon_tools, _ = runtime.filter_unavailable_tools(runtime.RECON_TOOLS)
        recon_limited = [t for t in available_recon_tools if t["name"] in analysis_tool_names]
        analysis_candidates = self._apply_scenario_tool_policy(
            recon_limited + skill_tools + runtime.DELIVERABLE_TOOLS, 3
        )
        analysis_tools = [
            self._wrap_tool(t, phase=3, agent="vuln_analysis")
            for t in analysis_candidates
        ]
        phase4_tool_catalog = sorted({
            str(tool.get("name"))
            for tool in [*available_recon_tools, *runtime.SKILL_TOOLS, *runtime.DELIVERABLE_TOOLS]
            if tool.get("name") and not (
                self.sealed and tool.get("name") in runtime.SEALED_FORBIDDEN_TOOLS
            )
        })

        try:
            phase3_timeout_s = max(30.0, float(os.environ.get("LANCE_PHASE3_DEVICE_TIMEOUT_S", "240")))
        except (TypeError, ValueError):
            phase3_timeout_s = 240.0

        def _analyze_device(device: dict):
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
            # reference. Full models receive the complete scanner evidence.
            scan_for_prompt = self._phase3_scan_results_for_prompt(
                scan_data, device_id
            )

            variables = {**self.context}
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

            print(f"  [+] Analyzing: {device_id} ({device_ip})")
            if stream_callback:
                stream_callback({
                    "type": "device_start", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                })

            if self._uses_compact_local_moe():
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
                self.tracker.start_phase(f"analyze_{device_id}")
                result_text = self.provider.chat_with_tools(
                    system_prompt=local_prompt,
                    user_message=f"Write the Phase 3 analyst memo for {device_id} now.",
                    tools=[],
                    max_turns=self.execution_profile.phase3_local_max_turns,
                    max_tokens=self.execution_profile.phase3_local_max_tokens,
                    cost_tracker=self.tracker,
                    stream_callback=self._model_stream_callback(
                        stream_callback, phase=3, agent=f"analyze_{device_id}"
                    ),
                    repeat_guard=False,
                    stop_event=self._stop_event,
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
                        sidecar = self.run_dir / f"03_device_{device_id}_analysis.md"
                        sidecar.write_text(analysis_text + "\n", encoding="utf-8")
                        self._model_stream_callback(
                            None, phase=3, agent=f"analyze_{device_id}_result"
                        )({"type": "text_chunk", "text": analysis_text})
                usage = self.tracker.end_phase()
                if not analysis_text or _looks_unusable_model_memo(analysis_text):
                    raise RuntimeError(
                        "missing_validated_deliverable: no usable Phase 3 analysis memo"
                    )
                if usage:
                    print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns")
                if stream_callback:
                    stream_callback({
                        "type": "device_done", "device_id": device_id,
                        "device_ip": device_ip, "phase": 3,
                        "turns": usage.turns if usage else 0,
                        "run_dir": str(self.run_dir),
                    })
                return

            allowed_tool_names = runtime.phase3_tool_names(
                self.execution_profile, device, scan_data
            )

            device_config = runtime.AgentConfig(
                name=f"analyze_{device_id}",
                phase=3,
                prompt_template="analyze_device",
                deliverable_file=deliverable_file,
                tools=[],
                validator="json_device_vulns",
            )
            device_tools = self._apply_deliverable_transaction(
                [
                    tool for tool in analysis_tools
                    if tool.get("name") in allowed_tool_names
                ],
                device_config,
                stream_callback,
            )
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
            device_tools = captured_tools
            variables["phase3_allowed_tools"] = ", ".join(
                sorted({
                    str(tool.get("name")) for tool in device_tools
                    if tool.get("name")
                })
            )
            variables["phase4_tool_catalog"] = ", ".join(phase4_tool_catalog)
            system_prompt = runtime.load_prompt("analyze_device", variables)
            device_deadline = _time.monotonic() + phase3_timeout_s
            full_completion: dict = {}
            self.tracker.start_phase(f"analyze_{device_id}")
            result_text = self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Review scan results for {device_id} ({device_ip}). "
                    f"Add confirmed CVE, data exposure, authorization, identity, update, and protocol findings. "
                    f"Then call save_deliverable('{deliverable_file}', json_content)."
                ),
                tools=device_tools,
                max_turns=self.execution_profile.phase3_max_turns,
                max_tokens=self.execution_profile.phase3_max_tokens,
                cost_tracker=self.tracker,
                stream_callback=self._model_stream_callback(
                    stream_callback, phase=3, agent=f"analyze_{device_id}"
                ),
                required_tool="save_deliverable",
                terminate_after_tool="save_deliverable",
                stop_event=self._stop_event,
                deadline=device_deadline,
                completion_metadata=full_completion,
            )
            usage = self.tracker.end_phase()
            promoted, validation_error = self._phase3_promoted_deliverable(
                device_id, deliverable_file, save_receipts[-1] if save_receipts else None
            )
            if self.execution_profile.name == "full" and block_recovery.is_truncation(full_completion):
                # A parseable save in a cut-short response is not a completed analysis.
                promoted = False
            if not promoted:
                if (self.execution_profile.name == "full"
                        and block_recovery.is_truncation(full_completion)):
                    log.warning(
                        "Phase 3 analysis for %s truncated on the output budget; "
                        "attempting bounded block recovery",
                        device_id,
                    )
                    self._recover_truncated_phase3_device(
                        device=device,
                        scan_data=scan_data,
                        deliverable_file=deliverable_file,
                        device_tools=device_tools,
                        save_receipts=save_receipts,
                        observations=observations,
                        deadline=device_deadline,
                        stream_callback=stream_callback,
                    )
                    promoted, validation_error = self._phase3_promoted_deliverable(
                        device_id, deliverable_file,
                        save_receipts[-1] if save_receipts else None,
                    )
                    if promoted:
                        if usage:
                            print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns (block recovery)")
                        if stream_callback:
                            stream_callback({
                                "type": "device_done", "device_id": device_id,
                                "device_ip": device_ip, "phase": 3,
                                "turns": usage.turns if usage else 0,
                                "run_dir": str(self.run_dir),
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
            if stream_callback:
                stream_callback({
                    "type": "device_done", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                    "turns": usage.turns if usage else 0,
                    "run_dir": str(self.run_dir),
                })

        worker_count = self._phase3_worker_count(len(surface))
        if worker_count == 1 and len(surface) > 1:
            log.info(
                "Phase 3: serial device analysis (provider=%s, workers=1)",
                getattr(self.provider, "provider", "unknown"),
            )

        phase3_status["worker_count"] = worker_count
        phase3_failures: list[dict] = []

        def _analyze_with_stagger(args):
            idx, device = args
            if worker_count > 1 and idx > 0:
                _time.sleep(min(idx * 2, 6))
            try:
                _analyze_device(device)
                phase3_status["devices_analyzed"] += 1
            except Exception as exc:
                device_id = str(device.get("id") or "unknown")
                log.exception("Phase 3 analysis failed for %s; keeping scanner fallback", device_id)
                failure = {"device_id": device_id, "error": str(exc)}
                if str(exc).startswith("truncated_output:"):
                    failure["cause"] = "truncated_output"
                phase3_failures.append(failure)
                phase3_status["devices_failed"] = phase3_failures
                try:
                    self.tracker.end_phase()
                except Exception:
                    log.debug("Could not close failed Phase 3 tracker for %s", device_id, exc_info=True)
                self._persist_phase3_device_findings(device, scanner_results)
                if stream_callback:
                    device_event = {
                        "type": "device_done", "device_id": device_id,
                        "device_ip": device.get("ip", "unknown"), "phase": 3,
                        "turns": 0, "error": str(exc),
                    }
                    if str(exc).startswith("truncated_output:"):
                        device_event["cause"] = "truncated_output"
                    stream_callback(device_event)

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            list(pool.map(_analyze_with_stagger, enumerate(surface)))

        phase3_status["status"] = (
            "completed_with_device_errors"
            if phase3_failures or phase3_status["scanner_errors"] or phase3_status.get("surface_error")
            else "completed"
        )
        if phase3_status["status"] == "completed_with_device_errors":
            self._phase3_execution_status = "executed_with_worker_errors"
        phase3_status["finished_at"] = datetime.now().astimezone().isoformat()
        _save_phase3_status()

        print(f"\n{'=' * 60}")
        print(f"  All {len(surface)} analysis agents finished.")
        print(f"{'=' * 60}\n")


def run(context, config, stream_callback=None):
    return context._run_agent(config, stream_callback)
