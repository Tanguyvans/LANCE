"""Analysis phase: compact adaptations."""
from __future__ import annotations
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit
from uuid import uuid4
import json
import re
from src.agent.core import runtime


class CompactAnalysisPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    @staticmethod
    def _compact_phase3_scan_results(
        scan_data: dict, *, max_chars: int = 5000, per_result_chars: int = 700
    ) -> dict:
        """Bound the small-model prompt while retaining full scans on disk."""
        compact: dict[str, list[dict] | dict] = {}
        used = 0
        omitted = 0
        scan_results = scan_data.get("scan_results", {})
        if not isinstance(scan_results, dict):
            scan_results = {}
        for service_key, entries in scan_results.items():
            if not isinstance(entries, list):
                continue
            compact_entries: list[dict] = []
            for entry in entries:
                if not isinstance(entry, dict):
                    omitted += 1
                    continue
                raw_result = entry.get("result", "")
                rendered = (
                    raw_result if isinstance(raw_result, str)
                    else json.dumps(raw_result, ensure_ascii=False, default=str)
                )
                if len(rendered) > per_result_chars:
                    head = max(1, (per_result_chars - 64) * 2 // 3)
                    tail = max(1, per_result_chars - 64 - head)
                    rendered = (
                        rendered[:head]
                        + "\n[... prompt summary; full result retained in 03_scans ...]\n"
                        + rendered[-tail:]
                    )
                candidate = {
                    "tool": entry.get("tool", ""),
                    "kwargs": entry.get("kwargs", {}),
                    "result": rendered,
                }
                candidate_size = len(json.dumps(
                    candidate, separators=(",", ":"), ensure_ascii=False
                ))
                if used + candidate_size > max_chars:
                    omitted += 1
                    continue
                compact_entries.append(candidate)
                used += candidate_size
            if compact_entries:
                compact[str(service_key)] = compact_entries

        compact["_evidence_projection"] = {
            "omitted_entries": omitted,
            "full_scan_artifact": "03_scans/<device_id>.json",
            "policy": (
                "Prompt-sized projection only; deterministic findings and the full "
                "scanner artifact remain available without truncation."
            ),
        }
        return compact

    def _run_phase3_local_cve_validation(
        self,
        scanner_results: dict[str, dict],
        surface: list[dict],
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Deterministic local-MoE CVE/version pass with auditable tool ledger."""
        recon_policy = runtime.tool_policy_for_phase(
            self.scenario_tool_policy, "recon"
        )
        cve_enabled = recon_policy is None or "cve_search" in recon_policy
        records: list[dict] = []
        log_path = self.run_dir / "tool_calls.jsonl"
        if not cve_enabled:
            (self.run_dir / "03_cve_validation.json").write_text(
                json.dumps({
                    "mode": "local_moe_deterministic",
                    "queries": 0,
                    "compatible_cves": 0,
                    "records": [],
                    "status": "skipped_by_scenario_tool_policy",
                }, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            return
        for device in surface:
            if not isinstance(device, dict):
                continue
            device_id = device.get("id", "")
            scan_data = scanner_results.get(device_id, {})
            device_changed = False
            for query_info in self._phase3_version_queries_for_device(device, scan_data):
                query = str(query_info.get("query", "")).strip()
                if not query:
                    continue
                evidence_ref = f"tc-{uuid4().hex}"
                with self._artifact_log_lock:
                    if self.max_tool_calls is not None and self._tool_call_count >= self.max_tool_calls:
                        sequence = None
                    else:
                        self._tool_call_count += 1
                        sequence = self._tool_call_count
                if sequence is None:
                    records.append({
                        **query_info,
                        "query": query,
                        "status": "skipped",
                        "reason": f"tool-call budget exhausted ({self.max_tool_calls})",
                    })
                    continue
                try:
                    raw_result = runtime.cve_search(query=query, top_k=5)
                except Exception as exc:
                    raw_result = json.dumps({"error": str(exc)}, ensure_ascii=False)
                entry = {
                    "timestamp": datetime.now().astimezone().isoformat(),
                    "sequence": sequence,
                    "tool": "cve_search",
                    "args": {"query": query, "top_k": 5},
                    "result": raw_result if isinstance(raw_result, str) else str(raw_result),
                    "evidence_ref": evidence_ref,
                    "phase": 3,
                    "device_id": query_info.get("device_id", ""),
                    "device_ip": query_info.get("device_ip", ""),
                    "service": query_info.get("service", ""),
                    "port": query_info.get("port"),
                    "product": query_info.get("product", ""),
                    "version": query_info.get("version", ""),
                }
                with self._artifact_log_lock:
                    with log_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
                compatible_items = self._phase3_compatible_cve_items(raw_result)
                for item in compatible_items:
                    device_changed = self._append_phase3_cve_finding(
                        scanner_results, query_info, item, evidence_ref
                    ) or device_changed
                records.append({
                    **query_info,
                    "query": query,
                    "status": "completed",
                    "evidence_ref": evidence_ref,
                    "compatible_cves": [
                        str(
                            item.get("cve_id") or item.get("id")
                            or (item.get("metadata") or {}).get("cve_id")
                            or (item.get("metadata") or {}).get("id")
                        ).upper()
                        for item in compatible_items
                    ],
                })
                if stream_callback:
                    stream_callback({
                        "type": "phase3_cve_check",
                        "phase": 3,
                        "device_id": query_info.get("device_id", ""),
                        "query": query,
                        "compatible_cves": records[-1]["compatible_cves"],
                    })
            if device_changed or not (self.run_dir / f"03_device_{device_id}.json").exists():
                self._persist_phase3_device_findings(device, scanner_results)

        summary = {
            "mode": "local_moe_deterministic",
            "queries": len(records),
            "compatible_cves": sum(len(r.get("compatible_cves", [])) for r in records),
            "records": records,
        }
        (self.run_dir / "03_cve_validation.json").write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @staticmethod
    def _apply_compact_finding_policy(finding: dict) -> None:
        """Apply compact evidence metadata without changing full-mode findings."""
        vuln_type = str(finding.get("type") or "").casefold()
        service = str(finding.get("service") or "").casefold()
        try:
            port = int(finding.get("port"))
        except (TypeError, ValueError):
            port = None
        status = str(finding.get("exploitation_status") or "").casefold()
        evidence = str(finding.get("evidence") or "")
        direct = status == "confirmed" and bool(evidence.strip())
        finding.setdefault("compact_confidence", "direct" if direct else "suspected")
        finding.setdefault("compact_evidence_kind", "direct_observation" if direct else "heuristic")
        finding.setdefault("compact_requires_verification", not direct)

        if vuln_type in {"missing_header", "directory_listing"} or (
            vuln_type == "info_disclosure"
            and str(finding.get("severity") or "").upper() == "LOW"
        ):
            finding["compact_report_only"] = True
            finding["compact_requires_verification"] = False

        if vuln_type == "no_auth" and (
            port in {102, 502, 44818, 5683}
            or service in {"modbus", "s7comm", "ethernet/ip", "coap"}
        ):
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "open_service"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "protocol_response"

        if vuln_type == "code_injection" and not re.search(
            r"(?i)(?:uid=|command\s+output|executed|shell\s+opened|rce\s+confirmed)",
            evidence,
        ):
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "endpoint_presence"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "safe_http_validation"

        if vuln_type == "insecure_update":
            finding["exploitation_status"] = "suspected"
            finding["compact_confidence"] = "suspected"
            finding["compact_evidence_kind"] = "endpoint_presence"
            finding["compact_requires_verification"] = True
            finding["compact_required_probe"] = "safe_http_validation"

    @staticmethod
    def _compact_observation_has_tool_evidence(
        finding: dict, tool_records: list[dict]
    ) -> bool:
        """Return whether a compact report-only observation has phase-2 support.

        Compact models can identify useful low-severity observations, but their
        model output must not be enough by itself to promote one into the
        canonical queue. This check only accepts evidence from the archived
        phase-2 tool log, keeping phase 4 from influencing its own input.
        """
        target = str(finding.get("device_ip") or finding.get("ip") or "").strip()
        vuln_type = str(finding.get("type") or "").casefold()
        service = str(finding.get("service") or "").casefold()
        if not target or vuln_type not in {
            "info_disclosure", "missing_header", "directory_listing"
        }:
            return False

        if vuln_type == "info_disclosure":
            finding_text = " ".join(
                str(finding.get(key) or "")
                for key in ("details", "evidence", "endpoint", "endpoints")
            ).casefold()
            if service == "ssh":
                # A passive OpenSSH/Dropbear version is asset metadata, not a
                # score-worthy compact finding by itself. Keep specific
                # banners or explicit OS/version disclosures.
                if not re.search(
                    r"(custom|non[- ]standard|service returns|"
                    r"operating system|os\s+(?:and\s+)?version|"
                    r"version\s+(?:and\s+)?os)",
                    finding_text,
                ):
                    return False
            elif service in {"http", "https", "web"}:
                # Generic Server: nginx is likewise only configuration
                # metadata. Promote disclosures tied to a sensitive resource.
                if not re.search(
                    r"(robots\.txt|sensitive|internal|backup|config|"
                    r"credential|password|secret|token|private)",
                    finding_text,
                ):
                    return False
            elif service == "mqtt":
                if not re.search(
                    r"(credential|password|secret|token|sensitive)",
                    finding_text,
                ):
                    return False
            else:
                return False

        try:
            finding_port = int(finding.get("port"))
        except (TypeError, ValueError):
            finding_port = 443 if service == "https" else 80

        def _payload(record: dict):
            result = record.get("result")
            if isinstance(result, str):
                try:
                    return json.loads(result)
                except (TypeError, ValueError):
                    return result
            return result

        def _successful(payload) -> bool:
            if isinstance(payload, dict):
                if payload.get("ok") is False or str(payload.get("status", "")).casefold() in {
                    "error", "failed", "failure"
                }:
                    return False
                return payload.get("return_code") in (None, 0)
            return not str(payload or "").casefold().startswith("error")

        def _output(payload) -> str:
            if isinstance(payload, dict):
                parts = [
                    payload.get(key, "")
                    for key in ("stdout", "output", "headers", "body", "data")
                ]
                return "\n".join(str(part) for part in parts if part)
            return str(payload or "")

        def _record_target(args: dict) -> str:
            for key in ("target", "ip", "host", "broker"):
                value = args.get(key)
                if value:
                    return str(value).strip()
            for key in ("url", "uri"):
                value = args.get(key)
                if value:
                    try:
                        return str(urlsplit(str(value)).hostname or "").strip()
                    except ValueError:
                        return ""
            return ""

        for record in tool_records:
            if record.get("phase") not in (2, "2"):
                continue
            tool = str(record.get("tool") or record.get("name") or "").casefold()
            args = record.get("args") or record.get("kwargs") or {}
            if not isinstance(args, dict) or _record_target(args) != target:
                continue
            payload = _payload(record)
            if not _successful(payload):
                continue
            output = _output(payload)
            output_lower = output.casefold()

            if vuln_type in {"missing_header", "directory_listing"}:
                if tool == "curl_headers" and (
                    (
                        vuln_type == "missing_header"
                        and (
                            "http/" in output_lower
                            or "strict-transport-security" in output_lower
                            or "x-frame-options" in output_lower
                            or "content-security-policy" in output_lower
                        )
                    )
                    or (
                        vuln_type == "directory_listing"
                        and (
                            "index of" in output_lower
                            or "directory listing" in output_lower
                        )
                    )
                ):
                    return True
                continue

            if service == "mqtt":
                if tool == "mqtt_listen" and (
                    "$sys" in output_lower or "mosquitto" in output_lower
                ):
                    return True
                continue

            if service == "ssh":
                if tool == "nmap_scan" and re.search(
                    r"(?im)\b22/tcp\s+open\s+ssh\b", output
                ) and re.search(r"(?i)(openssh|dropbear|ssh)", output):
                    return True
                if tool == "ssh_audit" and re.search(
                    r"(?i)(openssh|dropbear|ssh)", output
                ):
                    return True
                continue

            if service in {"http", "https", "web"}:
                if tool == "nmap_scan" and re.search(
                    rf"(?im)\b{finding_port}/tcp\s+open\s+https?\b", output
                ) and re.search(r"(?i)(nginx|apache|http|iis)", output):
                    return True
                if tool == "curl_headers" and "server:" in output_lower:
                    return True

        return False
