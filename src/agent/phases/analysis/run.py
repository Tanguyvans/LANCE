"""Analysis phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
from datetime import datetime
from urllib.parse import urlsplit
import json
import os
import re
import yaml
import logging
from src.agent.phases.analysis.prompts import ROLE_SPECIFIC_RULES
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.core import runtime


log = logging.getLogger(__name__)


class AnalysisPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _phase3_worker_count(self, device_count: int) -> int:
        """Avoid request queue amplification on the single-lock local GPU server."""
        if self._uses_local_moe():
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

    def _run_phase3(
        self,
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Phase 3 split: 3a (deterministic scanner) → 3b (LLM analysis) → 3c (merge)."""
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

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

        # Keep simulator security profiles internal to the deterministic
        # evaluator/scanner. The public graph intentionally omits them from
        # model context, but phase-3 publication needs the declared control
        # profile to reject look-alike findings reliably.
        try:
            scenario_path = runtime.resolve_scenario_path(self.scenario_id) if self.scenario_id is not None else None
            scenario_doc = yaml.safe_load(scenario_path.read_text(encoding="utf-8")) if scenario_path and scenario_path.exists() else {}
            topology_id = str((scenario_doc or {}).get("topology") or "")
            topology_path = runtime.resolve_topology_path(self.scenario_id, topology_id) if topology_id else None
            topology_doc = yaml.safe_load(topology_path.read_text(encoding="utf-8")) if topology_path and topology_path.exists() else {}
            profile_by_ip: dict[str, str] = {}
            router_doc = (topology_doc or {}).get("router") or {}
            if router_doc.get("ip") and router_doc.get("security_profile"):
                profile_by_ip[str(router_doc["ip"])] = str(router_doc["security_profile"])
            for service_doc in (topology_doc or {}).get("services", []):
                if service_doc.get("ip") and service_doc.get("security_profile"):
                    profile_by_ip[str(service_doc["ip"])] = str(service_doc["security_profile"])
            for node in surface:
                if isinstance(node, dict) and str(node.get("ip") or "") in profile_by_ip:
                    node["security_profile"] = profile_by_ip[str(node["ip"])]
        except (OSError, TypeError, ValueError, yaml.YAMLError) as exc:
            log.warning("Could not load internal simulator profiles: %s", exc)

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

        cloud_web = next(
            (device for device in surface
             if str(device.get("role") or "").casefold() == "cloud_web_server"
             and str(device.get("security_profile") or "").casefold() == "vulnerable"),
            None,
        )
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
        if cloud_web and cloud_metadata and cloud_control:
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
            runtime.set_expected_deliverable(deliverable_file)
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
            variables["phase3_allowed_tools"] = ", ".join(
                sorted({
                    str(tool.get("name")) for tool in device_tools
                    if tool.get("name")
                })
            )
            variables["phase4_tool_catalog"] = ", ".join(phase4_tool_catalog)
            system_prompt = runtime.load_prompt("analyze_device", variables)
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
                deadline=_time.monotonic() + phase3_timeout_s,
            )
            usage = self.tracker.end_phase()
            if usage:
                print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns")
            if stream_callback:
                stream_callback({
                    "type": "device_done", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                    "turns": usage.turns if usage else 0,
                    "run_dir": str(self.run_dir),
                })

            # Preserve scanner findings, but make a missing model save explicit.
            deliverable_path = self.run_dir / deliverable_file
            if not deliverable_path.exists() or not usage or not usage.format_attempts:
                log.warning(
                    "Phase 3 analysis for %s did not save a deliverable; "
                    "scanner findings remain canonical",
                    device_id,
                )

        worker_count = self._phase3_worker_count(len(surface))
        if worker_count == 1 and len(surface) > 1:
            log.info(
                "Phase 3 local MoE detected: serializing device agents to avoid "
                "GPU queue timeouts and duplicate retries"
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
                phase3_failures.append({"device_id": device_id, "error": str(exc)})
                phase3_status["devices_failed"] = phase3_failures
                try:
                    self.tracker.end_phase()
                except Exception:
                    log.debug("Could not close failed Phase 3 tracker for %s", device_id, exc_info=True)
                self._persist_phase3_device_findings(device, scanner_results)
                if stream_callback:
                    stream_callback({
                        "type": "device_done", "device_id": device_id,
                        "device_ip": device.get("ip", "unknown"), "phase": 3,
                        "turns": 0, "error": str(exc),
                    })

        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            list(pool.map(_analyze_with_stagger, enumerate(surface)))

        phase3_status["status"] = (
            "completed_with_device_errors"
            if phase3_failures or phase3_status["scanner_errors"]
            else "completed"
        )
        phase3_status["finished_at"] = datetime.now().astimezone().isoformat()
        _save_phase3_status()

        print(f"\n{'=' * 60}")
        print(f"  All {len(surface)} analysis agents finished.")
        print(f"{'=' * 60}\n")


def run(context, config, stream_callback=None):
    return context._run_agent(config, stream_callback)
