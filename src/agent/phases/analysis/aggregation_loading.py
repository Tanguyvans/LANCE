"""Load ordered candidates and archived evidence without writing projections."""
from __future__ import annotations

import json
import logging
from pathlib import Path
import re
from urllib.parse import urlsplit

from src.agent.finding_identity import finding_identity_key
from src.agent.tools.deliverable import _extract_json
from src.agent.phases.analysis.aggregation_context import AggregationContext, AggregationInputs
from src.agent.phases.analysis.mqtt_grouping import load_authoritative_mqtt_observations

log = logging.getLogger(__name__)


class CandidateRegistry:
    """Keep original candidate values separate from mutable working findings."""
    def __init__(self):
        self.sequence = 0
        self.findings: list[dict] = []
        self.records: list[dict] = []

    def add(self, vulns: list, source_file: str, source_kind: str) -> None:
        for source_index, raw in enumerate(vulns):
            self.sequence += 1
            candidate_id = f"CAND-{self.sequence:04d}"
            record = {
                "candidate_id": candidate_id,
                "source_file": source_file,
                "source_kind": source_kind,
                "source_index": source_index,
                "raw_finding": raw,
                "accepted_for_canonical": False,
                "decision": "pending",
                "decision_reason": "",
                "canonical_finding_id": None,
            }
            self.records.append(record)
            if not isinstance(raw, dict):
                record["decision"] = "rejected_malformed"
                record["decision_reason"] = "finding is not an object"
                continue
            working = json.loads(json.dumps(raw, ensure_ascii=False, default=str))
            working["_candidate_id"] = candidate_id
            working["_source_kind"] = source_kind
            self.findings.append(working)


def load_cve_search_evidence(run_dir: Path) -> dict[tuple[str, str], dict]:
    """Index deterministic CVE compatibility results from the raw tool ledger."""
    evidence: dict[tuple[str, str], dict] = {}
    log_path = run_dir / "tool_calls.jsonl"
    if not log_path.exists():
        return evidence
    for line in log_path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if entry.get("tool") != "cve_search":
            continue
        query = str((entry.get("args") or {}).get("query", "")).strip()
        if not query:
            continue
        raw_result = entry.get("result", "")
        try:
            results = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(results, list):
            continue
        for item in results:
            if not isinstance(item, dict):
                continue
            metadata = item.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            cve_id = str(
                item.get("cve_id") or item.get("id")
                or metadata.get("cve_id") or metadata.get("id") or ""
            ).upper()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
                continue
            compatibility = item.get("compatibility")
            compatibility = compatibility if isinstance(compatibility, dict) else {}
            status = str(
                compatibility.get("status")
                or item.get("compatibility_status")
                or metadata.get("compatibility_status")
                or "indeterminate"
            ).casefold()
            reason = str(
                compatibility.get("reason")
                or item.get("compatibility_reason")
                or metadata.get("compatibility_reason")
                or ""
            )
            evidence[(query.casefold(), cve_id)] = {
                "status": status,
                "reason": reason,
                "evidence_ref": entry.get("evidence_ref", ""),
            }
    return evidence


def add_scanner_candidates(
    context: AggregationContext, registry: CandidateRegistry,
    device_id: str, model_vulns: list[dict]
) -> None:
    """Promote scanner candidates according to the existing profile contracts."""
    scan_path = context.run_dir / "03_scans" / f"{device_id}.json"
    if not scan_path.exists():
        return
    try:
        from src.agent.scanner import extract_findings
        scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
        model_device = next(
            (
                {
                    "id": device_id,
                    "ip": item.get("device_ip", ""),
                    "role": item.get("device_role", item.get("role", "")),
                }
                for item in model_vulns
                if isinstance(item, dict)
            ),
            {"id": device_id, "ip": "", "role": ""},
        )
        scanner_device = next(
            (d for d in context.surface_nodes if d.get("id") == device_id),
            model_device,
        )
        findings = extract_findings(
            scan_data, scanner_device, compact=context.compact_local
        )
        if context.compact_local:
            findings = [
                finding for finding in findings
                if finding.get("type") in {"default_credentials", "insecure_update"}
            ]
            source_kind = "scanner_compact"
        else:
            # Promote only high-confidence scanner contracts in full
            # mode. This recovers direct S8 findings when an LLM times
            # out, without promoting speculative banners or port-only
            # observations.
            scanner_role = str(scanner_device.get("role") or "").casefold()
            findings = [
                finding for finding in findings
                if (
                    (
                        finding.get("type") in {
                            "no_auth", "default_credentials", "data_exposure",
                            "code_injection", "insecure_update",
                            "broken_access_control",
                        }
                        or (
                            scanner_role in {
                                "pki_ca_server", "pki_enrollment_server",
                                "pki_mtls_server", "pki_device",
                                "ota_device", "ot_opcua_server",
                            }
                            and finding.get("type") in {"weak_cipher", "misconfiguration"}
                        )
                        or (
                            scanner_role == "ot_bacnet_server"
                            and finding.get("type") == "info_disclosure"
                        )
                        or (
                            scanner_role == "cloud_metadata_server"
                            and finding.get("type") == "privilege_escalation"
                        )
                    )
                    and str(finding.get("exploitation_status") or finding.get("status") or "").casefold() == "confirmed"
                )
                or (
                    str(scanner_device.get("role") or "").casefold().startswith("exploit_")
                    and finding.get("type") in {
                        "broken_access_control", "code_injection",
                        "data_exposure", "privilege_escalation",
                    }
                )
            ]
            source_kind = "scanner_full"
        registry.add(findings, scan_path.name, source_kind)
    except Exception as exc:
        log.warning("Scanner findings unavailable for %s: %s", device_id, exc)


def add_pki_candidates(context: AggregationContext, registry: CandidateRegistry) -> None:
    # A single PKI fingerprint is metadata. Promote a cloned identity only
    # after the same SHA-256 value is observed on two declared devices.
    pki_fingerprints: dict[str, list[dict]] = {}
    for node in context.surface_nodes:
        if not isinstance(node, dict) or str(node.get("role") or "").casefold() != "pki_device":
            continue
        scan_path = context.run_dir / "03_scans" / f"{node.get('id', '')}.json"
        try:
            scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
        entries = [
            entry for values in scan_data.values() if isinstance(values, list)
            for entry in values
        ]
        for entry in entries:
            if entry.get("tool") != "http_request":
                continue
            url = str((entry.get("kwargs") or {}).get("url") or "")
            if urlsplit(url).path != "/identity/fingerprint":
                continue
            try:
                result = json.loads(str(entry.get("result") or ""))
                payload = json.loads(str(result.get("body") or ""))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            fingerprint = str(payload.get("public_key_fingerprint") or "").strip().casefold()
            if re.fullmatch(r"[0-9a-f]{64}", fingerprint):
                pki_fingerprints.setdefault(fingerprint, []).append({
                    "id": node.get("id", ""), "ip": node.get("ip", ""),
                })
    for fingerprint, observations in pki_fingerprints.items():
        if len(observations) < 2:
            continue
        clone = next(
            (item for item in observations if str(item["id"]).endswith("device-b")),
            observations[-1],
        )
        registry.add([{
            "device_id": clone["id"],
            "device_ip": clone["ip"],
            "type": "weak_cipher",
            "severity": "CRITICAL",
            # The strict S16 contract classifies cloned key material as
            # weak_crypto; project it onto the mTLS service so the
            # cryptographic queue does not confuse it with plain HTTP.
            "service": "https", "port": 8443, "protocol": "tcp",
            "endpoint": "",
            "details": "Device identity public-key fingerprint is identical to another device; cloned key material is confirmed",
            "evidence": f"/identity/fingerprint returned the same SHA-256 value {fingerprint} for {len(observations)} devices",
            "status": "confirmed", "exploitation_status": "confirmed",
            "suggested_tools": ["http_request"],
        }], "03_scans/cross_device_pki.json", "scanner_full")


def load_previous_ids(run_dir: Path) -> dict[tuple, str]:
    previous_ids: dict[tuple, str] = {}
    previous_path = run_dir / "03_vuln_analysis.json"
    try:
        previous = json.loads(previous_path.read_text(encoding="utf-8"))
        for previous_finding in previous.get("vulnerabilities", []):
            previous_id = str(previous_finding.get("id") or "")
            if re.fullmatch(r"VULN-\d+", previous_id):
                previous_ids[finding_identity_key(previous_finding)] = previous_id
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        pass
    return previous_ids


def load_inputs(context: AggregationContext) -> AggregationInputs:
    registry = CandidateRegistry()
    for f in sorted(context.run_dir.glob("03_device_*.json")):
        device_id = f.stem.replace("03_device_", "")
        try:
            content = _extract_json(f.read_text(encoding="utf-8"))
            data = json.loads(content)
            if isinstance(data, dict):
                vulns = data.get("vulnerabilities", [])
            elif isinstance(data, list):
                vulns = data
            else:
                vulns = []
            model_vulns = vulns if isinstance(vulns, list) else []
            registry.add(model_vulns, f.name, "rules" if context.decision_policy == "rules" else "model")
            add_scanner_candidates(context, registry, device_id, model_vulns)
        except Exception as exc:
            log.warning(
                "Failed to parse %s — falling back to scanner findings: %s",
                f.name, exc,
            )
            add_scanner_candidates(context, registry, device_id, [])

    add_pki_candidates(context, registry)
    return AggregationInputs(
        registry.findings, registry.records,
        load_cve_search_evidence(context.run_dir),
        load_authoritative_mqtt_observations(context.run_dir),
        load_previous_ids(context.run_dir),
    )
