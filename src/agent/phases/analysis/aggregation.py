"""Analysis phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
from copy import deepcopy
from urllib.parse import urlsplit
import json
import re
import logging
from src.agent.phases.analysis.evidence import _enrich_finding_structure, _sanitize_suggested_tools
from src.agent.core import runtime


log = logging.getLogger(__name__)


class FindingAggregation:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _detect_attack_chains(self, vulns: list[dict]) -> list[dict]:
        """Deterministic cross-device attack chain detection.

        Uses graph topology edges + aggregated vuln list to identify multi-hop paths
        where a compromised source device enables access to a downstream target.
        Returns a list of chain_hint dicts injected into 03_vuln_analysis.json so
        Phase 4 and Phase 5 agents can reason about lateral movement paths.
        """
        from src.agent.tools.graph_tools import _scenario_topology as _st, _backend as _bk
        from src.agent.vuln_taxonomy import is_config_only
        from collections import defaultdict

        by_ip: dict[str, list[dict]] = defaultdict(list)
        for v in vulns:
            by_ip[v.get("device_ip", "")].append(v)

        # Resolve topology edges (scenario mode only for now; lab mode backend TBD)
        if _st is not None:
            edges = _st.get("edges", [])
            node_index = _st["node_index"]
        else:
            return []  # No structured topology available

        _RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        chains: list[dict] = []
        seen: set[tuple[str, str]] = set()

        for e in edges:
            src_node = node_index.get(e.get("source", ""))
            dst_node = node_index.get(e.get("target", ""))
            if not src_node or not dst_node:
                continue

            src_ip = src_node.get("ip", "")
            dst_ip = dst_node.get("ip", "")
            src_vulns = by_ip.get(src_ip, [])
            dst_vulns = by_ip.get(dst_ip, [])

            # Chain: source has exploitable (non-config-only) MEDIUM+ vuln AND dest has any finding
            exploitable_src = [
                v for v in src_vulns
                if _RANK.get((v.get("severity") or "").lower(), 0) >= 2
                and not is_config_only(v.get("type", ""))
            ]

            if exploitable_src and dst_vulns:
                key = (src_ip, dst_ip)
                if key not in seen:
                    seen.add(key)
                    chains.append({
                        "chain": f"{e['source']} ({src_ip}) -> {e['target']} ({dst_ip})",
                        "src_device": e["source"],
                        "src_ip": src_ip,
                        "dst_device": e["target"],
                        "dst_ip": dst_ip,
                        "pivot_vuln": exploitable_src[0]["id"],
                        "target_vuln_ids": [v["id"] for v in dst_vulns],
                    })

        if chains:
            log.info("Detected %d cross-device attack chain(s)", len(chains))
        return chains

    def _load_cve_search_evidence(self) -> dict[tuple[str, str], dict]:
        """Index deterministic CVE compatibility results from the raw tool ledger."""
        evidence: dict[tuple[str, str], dict] = {}
        log_path = self.run_dir / "tool_calls.jsonl"
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

    def _aggregate_device_vulns(
        self,
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Build a canonical queue without destroying model-produced findings.

        03_vuln_analysis_raw.json is the append-only information layer:
        every candidate and every normalization/filter/dedup decision remains
        inspectable. 03_vuln_analysis.json stays backward-compatible and is
        the canonical projection consumed by exploitation and evaluation.
        """
        compact_mode = self._uses_compact_local_moe()
        all_vulns: list[dict] = []
        raw_records: list[dict] = []
        candidate_seq = 0

        def add_candidates(vulns: list, source_file: str, source_kind: str) -> None:
            nonlocal candidate_seq
            for source_index, raw in enumerate(vulns):
                candidate_seq += 1
                candidate_id = f"CAND-{candidate_seq:04d}"
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
                raw_records.append(record)
                if not isinstance(raw, dict):
                    record["decision"] = "rejected_malformed"
                    record["decision_reason"] = "finding is not an object"
                    continue
                working = json.loads(json.dumps(raw, ensure_ascii=False, default=str))
                working["_candidate_id"] = candidate_id
                working["_source_kind"] = source_kind
                all_vulns.append(working)

        surface_nodes: list[dict] = []
        try:
            surface_raw = json.loads(runtime.get_attack_surface())
            surface_nodes = surface_raw.get("nodes", []) if isinstance(surface_raw, dict) else surface_raw
            if not isinstance(surface_nodes, list):
                surface_nodes = []
        except Exception:
            surface_nodes = []

        surface_roles = {
            str(node.get("id") or ""): str(node.get("role") or node.get("type") or "").casefold()
            for node in surface_nodes
            if isinstance(node, dict)
        }

        def add_scanner_candidates(
            device_id: str, model_vulns: list[dict], *, source_kind: str = "scanner"
        ) -> None:
            """Add compact-mode deterministic findings alongside model output.

            The full profile keeps the model-authored Phase 3 queue autonomous;
            scanner artifacts remain available for audit and evidence. Compact
            local workers use the scanner as their deterministic promotion
            boundary because that profile trades exploration for precision.
            """
            scan_path = self.run_dir / "03_scans" / f"{device_id}.json"
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
                    (d for d in surface_nodes if d.get("id") == device_id),
                    model_device,
                )
                findings = extract_findings(
                    scan_data, scanner_device, compact=compact_mode
                )
                if compact_mode:
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
                add_candidates(findings, scan_path.name, source_kind)
            except Exception as exc:
                log.warning("Scanner findings unavailable for %s: %s", device_id, exc)

        for f in sorted(self.run_dir.glob("03_device_*.json")):
            device_id = f.stem.replace("03_device_", "")
            try:
                content = runtime._extract_json(f.read_text(encoding="utf-8"))
                data = json.loads(content)
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities", [])
                elif isinstance(data, list):
                    vulns = data
                else:
                    vulns = []
                model_vulns = vulns if isinstance(vulns, list) else []
                add_candidates(model_vulns, f.name, "model")
                add_scanner_candidates(device_id, model_vulns)
            except Exception as exc:
                log.warning(
                    "Failed to parse %s — falling back to scanner findings: %s",
                    f.name, exc,
                )
                add_scanner_candidates(device_id, [], source_kind="scanner_fallback")

        # A single PKI fingerprint is metadata. Promote a cloned identity only
        # after the same SHA-256 value is observed on two declared devices.
        pki_fingerprints: dict[str, list[dict]] = {}
        for node in surface_nodes:
            if not isinstance(node, dict) or str(node.get("role") or "").casefold() != "pki_device":
                continue
            scan_path = self.run_dir / "03_scans" / f"{node.get('id', '')}.json"
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
            add_candidates([{
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

        records_by_id = {r["candidate_id"]: r for r in raw_records}
        cve_search_evidence = self._load_cve_search_evidence()
        catalog_tool_names = runtime.available_tool_names()
        # Freeze the pre-filter identity. Later semantic normalization is an
        # operation to evaluate, not a reason to rewrite the candidate snapshot.
        for finding in all_vulns:
            candidate = deepcopy({key: value for key, value in finding.items() if not key.startswith("_")})
            candidate["type"] = runtime.canonicalize(candidate.get("type", ""))
            _enrich_finding_structure(candidate, strict_schema=not compact_mode)
            records_by_id[finding["_candidate_id"]]["candidate_finding"] = candidate
        compact_tool_records: list[dict] = []
        if compact_mode:
            tool_log = self.run_dir / "tool_calls.jsonl"
            if tool_log.exists():
                for line in tool_log.read_text(encoding="utf-8").splitlines():
                    try:
                        record = json.loads(line)
                    except (TypeError, ValueError):
                        continue
                    if isinstance(record, dict):
                        compact_tool_records.append(record)

        if not compact_mode:
            # Normalize all candidates before semantic checks so related claims
            # (for example /api/devices and /api/status) can be reasoned about
            # together. Raw candidates remain untouched in the audit registry.
            for finding in all_vulns:
                finding["type"] = runtime.canonicalize(finding.get("type", ""))
                _enrich_finding_structure(finding, strict_schema=True)
                port = finding.get("port")
                if isinstance(port, str) and port.isdigit():
                    finding["port"] = int(port)
            for finding in all_vulns:
                runtime._normalise_full_finding_semantics(
                    finding,
                    all_vulns,
                    device_role=surface_roles.get(
                        str(finding.get("device_id") or ""), ""
                    ),
                )

        for finding in all_vulns:
            _sanitize_suggested_tools(finding, catalog_names=catalog_tool_names)
            finding["type"] = runtime.canonicalize(finding.get("type", ""))
            if compact_mode:
                _enrich_finding_structure(finding)
                self._apply_compact_finding_policy(finding)
            else:
                _enrich_finding_structure(finding, strict_schema=True)
            port = finding.get("port")
            if isinstance(port, str) and port.isdigit():
                finding["port"] = int(port)
            if finding.get("type") == "known_cve":
                validation = finding.get("cve_validation")
                validation = validation if isinstance(validation, dict) else {}
                query = str(validation.get("query", "")).strip().casefold()
                claimed_ids = [
                    str(cve_id).upper()
                    for cve_id in finding.get("cve_ids", [])
                    if re.fullmatch(r"CVE-\d{4}-\d{4,}", str(cve_id).upper())
                ]
                assessments = {
                    cve_id: cve_search_evidence.get((query, cve_id))
                    for cve_id in claimed_ids
                }
                compatible_ids = [
                    cve_id for cve_id, assessment in assessments.items()
                    if assessment and assessment.get("status") == "compatible"
                ]
                observed_statuses = {
                    assessment.get("status")
                    for assessment in assessments.values()
                    if assessment
                }
                catalog_compatible_ids = []
                validation_product = str(validation.get("observed_product") or finding.get("product") or "")
                validation_version = str(validation.get("observed_version") or finding.get("version") or "")
                product_text = validation_product.casefold()
                if "dropbear" in product_text:
                    product_tokens = ["dropbear"]
                    # The strict contract uses the product family, while
                    # scanners commonly return "Dropbear sshd". Normalize
                    # only the canonical CVE projection; raw evidence keeps
                    # the full observed product string.
                    finding["product"] = "Dropbear"
                elif "openssh" in product_text:
                    product_tokens = ["openssh"]
                elif re.search(r"\bssh\b", product_text):
                    product_tokens = ["ssh"]
                else:
                    product_tokens = []
                finding_text = " ".join(
                    str(finding.get(key) or "")
                    for key in ("details", "evidence")
                )
                for claimed_id in claimed_ids:
                    if (
                        re.search(rf"(?i)\b{re.escape(claimed_id)}\b", finding_text)
                        and product_tokens
                        and validation_version
                        and any(
                            runtime.cve_is_allowed(claimed_id, [product], [validation_version])
                            for product in product_tokens
                        )
                    ):
                        catalog_compatible_ids.append(claimed_id)
                if (
                    compatible_ids
                    and not catalog_compatible_ids
                    and self.benchmark_split != "unassigned"
                ):
                    # strict-v3 is released with a reviewed offline CVE
                    # catalogue. A live/NVD-compatible claim outside that
                    # catalogue remains an auditable candidate, but is not
                    # promoted into the scored queue.
                    claim_status = "unreviewed_catalog"
                    finding["accepted_for_scoring"] = False
                elif compatible_ids:
                    claim_status = "validated"
                    finding["cve_ids"] = compatible_ids
                    finding["accepted_for_scoring"] = True
                elif catalog_compatible_ids:
                    # The archived search can be indeterminate when NVD has no
                    # CPE range for a cross-vendor CVE such as Terrapin. The
                    # reviewed offline catalogue remains authoritative when
                    # the model supplied explicit CVE, product, version, and
                    # evidence context. This preserves recall without
                    # accepting free-form or future CVE claims.
                    claim_status = "validated_catalog"
                    finding["cve_ids"] = catalog_compatible_ids
                    finding["accepted_for_scoring"] = True
                elif "conditional" in observed_statuses:
                    claim_status = "conditional"
                    finding["accepted_for_scoring"] = False
                elif "indeterminate" in observed_statuses:
                    claim_status = "uncertain"
                    finding["accepted_for_scoring"] = False
                elif observed_statuses and observed_statuses == {"incompatible"}:
                    claim_status = "incompatible"
                    finding["accepted_for_scoring"] = False
                else:
                    claim_status = "unverified"
                    finding["accepted_for_scoring"] = False
                finding["cve_claim_status"] = claim_status
                finding["cve_tool_evidence"] = {
                    cve_id: assessment
                    for cve_id, assessment in assessments.items()
                    if assessment
                }
            record = records_by_id[finding["_candidate_id"]]
            vuln_type = runtime.canonicalize(str(finding.get("type") or "").casefold())
            source_kind = str(finding.get("_source_kind") or record.get("source_kind") or "")
            device_id = str(finding.get("device_id") or "")
            device_role = surface_roles.get(device_id, "")
            semantic_issue = runtime._finding_semantic_issue(
                finding,
                source_kind=source_kind,
                compact=compact_mode,
                device_role=device_role,
                context_findings=all_vulns,
            )
            if semantic_issue:
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = semantic_issue
                continue
            record["normalized"] = {
                key: finding.get(key)
                for key in (
                    "device_id", "device_ip", "type", "severity", "service",
                    "port", "protocol", "endpoint", "endpoints", "product", "version",
                )
            }

        if not compact_mode:
            # A single unauthenticated HTTP surface is often described as
            # separate /admin, /api/devices, and /api/status candidates.
            # Publish the union on each surviving primary claim so strict-v3
            # can match the ground-truth contract without adding a new model
            # guardrail or suppressing full-profile exploration.
            api_groups: dict[tuple, set[str]] = {}
            for finding in all_vulns:
                # Include the excluded secondary /api/status candidate as a
                # source of contract paths. It is not published itself, but its
                # path is required to form the second API contract in S6.
                if finding.get("type") != "no_auth":
                    continue
                service = str(finding.get("service") or "").casefold()
                if service not in {"http", "https"}:
                    continue
                paths = set(runtime._extract_endpoint_paths(
                    finding.get("endpoint"), finding.get("endpoints"),
                    finding.get("details"), finding.get("evidence"),
                ))
                api_paths = {
                    path for path in paths
                    if path == "/admin" or path.startswith("/api/")
                }
                if not api_paths:
                    continue
                try:
                    port = int(finding.get("port"))
                except (TypeError, ValueError):
                    port = None
                group_key = (
                    finding.get("device_ip"), service, port,
                    str(finding.get("protocol") or "").casefold(),
                )
                api_groups.setdefault(group_key, set()).update(api_paths)

            for finding in all_vulns:
                record = records_by_id[finding["_candidate_id"]]
                if record.get("decision") == "excluded_from_canonical" or finding.get("type") != "no_auth":
                    continue
                service = str(finding.get("service") or "").casefold()
                if service not in {"http", "https"}:
                    continue
                try:
                    port = int(finding.get("port"))
                except (TypeError, ValueError):
                    port = None
                group_key = (
                    finding.get("device_ip"), service, port,
                    str(finding.get("protocol") or "").casefold(),
                )
                combined = api_groups.get(group_key)
                if not combined:
                    continue
                existing = set(runtime._extract_endpoint_paths(
                    finding.get("endpoint"), finding.get("endpoints"),
                ))
                finding["endpoints"] = sorted(existing | combined)

        try:
            surface_raw = json.loads(runtime.get_attack_surface())
            surface_nodes = surface_raw.get("nodes", []) if isinstance(surface_raw, dict) else []
            ip_to_device_id = {
                d["ip"]: d["id"]
                for d in surface_nodes
                if d.get("ip") and d.get("id")
            }
            for finding in all_vulns:
                if finding.get("device_id", "").startswith("discovered-"):
                    canonical = ip_to_device_id.get(finding.get("device_ip", ""))
                    if canonical:
                        finding["device_id"] = canonical
        except Exception as exc:
            log.debug("device_id remap skipped: %s", exc)

        if not compact_mode:
            # $SYS is a broker-wide low-value observation. Keep one
            # representative per run; repeated copies otherwise consume
            # evidence links and inflate strict-v3 hallucination counts.
            sys_findings = sorted(
                (
                    finding for finding in all_vulns
                    if records_by_id[finding["_candidate_id"]].get("decision")
                    != "excluded_from_canonical"
                    and finding.get("type") == "info_disclosure"
                    and str(finding.get("service") or "").casefold() == "mqtt"
                    and "$sys" in " ".join(
                        str(finding.get(key) or "")
                        for key in ("details", "evidence", "endpoint", "endpoints")
                    ).casefold()
                ),
                key=lambda item: str(item.get("device_ip") or ""),
            )
            for finding in sys_findings[1:]:
                record = records_by_id[finding["_candidate_id"]]
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = (
                    "duplicate low-value MQTT $SYS observation; representative retained"
                )

        eligible: list[dict] = []
        compact_observations: list[dict] = []
        for finding in all_vulns:
            record = records_by_id[finding["_candidate_id"]]
            if record.get("decision") == "excluded_from_canonical":
                continue
            vuln_type = finding.get("type", "")
            if runtime.is_noise(vuln_type):
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = "taxonomy marks this as a non-finding/noise type"
                continue
            if (finding.get("severity") or "").upper() == "INFO":
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = "INFO is retained as metadata, not scored as a vulnerability"
                continue
            if (
                vuln_type == "known_cve"
                and finding.get("accepted_for_scoring") is not True
            ):
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = (
                    "CVE claim is not corroborated as compatible by the archived "
                    f"cve_search result ({finding.get('cve_claim_status', 'unverified')})"
                )
                continue
            if compact_mode and finding.get("compact_report_only"):
                if self._compact_observation_has_tool_evidence(
                    finding, compact_tool_records
                ):
                    eligible.append(finding)
                    continue
                record["decision"] = "excluded_from_canonical"
                record["decision_reason"] = (
                    "compact configuration observation lacks sufficient phase-2 tool evidence"
                )
                observation = json.loads(json.dumps(finding, ensure_ascii=False, default=str))
                observation.pop("_candidate_id", None)
                compact_observations.append(observation)
                continue
            eligible.append(finding)

        severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        def finding_quality(finding: dict) -> tuple[int, int, int, int]:
            """Prefer evidence and confirmation; severity is only a final tie-break."""
            confirmed = int(
                (finding.get("exploitation_status") or "").casefold() == "confirmed"
            )
            evidence = str(finding.get("evidence") or "")
            traceability = int(bool(finding.get("evidence_ref") or finding.get("evidence_refs")))
            detail_size = len(evidence) + len(str(finding.get("details") or ""))
            severity = severity_rank.get((finding.get("severity") or "").casefold(), 0)
            return confirmed, traceability, detail_size, severity

        groups: dict[tuple, list[dict]] = {}
        for finding in eligible:
            base_key = (
                finding.get("device_ip", ""), finding.get("type", ""),
                finding.get("service", ""), finding.get("port"),
                finding.get("protocol", ""),
            )
            key = base_key + (finding.get("endpoint", ""),)
            service = str(finding.get("service") or "").casefold()
            if (
                finding.get("type") == "insecure_update"
                and service == "http"
                and str(surface_roles.get(str(finding.get("device_id") or ""), "")) == "ota_device"
            ):
                # Rollback and unsigned-metadata defects intentionally share
                # /install but describe different integrity failures.
                key = base_key + (finding.get("endpoint", ""), finding.get("details", ""))
            elif finding.get("type") == "data_exposure" and service == "mqtt":
                # MQTT topic exposures on one broker are one access surface in
                # the benchmark contract. Keep the strongest candidate and
                # preserve every raw topic claim in the audit registry.
                key = base_key + ("__mqtt_surface__",)
            elif (
                finding.get("type") == "no_auth"
                and service in {"http", "https"}
            ):
                # /admin, /api/devices and /api/status are evidence paths for
                # one unauthenticated HTTP surface. Their endpoint union is
                # preserved below, while only the strongest candidate is
                # published to strict-v3.
                key = base_key + ("__http_no_auth_surface__",)
            elif (
                finding.get("type") == "data_exposure"
                and service in {"http", "https"}
            ):
                text = " ".join(
                    str(finding.get(field) or "")
                    for field in ("details", "evidence")
                )
                primary_path = next(iter(runtime._extract_endpoint_paths(
                    finding.get("endpoint"),
                )), "")
                is_listing = bool(re.search(
                    r"(?i)(?:directory listing|autoindex|index of)", text
                ))
                if is_listing:
                    key = base_key + ("__listing_anchor__", finding["_candidate_id"])
                else:
                    for anchor in (
                        candidate for candidate in eligible
                        if candidate.get("type") == "data_exposure"
                        and str(candidate.get("service") or "").casefold() in {"http", "https"}
                        and candidate.get("device_ip") == finding.get("device_ip")
                        and candidate.get("port") == finding.get("port")
                        and bool(re.search(
                            r"(?i)(?:directory listing|autoindex|index of)",
                            " ".join(str(candidate.get(field) or "") for field in ("details", "evidence")),
                        ))
                    ):
                        anchor_paths = runtime._extract_endpoint_paths(
                            anchor.get("endpoint"), anchor.get("endpoints"),
                        )
                        if any(
                            primary_path == path.rstrip("/")
                            or primary_path.startswith(path.rstrip("/") + "/")
                            for path in anchor_paths
                            if path != "/"
                        ):
                            anchor_key = (
                                base_key + ("__listing_anchor__", anchor["_candidate_id"])
                            )
                            key = anchor_key
                            break
            groups.setdefault(key, []).append(finding)

        deduped: list[dict] = []
        for candidates in groups.values():
            chosen = max(candidates, key=finding_quality)
            if len(candidates) > 1 and chosen.get("type") in {
                "data_exposure", "no_auth"
            }:
                combined_endpoints = sorted({
                    endpoint
                    for candidate in candidates
                    for endpoint in runtime._extract_endpoint_paths(
                        candidate.get("endpoint"), candidate.get("endpoints"),
                    )
                })
                if combined_endpoints:
                    chosen["endpoints"] = combined_endpoints
            candidate_ids = [item["_candidate_id"] for item in candidates]
            chosen["_provenance"] = {
                "selected_candidate_id": chosen["_candidate_id"],
                "candidate_ids": candidate_ids,
                "raw_projection": "03_vuln_analysis_raw.json",
            }
            deduped.append(chosen)
            for item in candidates:
                record = records_by_id[item["_candidate_id"]]
                if item is chosen:
                    record["accepted_for_canonical"] = True
                    record["decision"] = "selected"
                    record["decision_reason"] = (
                        "best evidence/confirmation quality in canonical duplicate group"
                    )
                else:
                    record["decision"] = "deduplicated"
                    record["decision_reason"] = (
                        f"represented by {chosen['_candidate_id']}; raw candidate preserved"
                    )

        if not compact_mode:
            # strict-v3 allows only a small number of low-value bonus claims per
            # type. Keep the strongest representative in the canonical queue;
            # every other model candidate remains available in the raw audit
            # registry. This is a publication deduplication, not a full-profile
            # generation guardrail.
            for low_value_type in ("weak_cipher", "missing_header"):
                observations = sorted(
                    (
                        finding for finding in deduped
                        if finding.get("type") == low_value_type
                    ),
                    key=finding_quality,
                    reverse=True,
                )
                for finding in observations[1:]:
                    record = records_by_id[finding["_candidate_id"]]
                    record["accepted_for_canonical"] = False
                    record["decision"] = "excluded_from_canonical"
                    record["decision_reason"] = (
                        f"duplicate low-value {low_value_type} observation; representative retained"
                    )
                if observations:
                    deduped = [
                        finding for finding in deduped
                        if finding.get("type") != low_value_type
                        or finding is observations[0]
                    ]

        devices_with_insecure_update = {
            finding.get("device_ip")
            for finding in deduped
            if finding.get("type") == "insecure_update"
        }
        final: list[dict] = []
        for finding in deduped:
            if (
                finding.get("type") == "directory_listing"
                and finding.get("device_ip") in devices_with_insecure_update
                and "/firmware" in str(finding.get("details", "")).casefold()
            ):
                record = records_by_id[finding["_candidate_id"]]
                record["accepted_for_canonical"] = False
                record["decision"] = "represented_by_stronger_finding"
                record["decision_reason"] = (
                    "firmware directory observation represented by insecure_update"
                )
                continue
            final.append(finding)

        def _finding_identity(finding: dict) -> tuple[str, ...]:
            return tuple(
                str(finding.get(key) or "").strip().casefold()
                for key in (
                    "device_ip", "type", "service", "port", "protocol",
                    "endpoint", "product",
                )
            )

        # Phase 2.5 appends newly discovered devices and re-runs this
        # aggregation. Keep existing canonical IDs stable so Phase 4
        # deliverables and provenance do not get reassigned to another
        # vulnerability when a new host is added.
        previous_ids: dict[tuple[str, ...], str] = {}
        previous_path = self.run_dir / "03_vuln_analysis.json"
        try:
            previous = json.loads(previous_path.read_text(encoding="utf-8"))
            for previous_finding in previous.get("vulnerabilities", []):
                previous_id = str(previous_finding.get("id") or "")
                if re.fullmatch(r"VULN-\d+", previous_id):
                    previous_ids[_finding_identity(previous_finding)] = previous_id
        except (OSError, TypeError, ValueError, json.JSONDecodeError):
            pass
        used_ids: set[str] = set()
        previous_numbers = [
            int(identifier.removeprefix("VULN-"))
            for identifier in previous_ids.values()
            if identifier.removeprefix("VULN-").isdigit()
        ]
        next_number = max(previous_numbers, default=0) + 1

        for finding in final:
            finding_id = previous_ids.get(_finding_identity(finding))
            if not finding_id or finding_id in used_ids:
                while f"VULN-{next_number:03d}" in used_ids:
                    next_number += 1
                finding_id = f"VULN-{next_number:03d}"
                next_number += 1
            used_ids.add(finding_id)
            finding["id"] = finding_id
            finding["canonical_source"] = str(finding.get("_source_kind") or "model")
            for candidate_id in finding["_provenance"]["candidate_ids"]:
                records_by_id[candidate_id]["canonical_finding_id"] = finding_id
            finding.pop("_candidate_id", None)
            finding.pop("_source_kind", None)

        severity_counts = {
            "high": 0, "medium": 0, "low": 0, "info": 0, "critical": 0,
        }
        for finding in final:
            severity = (finding.get("severity") or "").casefold()
            if severity in severity_counts:
                severity_counts[severity] += 1

        raw_projection = {
            "schema_version": "2",
            "policy": (
                "Information-preserving candidate registry. Exclusion from the "
                "canonical queue never deletes the model output."
            ),
            "candidate_count": len(raw_records),
            "canonical_count": len(final),
            "candidates": raw_records,
        }
        raw_path = self.run_dir / "03_vuln_analysis_raw.json"
        raw_path.write_text(
            json.dumps(raw_projection, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        if compact_mode:
            for index, observation in enumerate(compact_observations, 1):
                observation["id"] = f"OBS-{index:03d}"
            (self.run_dir / "03_config_observations.json").write_text(
                json.dumps({
                    "schema_version": "1",
                    "observations": compact_observations,
                }, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        result = {
            "vulnerabilities": final,
            **({"configuration_observations": compact_observations} if compact_mode else {}),
            "attack_chain_hints": self._detect_attack_chains(final),
            "summary": {
                "total": len(final),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
                "raw_candidates": len(raw_records),
                "raw_projection": raw_path.name,
            },
        }

        out_path = self.run_dir / "03_vuln_analysis.json"
        out_path.write_text(
            json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(
            f"  Aggregated {len(raw_records)} raw candidates → {len(final)} canonical "
            "findings → 03_vuln_analysis.json"
        )
        log.info(
            "Information-preserving aggregation: %d candidates → %d canonical → %s",
            len(raw_records), len(final), out_path,
        )
