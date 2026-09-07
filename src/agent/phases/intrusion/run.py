"""Intrusion phase: common execution and evidence handling."""
from __future__ import annotations
import json
import logging
import re
from urllib.parse import urlsplit
from src.agent.phases.intrusion.compact import COMPACT_INTRUSION_FALLBACK_MAX_ROUNDS
from src.agent.phases.intrusion.scope import _intrusion_scope_violation
from src.agent.phases.intrusion.evidence import finalize_synthesis
from src.agent.core import runtime


log = logging.getLogger(__name__)


class IntrusionPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _ensure_intrusion_deliverable(self, config, results: dict, stream_callback=None) -> None:
        """Reconcile compact Phase 5 from tool evidence without hiding gaps.

        Full profiles keep the model-produced deliverable untouched.  Compact
        local-MoE runs use the tool ledger as the source of truth; a bounded
        fallback may complete missing actions, but incomplete coverage is
        reported as incomplete rather than promoted as a successful phase.
        """
        from src.agent.phases.intrusion import compact as compact_intrusion

        def finish(status: str, *, notify: bool = True) -> None:
            results[config.name] = status
            if stream_callback and notify:
                stream_callback({
                    "type": "phase_done", "phase": config.phase,
                    "name": config.name, "status": status,
                    "deliverable": config.deliverable_file,
                    "cost_usd": 0, "turns": 0,
                })

        path = self.run_dir / config.deliverable_file
        validator_fn = runtime.VALIDATORS.get(config.validator, runtime.VALIDATORS["default"])
        valid = False
        if path.exists():
            valid, _ = validator_fn(config.deliverable_file)
        compact = self._uses_compact_local_moe()
        terminal_completed = compact and self._compact_intrusion_completion_succeeded()
        if terminal_completed:
            already_reported = results.get(config.name) == "completed"
            self._run_compact_intrusion_post_access(config, stream_callback)
            if self._write_compact_intrusion_deliverable(
                note=(
                    "Committed by complete_intrusion_campaign from the "
                    "authoritative Phase 5 tool ledger."
                )
            ):
                finish("completed", notify=not already_reported)
                return
        if valid and not compact:
            return

        coverage_ok, coverage = (True, {})
        if compact:
            committed, coverage_ok, coverage = compact_intrusion.recover_completion(
                coverage=self._compact_intrusion_coverage,
                recover=lambda: self._run_compact_intrusion_fallback(config, stream_callback),
                post_access=lambda: self._run_compact_intrusion_post_access(config, stream_callback),
                complete=lambda: self._invoke_compact_intrusion_completion(
                    getattr(self, "_compact_intrusion_runtime_tools", None),
                    stream_callback,
                ),
                commit=self._write_compact_intrusion_deliverable,
                max_rounds=COMPACT_INTRUSION_FALLBACK_MAX_ROUNDS,
            )
            if committed:
                finish("completed")
                return

        data = self._synthesize_intrusion_from_tools(
            note=(
                "Reconciled from tool_calls.jsonl — compact local-MoE output is memo-only."
                if compact else None
            )
        )
        if compact:
            status = compact_intrusion.finalize_incomplete(
                data, coverage_ok=coverage_ok, coverage=coverage,
            )
        else:
            status = finalize_synthesis(data, results.get(config.name, "completed"))

        reason = data.get("blocked_reason")
        if reason:
            log.warning(reason)
        else:
            print(
                f"  Synthesized intrusion deliverable from tool calls "
                f"({data['summary']['devices_compromised']} compromised, "
                f"{data['summary']['credentials_harvested']} creds)"
            )
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        finish(status)

    def _synthesize_intrusion_from_tools(self, note: str | None = None) -> dict:
        """Reconstruct an intrusion deliverable from logged try_credential /
        ssh_exec calls (both are Phase-5-only tools)."""
        log_path = self.run_dir / "tool_calls.jsonl"
        compact_synthesis = self._uses_compact_local_moe()
        compromised: dict = {}
        creds: list = []
        allowed_credentials: set[tuple[str, str]] = set()
        seen_cred: set = set()
        attempted: set = set()  # all IPs touched by Phase 5 action tools
        action_evidence: dict[str, list[dict]] = {}

        def _host_from_url(value: object) -> str:
            raw = str(value or "").strip()
            if not raw:
                return ""
            parsed = urlsplit(raw)
            if parsed.hostname:
                return parsed.hostname
            return raw.split("/", 1)[0].split(":", 1)[0].strip()

        def _target_from_tool(tool: str, args: dict) -> str:
            for key in ("ip", "host", "broker", "target"):
                value = str(args.get(key) or "").strip()
                if value:
                    return value
            if tool in {"http_get", "curl_headers", "ftp_list"}:
                return _host_from_url(args.get("url"))
            if tool in {"telnet_connect", "ssh_login"}:
                match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", str(args.get("command_string") or ""))
                return match.group(0) if match else ""
            return ""

        def _credential_from_tool(tool: str, args: dict) -> tuple[str, str]:
            user = str(args.get("user") or "").strip()
            password = str(args.get("password") or "").strip()
            if tool == "ssh_login":
                command_string = str(args.get("command_string") or "")
                password_match = re.search(
                    r"sshpass\s+-p\s+(?:'([^']*)'|\"([^\"]*)\"|([^\s]+))",
                    command_string,
                )
                user_match = re.search(
                    r"\b([A-Za-z0-9_.-]+)@(?:\d{1,3}\.){3}\d{1,3}\b",
                    command_string,
                )
                password = password or next(
                    (group for group in (password_match.groups() if password_match else ()) if group),
                    "",
                )
                user = user or (user_match.group(1) if user_match else "")
            return user, password

        def extract_observed_credentials(text: str) -> list[tuple[str, str]]:
            """Extract only explicit user/password pairs returned by ssh_exec."""
            if not text:
                return []
            pairs: list[tuple[str, str]] = []
            structured = re.compile(
                r'(?:user(?:name)?|login|db_user)\s*[\"\']?\s*[=:]\s*[\"\']?'
                r'([A-Za-z0-9_@.\-]+)[\"\']?\s*[,;:\"\'(){}\s]+'
                r'(?:pass(?:word)?|pwd|db_pass)\s*[\"\']?\s*[=:]\s*[\"\']?'
                r'([^\s,;\"\'(){}\]]+)',
                re.IGNORECASE,
            )
            simple = re.compile(
                r'\b([A-Za-z][A-Za-z0-9_\-]{1,31}):'
                r'([A-Za-z0-9@!#$%^&*_\-+=.]{3,64})\b'
            )
            noise = {
                "http", "https", "ssh", "tcp", "udp", "version", "port",
                "uid", "gid", "groups", "host", "server", "root",
            }
            for match in structured.finditer(text):
                user, password = match.group(1).strip(), match.group(2).strip()
                if user and password:
                    pairs.append((user.split("@", 1)[0], password))
            for match in simple.finditer(text):
                user, password = match.group(1).strip(), match.group(2).strip()
                if user.casefold() not in noise and not password.isdigit():
                    pairs.append((user, password))
            return list(dict.fromkeys(pairs))

        # Map IP -> device_id from the pre-generated intrusion context so the
        # synthesized deliverable carries real device names, not blanks.
        ip_to_id: dict = {}
        entry_point_ips: set[str] = set()
        entry_evidence: dict[str, str] = {}
        context_data: dict = {}
        ctx_path = self.run_dir / "05_intrusion_context.json"
        if compact_synthesis and not ctx_path.exists():
            context_from_ledger = self._load_compact_intrusion_context()
            if isinstance(context_from_ledger, dict):
                try:
                    ctx_path.write_text(json.dumps(context_from_ledger, ensure_ascii=False), encoding="utf-8")
                except OSError:
                    pass
        if ctx_path.exists():
            try:
                ctx = json.loads(ctx_path.read_text(encoding="utf-8"))
                context_data = ctx if isinstance(ctx, dict) else {}
                for entry in ctx.get("entry_points", []):
                    if isinstance(entry, dict) and entry.get("device_ip"):
                        ip = str(entry["device_ip"])
                        entry_point_ips.add(ip)
                        entry_evidence[ip] = str(entry.get("evidence") or "").strip()
                for entry in (ctx.get("entry_points", []) + ctx.get("all_targets", [])):
                    did, dip = entry.get("device_id"), entry.get("device_ip")
                    if dip and did and dip not in ip_to_id:
                        ip_to_id[dip] = did
                for cred in ctx.get("recovered_credentials", []):
                    if not isinstance(cred, dict):
                        continue
                    user = str(cred.get("user", ""))
                    pwd = str(cred.get("password", ""))
                    svc = str(cred.get("service", ""))
                    source_ip = str(cred.get("source_ip", ""))
                    ckey = (source_ip, user, pwd, svc)
                    if user and pwd:
                        allowed_credentials.add((user, pwd))
                    if user and ckey not in seen_cred:
                        seen_cred.add(ckey)
                        creds.append({
                            "user": user,
                            "password": pwd,
                            "service": svc,
                            "source_ip": source_ip,
                            "source_device": cred.get("source_device", ""),
                        })
            except Exception:
                pass

        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                record_phase = rec.get("phase")
                if record_phase not in (None, 5, "5"):
                    continue
                if record_phase is None and rec.get("vuln_id"):
                    continue
                tool = rec.get("tool")
                args = rec.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                res: dict = {}
                raw = rec.get("result")
                if isinstance(raw, str):
                    try:
                        res = json.loads(raw)
                    except Exception:
                        res = {}
                elif isinstance(raw, dict):
                    res = raw
                if compact_synthesis and _intrusion_scope_violation(
                    str(tool or ""), args, self.context.get("target_subnet", "")
                ) is not None:
                    continue
                ip = _target_from_tool(str(tool or ""), args)
                if tool in {"try_credential", "ssh_exec", "ssh_login", "mqtt_listen", "http_get", "curl_headers", "telnet_connect", "ftp_list"} and ip:
                    attempted.add(ip)
                    action_evidence.setdefault(ip, []).append({
                        "tool": str(tool or ""),
                        "args": args,
                        "result": res,
                    })
                stdout = str(res.get("stdout") or res.get("output") or "") if isinstance(res, dict) else ""
                authenticated = (
                    isinstance(res, dict)
                    and res.get("authenticated", True) is not False
                    and (
                        res.get("success") is True
                        or (tool == "ssh_login" and (res.get("return_code") == 0 or re.search(r"\buid=\d+", stdout.casefold())))
                    )
                )
                if tool in {"try_credential", "ssh_exec", "ssh_login"}:
                    supplied_credential = _credential_from_tool(str(tool), args)
                    if supplied_credential not in allowed_credentials:
                        authenticated = False
                if not (authenticated and ip):
                    continue

                if tool == "try_credential":
                    user = args.get("user", "")
                    pwd = args.get("password", "")
                    svc = args.get("service") or res.get("service", "")
                    comp = compromised.setdefault(ip, {
                        "device_id": ip_to_id.get(ip, ""), "device_ip": ip,
                        "access_method": f"try_credential:{svc}:{user}:{pwd}",
                        "access_via": "entry_point" if ip in entry_point_ips else "lateral_movement",
                        "data_exfiltrated": "", "credentials_found": [],
                    })
                elif tool in {"ssh_exec", "ssh_login"}:
                    comp = compromised.setdefault(ip, {
                        "device_id": ip_to_id.get(ip, ""), "device_ip": ip,
                        "access_method": tool,
                        "access_via": "entry_point" if ip in entry_point_ips else "lateral_movement",
                        "data_exfiltrated": "", "credentials_found": [],
                    })
                    out = (res.get("stdout") or "").strip()
                    if out and not comp["data_exfiltrated"]:
                        comp["data_exfiltrated"] = out[:500]
                    for user, password in (
                        extract_observed_credentials(out)
                        if compact_synthesis else ()
                    ):
                        credential = {
                            "user": user,
                            "password": password,
                            "service": "ssh",
                            "target_ip": ip,
                        }
                        if credential not in comp["credentials_found"]:
                            comp["credentials_found"].append(credential)
                        ckey = (ip, user, password, "ssh")
                        if ckey not in seen_cred:
                            seen_cred.add(ckey)
                            creds.append({
                                "user": user,
                                "password": password,
                                "service": "ssh",
                                "source_ip": ip,
                                "source_device": ip_to_id.get(ip, ""),
                            })
                            allowed_credentials.add((user, password))

        def action_is_positive(record: dict) -> bool:
            tool = str(record.get("tool") or "")
            result = record.get("result") or {}
            if not isinstance(result, dict):
                return False
            if tool == "try_credential":
                return result.get("success") is True and result.get("authenticated", True) is not False
            if tool in {"ssh_login", "ssh_exec"}:
                stdout = str(result.get("stdout") or result.get("output") or "")
                return (
                    result.get("success") is True
                    or result.get("return_code") == 0
                    or bool(re.search(r"\buid=\d+", stdout))
                )
            if tool == "mqtt_listen":
                return (
                    result.get("return_code") in {0, 27}
                    and bool(str(result.get("stdout") or "").strip())
                )
            if tool in {"http_get", "curl_headers"}:
                return (
                    result.get("return_code") == 0
                    or isinstance(result.get("status_code"), int)
                    and 200 <= result["status_code"] < 400
                )
            if tool in {"telnet_connect", "ftp_list"}:
                return result.get("return_code") == 0
            return False

        def action_details(ip: str) -> tuple[str, list[str], str]:
            records = action_evidence.get(ip, [])
            if not records:
                return "context_entry", [], ""
            positive = next(
                (record for record in records if action_is_positive(record)),
                None,
            )
            if positive is None and entry_evidence.get(ip):
                return (
                    "confirmed_context_entry",
                    ["05_intrusion_context.json entry evidence"],
                    entry_evidence[ip][:400],
                )
            selected = positive or records[-1]
            tool = str(selected.get("tool") or "context_entry")
            args = selected.get("args") or {}
            if not isinstance(args, dict):
                args = {}
            command = str(args.get("command_string") or args.get("command") or "").strip()
            if not command:
                command = f"{tool} entry probe"
            result = selected.get("result") or {}
            if isinstance(result, dict):
                output = str(
                    result.get("stdout")
                    or result.get("body")
                    or result.get("received_ascii")
                    or result.get("interpretation")
                    or result.get("stderr")
                    or ""
                ).strip()
            else:
                output = str(result).strip()
            return tool, [command[:300]], output[:400]

        def build_hop(ip: str, index: int, pivot_to: str | None) -> dict:
            method, commands, output = action_details(ip)
            device_id = ip_to_id.get(ip, ip)
            if ip in compromised:
                method = str(compromised[ip].get("access_method") or method)
                if compromised[ip].get("data_exfiltrated"):
                    output = str(compromised[ip]["data_exfiltrated"])[:400]
            return {
                "hop_index": index,
                "device_id": device_id,
                "device_ip": ip,
                "access_method": method,
                "commands_run": commands,
                "output_summary": output,
                "pivot_to": pivot_to,
            }

        devices = list(compromised.values())
        # The context contains the bounded attack-chain hypotheses produced
        # from confirmed Phase 3/4 evidence. Promote only chains whose source
        # and destination both participated in this Phase 5 action ledger;
        # never invent a path from an isolated attempted login.
        chains: list[dict] = []
        for index, hint in enumerate(context_data.get("attack_chains", []), start=1):
            if not isinstance(hint, dict):
                continue
            source_ip = str(hint.get("src_ip") or "").strip()
            target_ip = str(hint.get("dst_ip") or "").strip()
            if not source_ip or not target_ip:
                continue
            if not action_evidence.get(source_ip) or not action_evidence.get(target_ip):
                continue
            if source_ip not in entry_point_ips and source_ip not in compromised:
                continue
            if target_ip not in entry_point_ips and target_ip not in compromised:
                continue
            chains.append({
                "id": f"chain_{index}",
                "hops": [
                    build_hop(source_ip, 1, target_ip),
                    build_hop(target_ip, 2, None),
                ],
                "crown_jewel_reached": None,
                "source": "05_intrusion_context.attack_chains + Phase 5 tool ledger",
            })

        return {
            "summary": {
                "devices_compromised": len(devices),
                "devices_attempted": len(attempted | set(compromised)),
                "credentials_harvested": len(creds),
                "crown_jewels_reached": [],
                "total_hops": sum(
                    max(0, len(chain.get("hops", [])) - 1)
                    for chain in chains
                ),
                "_note": note or "Synthesized from tool_calls.jsonl — model emitted no deliverable.",
            },
            "credential_pool": creds,
            "compromised_devices": devices,
            "chains": chains,
        }

    def _generate_intrusion_context(self) -> None:
        """Pre-generate 05_intrusion_context.json for the intrusion agent.

        Extracts confirmed exploits, recovered credentials, attack chains,
        and entry points from Phases 3 and 4.
        """
        import re as _re

        vuln_path = self.run_dir / "03_vuln_analysis.json"
        exploit_path = self.run_dir / "04_exploitation.json"
        full_profile = not self.execution_profile.routed_tools

        chains: list = []
        phase3_candidates: list[dict] = []
        confirmed: list = []
        entry_points: list = []
        credentials: list = []

        if vuln_path.exists():
            if full_profile:
                try:
                    vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
                except (OSError, TypeError, ValueError, json.JSONDecodeError):
                    vuln_data = {}
                if isinstance(vuln_data, dict):
                    chains = vuln_data.get("attack_chain_hints", [])
                    phase3_candidates = [
                        item for item in vuln_data.get("vulnerabilities", [])
                        if isinstance(item, dict)
                    ]
            else:
                # Preserve the compact context source and parsing behavior.
                vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
                chains = vuln_data.get("attack_chain_hints", [])

        if exploit_path.exists():
            exploit_data = json.loads(exploit_path.read_text(encoding="utf-8"))
            if isinstance(exploit_data, list):
                all_exploits = exploit_data
            elif isinstance(exploit_data, dict):
                all_exploits = exploit_data.get("tests", [])
            else:
                all_exploits = []
            confirmed = [e for e in all_exploits if e.get("status") == "CONFIRMED"]

            # Extract credentials from evidence / description / data_extracted.
            # Tolerant of quotes and JSON punctuation so it matches all of:
            #   user=root pass=x  |  username='test', password='test'
            #   "db_user":"root","db_pass":"<observed-password>"
            _cred_pattern = _re.compile(
                r'(?:user(?:name)?|login|db_user)\s*["\']?\s*[=:]\s*["\']?'
                r'([a-zA-Z0-9_@.\-]+)["\']?[\s,;:"\'(){}]+'
                r'(?:pass(?:word)?|pwd|db_pass)\s*["\']?\s*[=:]\s*["\']?'
                r'([^\s,;"\'(){}\]]+)',
                _re.IGNORECASE,
            )
            # Inline "user:pass" pairs (e.g. admin:admin, test:test). Slash-style
            # pairs are deliberately excluded — they match file paths
            # (etc/issue, cgi-bin/luci); slash passwords are caught by the
            # quoted/JSON form above instead.
            _simple_pattern = _re.compile(
                r'\b([a-zA-Z][a-zA-Z0-9_\-]{1,31}):'
                r'([a-zA-Z0-9@!#$%^&*_\-+=.]{3,32})\b'
            )
            _cred_noise = {"http", "https", "ssh", "tcp", "udp", "version", "port",
                           "uid", "gid", "groups", "host", "tor", "mosquitto", "server"}
            seen_creds: set = set()

            tool_records_by_ref: dict[str, list[dict]] = {}
            if self._uses_compact_local_moe():
                tool_log_path = self.run_dir / "tool_calls.jsonl"
                if tool_log_path.exists():
                    for line in tool_log_path.read_text(encoding="utf-8").splitlines():
                        try:
                            record = json.loads(line)
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                        ref = str(record.get("evidence_ref") or "").strip()
                        if ref:
                            tool_records_by_ref.setdefault(ref, []).append(record)

            def _add_cred(user: str, pwd: str, exp: dict) -> None:
                user = user.split("@")[0].strip()  # user@host → user
                key = (user, pwd, exp.get("device_ip", ""))
                if not user or not pwd or key in seen_creds:
                    return
                seen_creds.add(key)
                credentials.append({
                    "user": user, "password": pwd,
                    "source_ip": exp.get("device_ip", ""),
                    "source_device": exp.get("device_id", ""),
                })

            def _harvest(text: str, exp: dict) -> None:
                if not text:
                    return
                for m in _cred_pattern.finditer(text):
                    _add_cred(m.group(1), m.group(2), exp)
                for m in _simple_pattern.finditer(text):
                    user, pwd = m.group(1), m.group(2)
                    if user.lower() in _cred_noise or pwd.isdigit():
                        continue
                    _add_cred(user, pwd, exp)

            def _harvest_confirmed_tool_credentials(exp: dict) -> None:
                if not tool_records_by_ref:
                    return
                refs = exp.get("evidence_refs", [])
                refs = [refs] if isinstance(refs, str) else (refs or [])
                for ref in refs:
                    for record in tool_records_by_ref.get(str(ref), []):
                        tool = str(record.get("tool") or "")
                        args = record.get("args") or {}
                        if not isinstance(args, dict):
                            continue
                        raw_result = record.get("result")
                        try:
                            result = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
                        except (TypeError, ValueError, json.JSONDecodeError):
                            continue
                        if not isinstance(result, dict):
                            continue
                        stdout = str(result.get("stdout") or result.get("output") or "")
                        success = (
                            result.get("success") is True
                            and result.get("authenticated", True) is not False
                        ) or (
                            result.get("return_code") == 0
                        ) or (
                            tool == "ssh_login"
                            and bool(_re.search(r"\buid=\d+", stdout))
                        )
                        if not success:
                            continue
                        if tool == "try_credential":
                            _add_cred(
                                str(args.get("user") or ""),
                                str(args.get("password") or ""),
                                exp,
                            )
                            continue
                        if tool != "ssh_login":
                            continue
                        command = str(args.get("command_string") or "")
                        match = _re.search(
                            r"sshpass\s+-p\s+(?:'([^']*)'|\"([^\"]*)\"|([^\s]+)).*?\b([A-Za-z0-9_.-]+)@(?:\d{1,3}\.){3}\d{1,3}\b",
                            command,
                        )
                        if match:
                            password = next((group for group in match.groups()[:3] if group), "")
                            _add_cred(match.group(4), password, exp)

            for exp in confirmed:
                texts = [exp.get("evidence", "")]
                # Descriptions may contain examples or hints, not recovered secrets.
                if not self._uses_compact_local_moe():
                    texts.append(exp.get("description", ""))
                de = exp.get("data_extracted")
                if isinstance(de, list):
                    texts.extend(str(x) for x in de)
                elif isinstance(de, str):
                    texts.append(de)
                for text in texts:
                    _harvest(text or "", exp)
                _harvest_confirmed_tool_credentials(exp)

            if full_profile:
                # Full-profile Phase 5 consumes only verified, access-granting
                # evidence. Informational and crypto findings remain report
                # data, not footholds.
                _foothold_types = {
                    "default_credentials", "no_auth", "weak_credentials",
                    "insecure_protocol", "directory_listing", "data_exposure",
                    "broken_access_control", "code_injection", "insecure_update",
                    "privilege_escalation",
                }
                best_by_ip: dict = {}
                entry_sources: dict[str, tuple[str, bool]] = {}
                for exp in confirmed:
                    ip = str(exp.get("device_ip") or "").strip()
                    if not ip or not runtime._is_verified_report_finding(exp):
                        continue
                    vt = str(exp.get("type") or exp.get("vuln_type") or "").casefold()
                    if vt not in _foothold_types:
                        continue
                    score = (2, runtime._phase4_evidence_level(exp))
                    if ip not in best_by_ip or score > best_by_ip[ip][0]:
                        best_by_ip[ip] = (score, exp)
                        entry_sources[ip] = ("phase4", True)

                # scanner_full is deterministic simulator evidence and may seed
                # a Phase 5 probe when Phase 4 could not reproduce the fixture.
                # Model-only Phase 3 claims never become footholds.
                for exp in phase3_candidates:
                    ip = str(exp.get("device_ip") or "").strip()
                    source = str(exp.get("canonical_source") or "").casefold()
                    status = str(exp.get("exploitation_status") or exp.get("status") or "").casefold()
                    vt = str(exp.get("type") or exp.get("vuln_type") or "").casefold()
                    if (
                        not ip or ip in best_by_ip or source != "scanner_full"
                        or status not in {"confirmed", "exploited", "compromised"}
                        or vt not in _foothold_types
                    ):
                        continue
                    best_by_ip[ip] = ((1, runtime._phase4_evidence_level(exp)), exp)
                    entry_sources[ip] = ("phase3_scanner_contract", False)
            else:
                # Keep compact-profile context generation unchanged.
                _foothold_types = {
                    "default_credentials", "no_auth", "weak_credentials",
                    "insecure_protocol", "directory_listing", "data_exposure",
                }
                best_by_ip: dict = {}
                for exp in confirmed:
                    ip = exp.get("device_ip")
                    if not ip:
                        continue
                    vt = (exp.get("type") or exp.get("vuln_type") or "").lower()
                    if vt not in _foothold_types:
                        continue
                    score = (2, exp.get("evidence_level", 0))
                    if ip not in best_by_ip or score > best_by_ip[ip][0]:
                        best_by_ip[ip] = (score, exp)
            for ip, (_score, exp) in best_by_ip.items():
                entry = {
                    "device_id": exp.get("device_id"),
                    "device_ip": ip,
                    "vuln_type": exp.get("type") or exp.get("vuln_type"),
                    "service": exp.get("service"),
                    "port": exp.get("port"),
                    "evidence": (exp.get("evidence") or "")[:200],
                }
                if full_profile:
                    source, phase4_verified = entry_sources.get(ip, ("phase4", True))
                    entry.update({
                        "vuln_id": exp.get("vuln_id") or exp.get("id"),
                        "protocol": exp.get("protocol"),
                        "endpoint": exp.get("endpoint"),
                        "evidence": (exp.get("evidence") or "")[:400],
                        "evidence_source": source,
                        "phase4_verified": phase4_verified,
                    })
                entry_points.append(entry)

        # Deduplicate entry points by device_ip
        seen_ep: set = set()
        unique_entries = []
        for ep in entry_points:
            if ep["device_ip"] not in seen_ep:
                seen_ep.add(ep["device_ip"])
                unique_entries.append(ep)

        # All devices in the network — full target list for credential spraying.
        # get_attack_surface() returns a bare JSON list in scenario mode and a
        # dict with a "nodes" key otherwise — normalise both shapes.
        role_primary_services = {
            "router": "ssh", "gateway": "ssh", "ssh_server": "ssh",
            "mqtt_broker": "mqtt", "web_server": "http",
            "nodered_server": "http", "camera": "http",
            "ftp_server": "ftp", "db_server": "mysql", "db_server_v2": "redis",
        }
        if full_profile:
            role_primary_services.update({
                "modbus_server": "modbus", "coap_server": "coap", "snmp_server": "snmp",
                "api_identity_server": "http", "api_tenant_server": "http",
                "api_data_store": "http", "api_event_broker": "http",
                "api_admin_portal": "http", "pki_ca_server": "http",
                "pki_enrollment_server": "http", "pki_mtls_server": "https",
                "pki_registry": "http", "pki_device": "http",
                "ota_repository": "http", "ota_server": "http",
                "ota_device": "http", "ota_signer": "http", "ota_monitor": "http",
                "cloud_web_server": "http", "cloud_metadata_server": "http",
                "cloud_control_plane": "http", "cloud_worker": "http", "cloud_audit": "http",
                "ot_hmi": "http", "ot_historian": "http",
                "ot_opcua_server": "opcua", "ot_bacnet_server": "bacnet",
            })
        entry_primary_services = {
            str(item.get("device_ip") or item.get("ip") or "").strip():
            str(item.get("service") or "").strip().casefold()
            for item in unique_entries
            if isinstance(item, dict) and item.get("service")
        }
        all_targets: list = []
        try:
            surface = json.loads(runtime.get_attack_surface())
            nodes = surface if isinstance(surface, list) else surface.get("nodes", [])
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                ip = node.get("ip")
                if ip:
                    if full_profile:
                        raw_services = node.get("services", [])
                        service_details = [
                            {
                                "name": str(item.get("name") or item.get("service") or "").casefold(),
                                "port": item.get("port"),
                                "protocol": item.get("protocol") or "",
                            }
                            for item in raw_services
                            if isinstance(item, dict) and item.get("port")
                        ]
                        role = str(node.get("role") or "").strip().casefold()
                        primary_service = (
                            role_primary_services.get(role)
                            or entry_primary_services.get(str(ip).strip())
                            or next((item["name"] for item in service_details if item["name"]), None)
                        )
                        all_targets.append({
                            "device_id": node.get("id") or node.get("name"),
                            "device_ip": ip,
                            "role": node.get("role"),
                            "primary_service": primary_service,
                            "services": [item["port"] for item in service_details],
                            "service_details": service_details,
                        })
                    else:
                        all_targets.append({
                            "device_id": node.get("id") or node.get("name"),
                            "device_ip": ip,
                            "role": node.get("role"),
                            "primary_service": role_primary_services.get(str(node.get("role") or "").strip().casefold()) or entry_primary_services.get(str(ip).strip()),
                            "services": [
                                (s.get("port") if isinstance(s, dict) else s)
                                for s in node.get("services", [])
                                if (s.get("port") if isinstance(s, dict) else s)
                            ],
                        })
        except Exception:
            pass

        # Fallback: derive targets from confirmed exploits if the graph gave nothing.
        if not all_targets:
            seen_t: set = set()
            for exp in confirmed:
                ip = exp.get("device_ip")
                if ip and ip not in seen_t:
                    seen_t.add(ip)
                    all_targets.append({
                        "device_id": exp.get("device_id"),
                        "device_ip": ip,
                        "role": None,
                        "primary_service": str(exp.get("service") or "").strip().casefold() or None,
                        "services": [exp.get("port")] if exp.get("port") else [],
                    })

        ctx = {
            "generated_for": "phase5_intrusion",
            "attack_chains": chains,
            "entry_points": unique_entries,
            "all_targets": all_targets,
            "confirmed_exploits": len(confirmed),
            "recovered_credentials": credentials[:30],
            "NOTE": (
                "STRATEGY: (1) Use entry_points as starting devices. "
                "(2) After gaining access, harvest all credentials from the host. "
                "(3) Spray ALL harvested credentials against ALL devices in all_targets. "
                "(4) Repeat from each newly compromised device until no new hosts are reachable. "
                "Goal: maximize compromised devices and reach crown jewels (db, plc, historian, admin)."
            ),
        }

        if full_profile:
            ctx["verified_exploits"] = sum(
                1 for item in confirmed if runtime._is_verified_report_finding(item)
            )

        out_path = self.run_dir / "05_intrusion_context.json"
        out_path.write_text(json.dumps(ctx, indent=2, ensure_ascii=False), encoding="utf-8")
        print(
            f"  [intrusion] 05_intrusion_context.json "
            f"({len(unique_entries)} entry points, {len(all_targets)} targets, "
            f"{len(credentials)} creds, {len(chains)} chains, {out_path.stat().st_size:,} bytes)"
        )

    @staticmethod
    def _repair_json(text: str) -> str:
        """Best-effort repair for common LLM JSON issues (embedded unescaped quotes inside strings)."""
        import re
        # Replace control characters that break JSON
        text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', text)
        return text

    def _emit_intrusion_events(self, stream_callback) -> None:
        """Parse 05_intrusion.json and emit intrusion_hop / intrusion_done SSE events."""
        if not stream_callback:
            return
        intrusion_path = self.run_dir / "05_intrusion.json"
        if not intrusion_path.exists():
            return
        try:
            raw = intrusion_path.read_text(encoding="utf-8")
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                data = json.loads(self._repair_json(raw))
        except Exception as exc:
            log.warning("Failed to parse intrusion results for SSE: %s", exc)
            return

        try:
            chains = data.get("chains", [])
            summary = data.get("summary", {})
            compromised_devices = data.get("compromised_devices", [])

            # Emit one compromised event per device from the compromised_devices list
            for dev in compromised_devices:
                stream_callback({
                    "type": "intrusion_compromised",
                    "device_id": dev.get("device_id"),
                    "device_ip": dev.get("device_ip"),
                    "access_method": dev.get("access_method", ""),
                    "credentials_found": len(dev.get("credentials_found", [])),
                })

            # Emit hop events for multi-hop chains
            for chain in chains:
                hops = chain.get("hops", [])
                for i, hop in enumerate(hops):
                    if i + 1 < len(hops):
                        next_hop = hops[i + 1]
                        stream_callback({
                            "type": "intrusion_hop",
                            "hop_index": i + 1,
                            "from_ip": hop.get("device_ip"),
                            "from_id": hop.get("device_id"),
                            "to_ip": next_hop.get("device_ip"),
                            "to_id": next_hop.get("device_id"),
                            "method": hop.get("access_method", ""),
                            "chain_id": chain.get("id"),
                        })

            stream_callback({
                "type": "intrusion_done",
                "devices_compromised": summary.get("devices_compromised", len(compromised_devices)),
                "chains": summary.get("chains_attempted", len(chains)),
                "hops": summary.get("total_hops", 0),
                "crown_jewels_reached": summary.get("crown_jewels_reached", []),
                "credentials_harvested": summary.get("credentials_harvested", 0),
            })
        except Exception as exc:
            log.warning("Failed to emit intrusion SSE events: %s", exc)


def run(context, config, stream_callback=None):
    return context._run_agent(config, stream_callback)
