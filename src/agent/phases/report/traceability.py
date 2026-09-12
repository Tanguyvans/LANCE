"""Report-only reference diagnostics, not a second evidence evaluator.

Resolving a reference and checking its ID/destination does not validate the
service, resource or security property. Only the shared evaluation contract can
accept a proof. Source addresses in output likewise do not create targets.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

from src.agent.evidence.capabilities import result_data
from src.agent.evidence.records import observed_targets


class ReportTraceIndex:
    def __init__(self, run_dir: Path):
        self.records: dict[str, list[dict]] = {}
        self.intact = True
        try:
            with (run_dir / "tool_calls.jsonl").open(encoding="utf-8") as ledger:
                for line in ledger:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except ValueError:
                        self.intact = False
                        continue
                    if not isinstance(record, dict):
                        self.intact = False
                        continue
                    ref = record.get("evidence_ref")
                    if isinstance(ref, str) and ref.strip():
                        self.records.setdefault(ref.strip(), []).append(record)
        except (OSError, UnicodeError):
            self.intact = False

    def describe(self, test: dict) -> str:
        refs = test.get("evidence_refs")
        if not isinstance(refs, list) or not refs:
            return "No evidence references; trace attribution unavailable"
        if not self.intact:
            return "Ledger unavailable or incomplete; reference attribution not established"
        counts: dict[str, int] = {}
        for ref in dict.fromkeys(str(ref).strip() for ref in refs):
            records = self.records.get(ref, [])
            if not records:
                state = "missing"
            elif len(records) != 1:
                state = "ambiguous"
            else:
                record = records[0]
                expected_id = str(test.get("vuln_id") or "").strip()
                actual_id = str(record.get("vuln_id") or "").strip()
                target = str(test.get("device_ip") or "").strip()
                if expected_id and actual_id and expected_id != actual_id:
                    state = "finding ID mismatch"
                elif target and target not in observed_targets(record):
                    state = "destination mismatch or unavailable"
                elif not expected_id or not actual_id or not target:
                    state = "resolved, attribution incomplete"
                else:
                    state = "resolved, ID/destination linked"
            counts[state] = counts.get(state, 0) + 1
        return "; ".join(f"{state}: {count}" for state, count in counts.items()) + (
            "; reference linkage only — property/proof acceptance is not evaluated here"
        )

    def ssh_source_observations(self) -> list[dict]:
        """Read explicitly labelled SSH environment tuples from unique records.

        This is output interpretation, not execution attestation. Never infer
        the client's role or a pivot. Require the server to match tool input.
        """
        if not self.intact:
            return []
        observations = []
        seen = set()
        for ref, records in self.records.items():
            if len(records) != 1:
                continue
            record = records[0]
            if record.get("tool") not in {"ssh_exec", "ssh_login"}:
                continue
            result = result_data(record)
            # Reading an explicit environment tuple does not require an `id`
            # command as well. This remains an output observation, not access
            # validation; a failed/unfinished command is excluded.
            rc = result.get("return_code")
            if (isinstance(rc, bool) or rc != 0 or result.get("error") or result.get("timed_out")
                    or any(result.get(key) is False for key in ("success", "ok", "authenticated"))):
                continue
            stdout = str(result.get("stdout") or result.get("output") or "")
            for match in re.finditer(
                r"(?m)^SSH_CONNECTION=([^\s]+) ([0-9]+) ([^\s]+) ([0-9]+)\r?$", stdout,
            ):
                client, client_port, server, server_port = match.groups()
                try:
                    client = str(ipaddress.ip_address(client))
                    server = str(ipaddress.ip_address(server))
                except ValueError:
                    continue
                if not all(0 < int(port) <= 65535 for port in (client_port, server_port)):
                    continue
                if server not in observed_targets(record):
                    continue
                key = (client, server, ref)
                if key in seen:
                    continue
                seen.add(key)
                observations.append({
                    "client_source_ip": client, "server_ip": server,
                    "evidence_ref": ref,
                    "interpretation": "SSH client source reported in stdout; not an additional target, runner identity or pivot proof",
                })
        return observations
