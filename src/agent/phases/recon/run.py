"""Recon phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
import ipaddress
import json
import re
import subprocess
import logging
from src.agent.core import runtime


log = logging.getLogger(__name__)


class ReconPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _build_recon_evidence_projection(self) -> dict:
        """Project raw Recon tool evidence into a compact, lossless-sidecar ledger."""
        devices: dict[str, dict] = {}
        log_path = self.run_dir / "tool_calls.jsonl"
        if log_path.exists():
            for line in log_path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except (TypeError, ValueError, json.JSONDecodeError):
                    continue
                tool = entry.get("tool", "")
                args = entry.get("args", {}) or {}
                raw_result = entry.get("result", "")
                try:
                    payload = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
                except (TypeError, ValueError, json.JSONDecodeError):
                    payload = {}
                stdout = str(payload.get("stdout", "")) if isinstance(payload, dict) else ""

                if tool == "arp_scan" and isinstance(payload, dict):
                    for host in payload.get("hosts", []):
                        ip = str(host.get("ip", "")).strip()
                        if not ip:
                            continue
                        row = devices.setdefault(ip, {
                            "ip": ip, "device": "", "sources": [],
                            "open_ports": [], "services": [], "failures": [],
                        })
                        row["mac"] = host.get("mac", "")
                        row["vendor"] = host.get("vendor", "")
                        row["sources"].append("arp_scan")

                discovered_ips = []
                if tool == "nmap_discovery":
                    discovered_ips = re.findall(
                        r"Nmap scan report for (?:[^\n(]+ \()?((?:\d{1,3}\.){3}\d{1,3})",
                        stdout,
                    )
                for ip in discovered_ips:
                    row = devices.setdefault(ip, {
                        "ip": ip, "device": "", "sources": [],
                        "open_ports": [], "services": [], "failures": [],
                    })
                    row["sources"].append("nmap_discovery")

                if tool == "nmap_scan":
                    target = str(args.get("target", "")).strip()
                    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", target):
                        continue
                    row = devices.setdefault(target, {
                        "ip": target, "device": "", "sources": [],
                        "open_ports": [], "services": [], "failures": [],
                    })
                    row["sources"].append("nmap_scan")
                    for match in re.finditer(
                        r"(?m)^(\d+)/(tcp|udp)[ \t]+open[ \t]+(\S+)"
                        r"(?:[ \t]+(.*))?$",
                        stdout,
                    ):
                        port = int(match.group(1))
                        protocol = match.group(2)
                        service = match.group(3)
                        version = (match.group(4) or "").strip()
                        if port not in row["open_ports"]:
                            row["open_ports"].append(port)
                        observation = {
                            "port": port, "protocol": protocol,
                            "service": service, "version": version,
                        }
                        if observation not in row["services"]:
                            row["services"].append(observation)
                    if isinstance(payload, dict) and payload.get("return_code") not in (None, 0):
                        row["failures"].append(str(payload.get("stderr") or "scan failed"))

        try:
            from src.agent.tools.graph_tools import _scenario_topology
            nodes = (_scenario_topology or {}).get("nodes", [])
            names = {str(node.get("ip")): node.get("id", "") for node in nodes}
        except Exception:
            names = {}
        for ip, row in devices.items():
            row["device"] = names.get(ip, row.get("device", ""))
            row["sources"] = sorted(set(row["sources"]))
            row["open_ports"] = sorted(set(row["open_ports"]))

        rows = sorted(devices.values(), key=lambda item: ipaddress.ip_address(item["ip"]))
        def _ports_label(row: dict) -> str:
            if row["open_ports"]:
                return ",".join(str(port) for port in row["open_ports"])
            sources = set(row.get("sources", []))
            if "nmap_scan" in sources:
                if sources.intersection({"arp_scan", "nmap_discovery"}):
                    return "no open ports observed"
                return "unreachable"
            if sources.intersection({"arp_scan", "nmap_discovery"}):
                return "not service-scanned"
            return "unreachable"

        markdown_rows = [
            "| {device} | {ip} | {ports} | {services} |".format(
                device=row.get("device") or "undocumented",
                ip=row["ip"],
                ports=_ports_label(row),
                services=", ".join(
                    f"{service['service']}:{service['port']}"
                    + (f" {service['version']}" if service["version"] else "")
                    for service in row["services"]
                ) or "none observed",
            )
            for row in rows
        ]
        projection = {
            "schema_version": "1",
            "source": "tool_calls.jsonl",
            "device_count": len(rows),
            "devices": rows,
            "markdown_service_rows": markdown_rows,
            "note": (
                "Deterministic evidence projection; model narrative remains in "
                "02_recon.md and raw outputs remain in tool_calls.jsonl."
            ),
        }
        (self.run_dir / "02_recon_evidence.json").write_text(
            json.dumps(projection, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return projection

    def _reconcile_phase2_attack_surface(self, projection: dict | None = None) -> dict:
        """Promote Phase 2 service observations into the Phase 3 scenario graph.

        Public benchmark topologies can contain deliberately novel roles. The
        graph loader must not guess their services from the role name, but the
        deterministic Phase 2 ledger already contains observed IP/port facts.
        Merge those facts into the declared role services: Nmap labels can be
        incomplete or uncertain, while the topology remains the coverage floor.
        """
        if self.scenario_id is None or self.target_network is not None:
            return {"status": "not_applicable"}

        if projection is None:
            projection_path = self.run_dir / "02_recon_evidence.json"
            try:
                projection = json.loads(projection_path.read_text(encoding="utf-8"))
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                return {"status": "missing_projection"}
        if not isinstance(projection, dict):
            return {"status": "invalid_projection"}

        from src.agent.tools.graph_tools import _scenario_topology

        topology = _scenario_topology or {}
        nodes = topology.get("nodes", [])
        if not isinstance(nodes, list):
            return {"status": "missing_topology"}

        observed_by_ip = {
            str(row.get("ip")): row
            for row in projection.get("devices", [])
            if isinstance(row, dict) and str(row.get("ip", "")).strip()
        }
        reconciled: list[str] = []
        unresolved: list[str] = []

        for node in nodes:
            if not isinstance(node, dict):
                continue
            node_id = str(node.get("id", ""))
            ip = str(node.get("ip", ""))
            row = observed_by_ip.get(ip)
            observed_services = list(node.get("services") or [])
            if row:
                observed_services.extend(row.get("services") or [])
            normalized_services: list[dict] = []
            seen_services: set[tuple[int, str, str]] = set()
            for service in observed_services:
                if not isinstance(service, dict):
                    continue
                try:
                    port = int(service.get("port"))
                except (TypeError, ValueError):
                    continue
                raw_name = str(
                    service.get("service") or service.get("name") or "unknown"
                ).strip().casefold()
                raw_name = raw_name.rstrip("?").strip()
                name = runtime.SERVICE_ALIASES.get(raw_name, raw_name)
                protocol = str(service.get("protocol") or "tcp").casefold()
                version = str(service.get("version") or "")
                key = (port, protocol, name)
                if key in seen_services:
                    continue
                seen_services.add(key)
                normalized_services.append({
                    "name": name,
                    "port": port,
                    "protocol": protocol,
                    "version": version,
                    "source": "phase2_recon",
                })

            if normalized_services:
                normalized_services.sort(
                    key=lambda item: (item["port"], item["protocol"], item["name"])
                )
                node["services"] = normalized_services
                reconciled.append(node_id)
            elif not node.get("services"):
                unresolved.append(node_id)

        result = {
            "status": "reconciled",
            "declared_nodes": len([node for node in nodes if isinstance(node, dict)]),
            "observed_nodes": len(observed_by_ip),
            "reconciled_nodes": sorted(reconciled),
            "unresolved_nodes": sorted(unresolved),
        }
        log.info(
            "Phase 2 surface reconciliation: %d nodes updated, %d unresolved",
            len(reconciled), len(unresolved),
        )
        return result

    def _discover_attack_surface(
        self,
        target_network: str,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> list[dict]:
        """Discovery/blind mode: nmap-scan the target network to build the
        Phase 3 device surface.

        In blind mode there is no pre-defined topology, so Phase 3 would
        otherwise have zero devices. This actively scans the network and
        excludes the pipeline host's own IPs so the master VM never scans
        itself (avoids polluting the surface with infrastructure hosts).
        """
        tcp_port_services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
            443: "https", 1880: "http", 1883: "mqtt", 3306: "mysql",
            502: "modbus", 4840: "opcua", 5432: "postgresql", 6379: "redis",
            8000: "http", 8080: "http",
            8081: "http", 8443: "https", 9001: "mqtt", 9200: "http",
        }
        udp_port_services = {161: "snmp", 5683: "coap", 47808: "bacnet"}
        tcp_ports = ",".join(str(p) for p in sorted(tcp_port_services))
        udp_ports = ",".join(str(p) for p in sorted(udp_port_services))
        print(f"\n{'=' * 60}")
        print(f"PHASE 3a: DISCOVERY SCAN ({target_network})")
        print(f"{'=' * 60}\n")

        # Own IPs — the master VM must never appear as a target.
        local_ips: set[str] = set()
        try:
            hn = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
            local_ips = {ip for ip in hn.stdout.split() if ip}
        except (OSError, subprocess.SubprocessError):
            pass

        tcp_cmd = ["nmap", "-Pn", "-sT", "-p", tcp_ports, "--open", "-T4", "-oG", "-", *target_network.split()]
        udp_cmd = ["nmap", "-Pn", "-sU", "-p", udp_ports, "--open", "-T4", "-oG", "-", *target_network.split()]
        try:
            tcp_proc = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=600)
            raw_sections = [("tcp", tcp_proc.stdout)]
            try:
                udp_proc = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=600)
                if udp_proc.returncode == 0:
                    raw_sections.append(("udp", udp_proc.stdout))
                else:
                    log.warning("UDP discovery unavailable: %s", udp_proc.stderr.strip()[:300])
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning("UDP discovery unavailable: %s", exc)
        except (OSError, subprocess.SubprocessError) as e:
            log.error("Discovery nmap failed: %s", e)
            return []

        try:
            scans_dir = self.run_dir / "03_scans"
            scans_dir.mkdir(parents=True, exist_ok=True)
            discovery_log = "\n".join(
                f"### {protocol.upper()} DISCOVERY\n{output}"
                for protocol, output in raw_sections
            )
            (scans_dir / "_discovery.txt").write_text(discovery_log, encoding="utf-8")
        except OSError:
            pass

        discovered: dict[str, dict] = {}
        for _scan_protocol, raw in raw_sections:
            for line in raw.splitlines():
                # Greppable line: "Host: <ip> (<name>)\tPorts: 22/open/tcp//ssh///, ..."
                if not line.startswith("Host:") or "Ports:" not in line:
                    continue
                ip = line.split()[1]
                if ip in local_ips:
                    continue
                host = discovered.setdefault(ip, {"id": ip, "ip": ip, "type": "host", "services": []})
                existing = {(item["port"], item.get("protocol", "tcp")) for item in host["services"]}
                for entry in line.split("Ports:", 1)[1].split(","):
                    parts = entry.strip().split("/")
                    if len(parts) < 3 or parts[1] != "open":
                        continue
                    try:
                        port = int(parts[0])
                    except ValueError:
                        continue
                    protocol = parts[2] or "tcp"
                    key = (port, protocol)
                    if key in existing:
                        continue
                    names = udp_port_services if protocol == "udp" else tcp_port_services
                    host["services"].append({
                        "name": names.get(port, "unknown"),
                        "port": port,
                        "protocol": protocol,
                    })
                    existing.add(key)
        surface = [host for host in discovered.values() if host["services"]]

        print(f"  Discovered {len(surface)} host(s) with open ports on {target_network}")
        if not surface:
            log.warning("Discovery scan of %s found no hosts with open ports", target_network)
        if stream_callback:
            ips = ", ".join(h["ip"] for h in surface) or "none"
            stream_callback({
                "type": "tool_result",
                "name": "discovery_scan",
                "result": f"Discovered {len(surface)} host(s): {ips}",
            })
        return surface

    @staticmethod
    def _recon_scan_plan(nodes: list) -> list[dict]:
        """Return the minimum per-device port coverage required from Recon."""
        plan = []
        for node in nodes:
            ip = node.get("ip", "")
            if not ip:
                continue
            role = node.get("role") or node.get("type") or "unknown"
            plan.append({
                "target": ip,
                "ports": runtime.DEVICE_DEFAULT_PORTS.get(role, runtime.DEFAULT_PORTS),
                "skip_discovery": True,
                "device_id": node.get("id", ip),
                "role": role,
            })
        return sorted(plan, key=lambda item: ipaddress.ip_address(item["target"]))

    @classmethod
    def _build_nmap_groups(cls, nodes: list) -> str:
        """Return the minimum per-device port coverage table shown to Recon."""
        plan = cls._recon_scan_plan(nodes)
        if not plan:
            return ""

        lines = ["Minimum nmap coverage ledger — satisfy every row in any order:"]
        lines.append("")
        lines.append("| Row | Device | Role | target | minimum ports | recommended skip_discovery |")
        lines.append("|-----|--------|------|--------|---------------|----------------------------|")
        for call_n, item in enumerate(plan, 1):
            lines.append(
                f"| {call_n} | `{item['device_id']}` | `{item['role']}` | "
                f"`{item['target']}` | `{item['ports']}` | `true` |"
            )
        lines.append("")
        lines.append(
            f"Total: {len(plan)} devices requiring minimum port coverage. "
            "A wider scan or several complementary scans also satisfy a row."
        )
        return "\n".join(lines)

    def _apply_recon_tool_contract(self, tools: list[dict]) -> list[dict]:
        """Enforce Recon invariants without prescribing the model's strategy.

        All models receive the same non-mutating reconnaissance surface and may
        choose call order, repeat observations, split port ranges, widen scans,
        and use specialized probes.  The contract enforces only universal
        invariants: network scope, a discovery/read baseline, minimum per-device
        port coverage, and a non-empty validated deliverable at completion.
        """
        supporting_names = {
            tool["name"]
            for group in (runtime.GRAPH_TOOLS, runtime.DELIVERABLE_TOOLS, runtime.SKILL_TOOLS)
            for tool in group
        } - {"search_history"}
        allowed_names = runtime.RECON_READ_ONLY_TOOL_NAMES | supporting_names
        selected = [tool for tool in tools if tool["name"] in allowed_names]

        from src.agent.tools.graph_tools import _scenario_topology as topology

        nodes = (topology or {}).get("nodes", [])
        plan = self._recon_scan_plan(nodes)
        expected_scans: dict[str, dict] = {
            item["target"]: item for item in plan
        }
        covered_ports: dict[str, set[int]] = {}
        failed_ports: dict[str, set[int]] = {}
        completed_calls: set[str] = set()
        scan_cache: dict[str, str] = {}
        scan_failure_counts: dict[str, int] = {}
        strict_compact_completion = self._uses_compact_local_moe()
        target_subnets = [
            value for value in str(self.context.get("target_subnet", "")).split()
            if value
        ]

        def _in_scope(target: str) -> bool:
            try:
                candidate = ipaddress.ip_network(target, strict=False)
                return any(
                    candidate.subnet_of(ipaddress.ip_network(cidr, strict=False))
                    for cidr in target_subnets
                )
            except ValueError:
                return False

        def _out_of_scope_argument(kwargs: dict) -> str | None:
            """Return the first explicit IPv4/CIDR outside the declared scope."""
            target_fields = {"target", "host", "ip", "broker", "url"}
            for field, value in kwargs.items():
                if field not in target_fields or value is None:
                    continue
                for match in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", str(value)):
                    if not _in_scope(match):
                        return match
            return None

        def _ports(spec: str) -> set[int]:
            """Expand common nmap comma/range syntax into a coverage set."""
            result: set[int] = set()
            for token in str(spec).replace(" ", ",").split(","):
                token = token.strip()
                if not token:
                    continue
                token = re.sub(r"^[TtUu]:", "", token)
                if token == "-":
                    result.update(range(1, 65536))
                    continue
                try:
                    if "-" in token:
                        start, end = (int(part) for part in token.split("-", 1))
                        if 1 <= start <= end <= 65535:
                            result.update(range(start, end + 1))
                    else:
                        port = int(token)
                        if 1 <= port <= 65535:
                            result.add(port)
                except ValueError:
                    continue
            return result

        def _succeeded(result: str) -> bool:
            if str(result).startswith("Error"):
                return False
            try:
                payload = json.loads(result)
            except (TypeError, ValueError, json.JSONDecodeError):
                return True
            if not isinstance(payload, dict):
                return True
            return not (
                payload.get("ok") is False
                or bool(payload.get("error"))
                or payload.get("status") == "ERROR"
                or payload.get("return_code") not in (None, 0)
            )

        def _discover_targets(result: str) -> None:
            """In blind mode, discovery results become the mandatory scan ledger."""
            if plan:
                return
            discovered: set[str] = set()
            try:
                payload = json.loads(result)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {}
            for host in payload.get("hosts", []) if isinstance(payload, dict) else []:
                if isinstance(host, dict) and host.get("ip"):
                    discovered.add(str(host["ip"]))
            stdout = payload.get("stdout", "") if isinstance(payload, dict) else str(result)
            discovered.update(re.findall(
                r"Nmap scan report for (?:[^\s(]+ \()?((?:\d{1,3}\.){3}\d{1,3})\)?",
                stdout,
            ))
            for target in sorted(discovered):
                if not _in_scope(target):
                    continue
                expected_scans.setdefault(target, {
                    "target": target,
                    "ports": runtime.DEFAULT_PORTS,
                    "skip_discovery": True,
                    "device_id": target,
                    "role": "discovered",
                })

        def _missing_requirements() -> list[dict]:
            missing: list[dict] = []
            if "arp_scan" not in completed_calls:
                missing.append({"requirement": "local_discovery", "tool": "arp_scan"})
            for subnet in target_subnets:
                marker = f"nmap_discovery:{subnet}"
                if marker not in completed_calls:
                    missing.append({
                        "requirement": "subnet_discovery",
                        "target": subnet,
                        "tool": "nmap_discovery",
                    })
            if "read_phase1" not in completed_calls:
                missing.append({
                    "requirement": "phase1_context",
                    "filename": "01_graph_analysis.md",
                    "tool": "read_deliverable",
                })
            for target, item in expected_scans.items():
                required = _ports(item["ports"])
                absent = sorted(required - covered_ports.get(target, set()))
                if absent:
                    missing.append({
                        "requirement": "minimum_port_coverage",
                        "target": target,
                        "missing_ports": absent,
                        "suggested_tool": "nmap_scan",
                    })
            return missing

        def _progress() -> dict:
            """Return the authoritative Recon ledger after every tool result."""
            missing = _missing_requirements()
            targets = []
            for target, item in expected_scans.items():
                required = _ports(item["ports"])
                covered = covered_ports.get(target, set())
                targets.append({
                    "target": target,
                    "device_id": item.get("device_id", target),
                    "role": item.get("role", "unknown"),
                    "required_ports": sorted(required),
                    "covered_ports": sorted(required & covered),
                    "failed_ports": sorted(required & failed_ports.get(target, set())),
                    "missing_ports": sorted(required - covered),
                })
            return {
                "schema_version": "1",
                "completed": {
                    "local_discovery": "arp_scan" in completed_calls,
                    "subnet_discovery": all(
                        f"nmap_discovery:{subnet}" in completed_calls
                        for subnet in target_subnets
                    ),
                    "phase1_context": "read_phase1" in completed_calls,
                },
                "targets": targets,
                "missing_requirements": missing,
                "next_requirement": missing[0] if missing else None,
                "ready_to_save": not missing,
            }

        def _with_progress(
            result: str,
            *,
            cache_hit: bool = False,
            cache_reason: str = "",
        ) -> str:
            """Attach machine-readable progress without discarding tool evidence."""
            try:
                payload = json.loads(result)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = {"ok": True, "result": str(result)}
            if not isinstance(payload, dict):
                payload = {"ok": True, "result": payload}
            else:
                payload = dict(payload)
            payload["recon_progress"] = _progress()
            if cache_hit:
                payload["recon_cache"] = {
                    "hit": True,
                    "reason": cache_reason or "equivalent successful scan already executed",
                }
            return json.dumps(payload, ensure_ascii=False, default=str)

        def _scan_signature(kwargs: dict) -> str:
            """Canonicalize an nmap request so argument ordering cannot evade cache."""
            normalized = dict(kwargs)
            normalized["target"] = str(kwargs.get("target", "")).strip()
            normalized["ports"] = sorted(_ports(str(kwargs.get("ports", ""))))
            scripts = kwargs.get("scripts")
            if scripts is not None:
                normalized["scripts"] = sorted({
                    value.strip() for value in str(scripts).split(",") if value.strip()
                })
            for key in ("skip_discovery", "udp_scan", "service_detection"):
                if key in normalized:
                    normalized[key] = bool(normalized[key])
            return json.dumps(normalized, sort_keys=True, ensure_ascii=False, default=str)

        def _error(kind: str, message: str, **extra) -> str:
            return _with_progress(json.dumps({
                "ok": False, "error_kind": kind, "error": message, **extra,
            }))

        def _guard(name: str, original_fn):
            def guarded(**kwargs):
                outside = _out_of_scope_argument(kwargs)
                if outside is not None:
                    return _error(
                        "invalid_recon_target",
                        f"Out-of-scope Recon target: {outside}",
                        allowed_subnets=target_subnets,
                    )
                if (
                    strict_compact_completion
                    and name != "save_deliverable"
                    and not _missing_requirements()
                ):
                    return _error(
                        "recon_completion_required",
                        "Compact local Recon evidence is complete; only "
                        "save_deliverable is allowed now.",
                        allowed_tool="save_deliverable",
                    )

                if name == "arp_scan":
                    if kwargs:
                        return _error("invalid_recon_args", "arp_scan must be called without arguments")
                    result = original_fn(**kwargs)
                    if _succeeded(result):
                        completed_calls.add("arp_scan")
                    _discover_targets(result)
                    return _with_progress(result)

                if name == "nmap_discovery":
                    target = str(kwargs.get("target", ""))
                    result = original_fn(target=target)
                    if _succeeded(result) and target in target_subnets:
                        completed_calls.add(f"nmap_discovery:{target}")
                    _discover_targets(result)
                    return _with_progress(result)

                if name == "read_deliverable":
                    if (
                        strict_compact_completion
                        and kwargs.get("filename") == "01_graph_analysis.md"
                        and "read_phase1" in completed_calls
                    ):
                        return _with_progress(json.dumps({
                            "filename": "01_graph_analysis.md",
                            "already_loaded": True,
                            "content": (
                                "Phase 1 context was already loaded successfully. "
                                "Reuse the earlier tool result and finish 02_recon.md."
                            ),
                        }))
                    result = original_fn(**kwargs)
                    if (
                        kwargs.get("filename") == "01_graph_analysis.md"
                        and _succeeded(result)
                    ):
                        completed_calls.add("read_phase1")
                    return _with_progress(result)

                if name == "nmap_scan":
                    target = str(kwargs.get("target", ""))
                    signature = _scan_signature(kwargs)
                    if signature in scan_cache:
                        return _with_progress(
                            scan_cache[signature],
                            cache_hit=True,
                            cache_reason=(
                                "strictly equivalent target/ports/scripts/protocol "
                                "scan already completed"
                            ),
                        )
                    result = original_fn(**kwargs)
                    succeeded = _succeeded(result)
                    requested_ports = _ports(str(kwargs.get("ports", "")))
                    if succeeded and target in expected_scans:
                        covered_ports.setdefault(target, set()).update(requested_ports)
                    if succeeded:
                        scan_cache[signature] = result
                    elif target in expected_scans:
                        attempts = scan_failure_counts.get(signature, 0) + 1
                        scan_failure_counts[signature] = attempts
                        if attempts >= 2:
                            # Two identical failed probes are conclusive enough for
                            # Recon completion: preserve them as failed evidence
                            # instead of retrying forever or claiming an open port.
                            covered_ports.setdefault(target, set()).update(requested_ports)
                            failed_ports.setdefault(target, set()).update(requested_ports)
                    return _with_progress(result)

                if name == "save_deliverable":
                    missing = _missing_requirements()
                    if missing:
                        return _error(
                            "recon_contract_incomplete",
                            "Recon cannot finish until all minimum evidence requirements are satisfied; strategy and call order remain free",
                            missing_requirements=missing,
                        )
                    return _with_progress(original_fn(**kwargs))

                return _with_progress(original_fn(**kwargs))

            return guarded

        wrapped = [
            {**tool, "function": _guard(tool["name"], tool["function"])}
            for tool in selected
        ]
        return wrapped

    @staticmethod
    def _infer_role_from_ports(ports: list) -> str:
        """Infer a device role from open ports so the analyze_device prompt gets meaningful guidance."""
        port_set = set(int(p) for p in ports if str(p).isdigit())
        if 1883 in port_set or 8883 in port_set:
            return "mqtt_broker"
        if 1880 in port_set:
            return "nodered_server"
        if 502 in port_set or 44818 in port_set or 102 in port_set:
            return "modbus_server"
        if 5683 in port_set:
            return "coap_server"
        if 554 in port_set or 8554 in port_set:
            return "camera_server"
        if 21 in port_set:
            return "ftp_server"
        if 6379 in port_set:
            return "db_server_v2"
        if 3306 in port_set:
            return "db_server"
        if 161 in port_set:
            return "snmp_server"
        if 8080 in port_set or 8443 in port_set or 80 in port_set or 443 in port_set:
            return "web_server"
        return "unknown"

    @staticmethod
    def _service_for_discovered_port(port: object) -> tuple[str, str]:
        """Return the scanner alias and transport for a discovered port."""
        try:
            number = int(port)
        except (TypeError, ValueError):
            return "unknown", "tcp"
        service = {
            21: "ftp", 22: "ssh", 23: "telnet", 80: "http", 443: "https",
            161: "snmp", 389: "ldap", 502: "modbus", 102: "modbus",
            3306: "mysql", 44818: "modbus", 4840: "opcua", 5683: "coap",
            6379: "redis", 1883: "mqtt", 8883: "mqtt", 9001: "mqtt",
        }.get(number, "unknown")
        protocol = "udp" if number in {161, 5683} else "tcp"
        return service, protocol

    def _run_discovery_followup(
        self,
        new_hosts: list[dict],
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Mini Phase 2.5/3.5: scan and analyze hosts discovered during Phase 4 exploitation.

        For each newly discovered host:
        1. Run the deterministic scanner (nmap + service fingerprinting).
        2. Run a Phase 3b LLM micro-agent to analyse the scan results.
        3. Re-aggregate all device findings so the new vulns appear in 03_vuln_analysis.json
           before Phase 5 report generation.
        """
        from src.agent.scanner import run_scanner
        from src.agent.tools.graph_tools import update_discovery_hosts, get_network_neighbors

        print(f"\n{'=' * 60}")
        print(f"PHASE 2.5/3.5: DISCOVERY FOLLOWUP ({len(new_hosts)} new host(s))")
        print(f"{'=' * 60}\n")

        if stream_callback:
            stream_callback({"type": "phase_start", "phase": "2.5", "label": "Discovery followup"})

        skill_tools = [t for t in runtime.SKILL_TOOLS if t["name"] == "cve_search"]
        available_recon_tools, _ = runtime.filter_unavailable_tools(runtime.RECON_TOOLS)
        recon_limited = [t for t in available_recon_tools if t["name"] == "http_get"]
        analysis_candidates = self._apply_scenario_tool_policy(
            recon_limited + skill_tools + runtime.DELIVERABLE_TOOLS, 3
        )
        analysis_tools = [self._wrap_tool(t) for t in analysis_candidates]

        for host in new_hosts:
            ip = host.get("ip", "")
            if not ip:
                continue
            device_id = f"discovered-{ip.replace('.', '-')}"
            inferred_role = self._infer_role_from_ports(host.get("open_ports", []))
            device = {
                "id": device_id,
                "ip": ip,
                "type": inferred_role,
                "role": inferred_role,
                "services": [
                    {
                        "name": self._service_for_discovered_port(p)[0],
                        "port": p,
                        "protocol": self._service_for_discovered_port(p)[1],
                    }
                    for p in host.get("open_ports", [])
                ],
            }
            print(f"  [+] Followup scan: {device_id} ({ip})")

            # 1. Targeted nmap scan
            scanner_kwargs = {"compact": self._uses_compact_local_moe()}
            recon_policy = runtime.tool_policy_for_phase(
                self.scenario_tool_policy, "recon"
            )
            if recon_policy is not None:
                scanner_kwargs["allowed_tool_names"] = recon_policy
            mini_scan = run_scanner(
                self.run_dir, [device], stream_callback, **scanner_kwargs
            )
            scan_data = mini_scan.get(device_id, {})

            # Prepare scan results for prompt
            scan_for_prompt: dict = {}
            for svc_key, entries in scan_data.get("scan_results", {}).items():
                scan_for_prompt[svc_key] = []
                for entry in entries:
                    result = entry.get("result", "")
                    if isinstance(result, str) and len(result) > 2000:
                        result = result[:2000] + "\n[truncated]"
                    scan_for_prompt[svc_key].append({
                        "tool": entry["tool"],
                        "kwargs": entry.get("kwargs", {}),
                        "result": result,
                    })

            deliverable_file = f"03_device_{device_id}.json"
            variables = {**self.context}
            variables["device_id"] = device_id
            variables["device_ip"] = ip
            variables["device_type"] = inferred_role
            variables["device_role"] = inferred_role
            variables["device_services"] = ", ".join(str(p) for p in host.get("open_ports", []))
            variables["device_os"] = "unknown"
            variables["expected_deliverable"] = deliverable_file
            runtime.set_expected_deliverable(deliverable_file)
            variables["scan_results"] = json.dumps(scan_for_prompt, indent=2, ensure_ascii=False)
            variables["trivial_findings"] = json.dumps(
                scan_data.get("findings", []), indent=2, ensure_ascii=False
            )
            variables["network_neighbors_upstream"] = host.get("discovered_via", "unknown (pivot discovery)")
            variables["network_neighbors_downstream"] = "unknown — newly discovered host"
            variables["network_role"] = "PIVOT"

            system_prompt = runtime.load_prompt("analyze_device", variables)
            phase_name = f"followup_{device_id}"
            followup_config = runtime.AgentConfig(
                name=phase_name,
                phase=3,
                prompt_template="analyze_device",
                deliverable_file=deliverable_file,
                tools=[],
                validator="json_valid",
            )
            followup_tools = self._apply_deliverable_transaction(
                analysis_tools, followup_config, stream_callback
            )
            self.tracker.start_phase(phase_name)
            self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Analyze vulnerabilities for newly discovered host {ip}. "
                    f"MANDATORY: call save_deliverable('{deliverable_file}', json_content) before finishing."
                ),
                tools=followup_tools,
                max_turns=config.max_turns,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
                stream_callback=self._model_stream_callback(
                    stream_callback, phase="3.5", agent=phase_name
                ),
                required_tool="save_deliverable",
                terminate_after_tool="save_deliverable",
                stop_event=self._stop_event,
            )
            self.tracker.end_phase()
            print(f"  [+] Followup done: {device_id}")

        # 3. Re-aggregate all device findings (including newly discovered ones)
        print("  [+] Re-aggregating device vulns with new findings...")
        self._aggregate_device_vulns(config, stream_callback)
        # 4. Rebuild 04_exploitation.json to reflect new Phase 3 findings
        print("  [+] Re-aggregating exploit results with new findings...")
        self._aggregate_exploit_results()

    def _infer_topology_links(self, stream_callback) -> None:
        """Infer network links between discovered hosts using traceroute.

        Runs after Phase 2 when target_network is set (discovery mode).
        For each host in 02_recon.md, runs traceroute and deduces edges:
          - hop at distance 1 = direct gateway link
          - shared intermediate hops = common router between two hosts
        Emits topology_edge SSE events consumed by the Cytoscape frontend.
        """
        import re as _re
        import subprocess as _sub

        log.info("Discovery mode: inferring topology links via traceroute")

        # Extract discovered host IPs from 02_recon.md
        recon_path = self.run_dir / "02_recon.md"
        if not recon_path.exists():
            log.warning("02_recon.md not found — skipping topology inference")
            return

        recon_text = recon_path.read_text(encoding="utf-8")
        # Parse IPs that look like 192.168.x.x from the recon report
        subnet_prefix = self.target_network.rsplit(".", 1)[0] if self.target_network else ""
        host_ips = list(dict.fromkeys(  # deduplicate, preserve order
            m for m in _re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", recon_text)
            if subnet_prefix and m.startswith(subnet_prefix) and not m.endswith(".0") and not m.endswith(".255")
        ))

        if not host_ips:
            log.warning("No host IPs found in 02_recon.md — skipping topology inference")
            return

        log.info("Running traceroute on %d hosts: %s", len(host_ips), host_ips[:10])

        # {ip: [hop_ip, ...]} — ordered list of hops for each host
        host_hops: dict[str, list[str]] = {}

        def _traceroute(target: str, max_hops: int = 8) -> list[str]:
            import platform
            cmd = (["traceroute", "-n", "-m", str(max_hops), target]
                   if platform.system() == "Darwin"
                   else ["traceroute", "-n", "-m", str(max_hops), "-w", "1", target])
            try:
                r = _sub.run(cmd, capture_output=True, text=True, timeout=max_hops * 3 + 5)
                hops = []
                for line in r.stdout.splitlines():
                    m = _re.match(r"^\s*\d+\s+([\d.]+)", line)
                    if m and m.group(1) != target:
                        hops.append(m.group(1))
                return hops
            except Exception as exc:
                log.debug("traceroute to %s failed: %s", target, exc)
                return []

        emitted_edges: set[tuple[str, str]] = set()

        def _emit_edge(src: str, dst: str, link_type: str = "ethernet"):
            key = (min(src, dst), max(src, dst))
            if key in emitted_edges:
                return
            emitted_edges.add(key)
            log.info("Topology edge inferred: %s → %s (%s)", src, dst, link_type)
            if stream_callback:
                stream_callback({
                    "type": "topology_edge",
                    "source": src,
                    "target": dst,
                    "link_type": link_type,
                })

        for ip in host_ips:
            hops = _traceroute(ip, max_hops=8)
            host_hops[ip] = hops
            if hops:
                # Direct link: host ↔ first hop (gateway/switch)
                _emit_edge(ip, hops[0], "ethernet")
                # Intermediate hops form a chain
                for i in range(len(hops) - 1):
                    _emit_edge(hops[i], hops[i + 1], "ethernet")

        # Shared intermediate hops → same router serves multiple hosts
        # (already handled above via direct edge emission)

        # Service-based inference: MQTT broker on port 1883 = hub
        # Parse nmap results from 02_recon.md for service hints
        mqtt_broker = None
        for m in _re.finditer(r"([\d.]+).*?1883/tcp.*?open", recon_text, _re.DOTALL):
            mqtt_broker = m.group(1)
            break
        if not mqtt_broker:
            # Also check line-by-line for "host | ... | 1883"
            for line in recon_text.splitlines():
                if "1883" in line:
                    m = _re.search(r"([\d]+\.[\d]+\.[\d]+\.[\d]+)", line)
                    if m:
                        mqtt_broker = m.group(1)
                        break

        if mqtt_broker:
            log.info("MQTT broker detected at %s — adding spoke edges", mqtt_broker)
            for ip in host_ips:
                if ip != mqtt_broker:
                    _emit_edge(ip, mqtt_broker, "mqtt")

        # Save inferred edges to run directory for report context
        edges_path = self.run_dir / "02_topology_edges.json"
        edges_data = [{"source": s, "target": t} for s, t in emitted_edges]
        edges_path.write_text(json.dumps({"edges": edges_data, "host_hops": host_hops}, indent=2))
        log.info("Topology inference complete: %d edges, saved to %s", len(edges_data), edges_path)


def run(context, config, stream_callback=None):
    return context._run_agent(config, stream_callback)
