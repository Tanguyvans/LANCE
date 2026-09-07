"""Graph phase: compact adaptations."""
from __future__ import annotations
from datetime import datetime


class CompactGraphPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _render_compact_graph_markdown(self) -> str:
        """Render compact Graph facts from the deterministic graph ledger."""
        projection = self._build_graph_evidence_projection()
        nodes = [
            node for node in projection.get("nodes", []) if isinstance(node, dict)
        ]
        edges = [
            edge for edge in projection.get("edges", []) if isinstance(edge, dict)
        ]
        surface = [
            item for item in projection.get("attack_surface", [])
            if isinstance(item, dict)
        ]
        attack_paths = [
            item for item in projection.get("attack_paths", [])
            if isinstance(item, dict)
        ]
        risk_scores = [
            item for item in projection.get("risk_scores", [])
            if isinstance(item, dict)
        ]

        numeric_scores = []
        for item in risk_scores:
            value = item.get("risk_score", item.get("score"))
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                numeric_scores.append((float(value), str(item.get("id", ""))))
        main_risk = max(numeric_scores)[1] if numeric_scores else "Not pre-computed"

        topology_rows = [
            "| {segment} | {device} | {role} |".format(
                segment=str(node.get("type") or node.get("role") or "declared"),
                device=str(node.get("id") or "unknown"),
                role=str(node.get("role") or "unknown"),
            )
            for node in nodes
        ] or ["| — | No declared devices | — |"]

        protocols: dict[str, int] = {}
        for edge in edges:
            protocol = str(edge.get("protocol") or "Not declared")
            protocols[protocol] = protocols.get(protocol, 0) + 1
        protocol_rows = [
            f"| {protocol} | {count} links | Declarative edge metadata |"
            for protocol, count in sorted(protocols.items())
        ] or ["| Not declared | 0 links | No declarative edge metadata |"]

        surface_rows = []
        for item in surface:
            services = [
                service for service in item.get("services", [])
                if isinstance(service, dict)
            ]
            services_text = ", ".join(
                f"{service.get('name', 'unknown')}:{service.get('port', '?')}"
                for service in services
            ) or "none declared"
            surface_rows.append(
                "| {id} | {ip} | {type} | {services} | Not pre-computed |".format(
                    id=item.get("id", "unknown"),
                    ip=item.get("ip", "unknown"),
                    type=item.get("type", item.get("role", "unknown")),
                    services=services_text,
                )
            )
        if not surface_rows:
            surface_rows.append("| — | — | — | No declared services | — |")

        path_rows = []
        for rank, item in enumerate(attack_paths, 1):
            raw_path = item.get("path", item.get("nodes", item.get("chain", "")))
            if isinstance(raw_path, list):
                raw_path = " → ".join(str(node) for node in raw_path)
            cves = item.get("cve_ids", item.get("cves", []))
            if isinstance(cves, list):
                cves = ", ".join(str(cve) for cve in cves) or "N/A"
            path_rows.append(
                f"| {rank} | {raw_path or item.get('id', 'declared path')} | "
                f"{item.get('score', 'Not pre-computed')} | {cves or 'N/A'} |"
            )
        if not path_rows:
            note = projection.get("attack_paths_note") or "No pre-computed attack paths"
            path_rows.append(f"| — | {note} | — | — |")

        risk_by_id = {
            str(item.get("id")): item for item in risk_scores if item.get("id")
        }
        risk_rows = []
        for rank, node in enumerate(nodes, 1):
            item = risk_by_id.get(str(node.get("id")), {})
            score = item.get("risk_score", item.get("score", "Not pre-computed"))
            risk_rows.append(
                f"| {rank} | {node.get('id', 'unknown')} | {score} | — | — | — | — |"
            )
        if not risk_rows:
            risk_rows.append("| — | No risk scores supplied | — | — | — | — | — |")

        scan_rows = []
        for priority, item in enumerate(surface, 1):
            ports = sorted({
                int(service["port"])
                for service in item.get("services", [])
                if isinstance(service, dict)
                and isinstance(service.get("port"), int)
                and not isinstance(service.get("port"), bool)
            })
            scan_rows.append(
                f"| {priority} | {item.get('id', 'unknown')} | "
                f"{item.get('ip', 'unknown')} | "
                f"{','.join(str(port) for port in ports) or 'default'} | "
                "Validate declared services with active reconnaissance |"
            )
        if not scan_rows:
            scan_rows.append("| — | — | — | — | No declared targets |")

        return "\n".join([
            "# Phase 1: Graph Analysis — NATO Smart City IoT Lab",
            "",
            f"**Date:** {datetime.now().date().isoformat()}",
            "**Source:** Deterministic projection of declarative graph tools",
            "",
            "## 1. Executive Summary",
            "",
            f"- **Declared devices:** {projection.get('node_count', len(nodes))}",
            f"- **Theoretical attack surface:** {projection.get('service_count', 0)} declared services",
            f"- **Estimated main risk:** {main_risk}",
            "",
            "## 2. Network Topology (Declarative Model)",
            "",
            "### 2.1 Network Segments",
            "",
            "| Segment | Devices | Role |",
            "|---------|---------|------|",
            *topology_rows,
            "",
            "### 2.2 Protocols",
            "",
            "| Protocol | Links | Security Notes |",
            "|----------|-------|----------------|",
            *protocol_rows,
            "",
            "## 3. Theoretical Attack Surface",
            "",
            "| Device ID | IP Address | Type | Services (declared) | Risk Factor |",
            "|-----------|------------|------|---------------------|-------------|",
            *surface_rows,
            "",
            "## 4. Critical Attack Paths",
            "",
            "| Rank | Path | Score | CVEs Involved |",
            "|------|------|-------|---------------|",
            *path_rows,
            "",
            "## 5. Pivot Nodes",
            "",
            "| Device | Betweenness Centrality | Paths Through | Role |",
            "|--------|------------------------|---------------|------|",
            "| Not pre-computed | — | — | Validate after active reconnaissance |",
            "",
            "## 6. Risk Scores",
            "",
            "| Rank | Device | Risk Score | Max CVSS | CVE Count | Hops from Internet | Centrality |",
            "|------|--------|------------|----------|-----------|--------------------|------------|",
            *risk_rows,
            "",
            "## 7. Scan Plan for Phase 2",
            "",
            "### 7.1 Priority Targets",
            "",
            "| Priority | Device | IP | Ports to Scan | Rationale |",
            "|----------|--------|----|---------------|-----------|",
            *scan_rows,
            "",
            "### 7.2 Anticipated Discrepancies",
            "",
            "- Undocumented hosts or services may appear during active discovery.",
            "- Declared services may be filtered, unavailable, or exposed on additional ports.",
            "- Attack paths and risk scores remain uncomputed until active evidence exists.",
            "",
        ])

    @staticmethod
    def _validate_compact_graph_projection(
        content: str, projection: dict
    ) -> tuple[bool, str]:
        evidence_refs = projection.get("evidence_refs", {})
        required_tools = {
            "get_network_topology", "get_attack_surface",
            "get_attack_paths", "get_risk_scores",
        }
        missing_tools = sorted(
            tool for tool in required_tools if not evidence_refs.get(tool)
        )
        if missing_tools:
            return False, (
                "Compact Graph evidence is incomplete; call the missing tools: "
                + ", ".join(missing_tools)
            )
        expected = [
            f"**Declared devices:** {projection.get('node_count', 0)}",
            f"**Theoretical attack surface:** {projection.get('service_count', 0)} declared services",
        ]
        declared_ids = {
            str(node.get("id")) for node in projection.get("nodes", [])
            if isinstance(node, dict) and node.get("id")
        }
        covered_ids = set(projection.get("device_coverage", {}))
        missing_coverage = sorted(declared_ids - covered_ids)
        if missing_coverage:
            return False, (
                "Graph evidence lacks per-device facts. Reuse get_attack_surface "
                "coverage and call get_device_info only for missing nodes: "
                + ", ".join(missing_coverage)
            )
        expected.extend(
            f"| {item.get('id')} | {item.get('ip')} |"
            for item in projection.get("attack_surface", [])
            if isinstance(item, dict) and item.get("id") and item.get("ip")
        )
        missing = [token for token in expected if token not in content]
        if missing:
            return False, (
                "Compact Graph output diverges from deterministic evidence: "
                f"{len(missing)} fact token(s) missing"
            )
        return True, "OK"
