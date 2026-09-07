"""Recon phase: compact adaptations."""
from __future__ import annotations
from collections.abc import Callable
import logging
from src.agent.core import runtime


log = logging.getLogger(__name__)


class CompactReconPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _finalize_compact_recon_markdown(self, content: str) -> str:
        """Bind compact local Recon facts to the deterministic evidence ledger.

        Compact 3B models retain control over the Key Findings narrative, while
        the two fact-heavy sections are rebuilt from raw tool evidence. Full
        profiles never call this helper and keep autonomous report composition.
        """
        projection = self._build_recon_evidence_projection()
        rows = projection.get("devices", [])
        arp_count = sum(
            "arp_scan" in row.get("sources", [])
            for row in rows if isinstance(row, dict)
        )
        observed_ips = {
            str(row.get("ip"))
            for row in rows
            if isinstance(row, dict)
            and row.get("ip")
            and (
                "arp_scan" in row.get("sources", [])
                or "nmap_discovery" in row.get("sources", [])
                or bool(row.get("open_ports"))
            )
        }
        confirmed_count = sum(
            bool(row.get("device")) and str(row.get("ip")) in observed_ips
            for row in rows if isinstance(row, dict)
        )
        undocumented_count = sum(
            not row.get("device") and str(row.get("ip")) in observed_ips
            for row in rows if isinstance(row, dict)
        )

        try:
            from src.agent.tools.graph_tools import _scenario_topology
            declared_nodes = (_scenario_topology or {}).get("nodes", [])
        except Exception:
            declared_nodes = []
        unreachable_count = sum(
            bool(node.get("ip")) and str(node.get("ip")) not in observed_ips
            for node in declared_nodes if isinstance(node, dict)
        )

        summary = "\n".join([
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total live hosts (ARP) | {arp_count} |",
            f"| YAML devices confirmed | {confirmed_count} |",
            f"| Undocumented devices | {undocumented_count} |",
            f"| Unreachable YAML devices | {unreachable_count} |",
            "",
            "Evidence policy: this inventory is regenerated from recorded "
            "ARP and Nmap results. An unreachable host or a service marked "
            "as not observed is not treated as evidence that it is absent.",
        ])
        services = "\n".join([
            "| Device | IP | Open Ports | Key Services |",
            "|--------|----|------------|--------------|",
            *[str(row) for row in projection.get("markdown_service_rows", [])],
        ])

        summary_heading = "## 1. Summary"
        services_heading = "## 2. Discovered Services per Device"
        findings_heading = "## 3. Key Findings"
        summary_index = content.find(summary_heading)
        findings_index = content.find(findings_heading)
        if summary_index >= 0:
            preamble = content[:summary_index].rstrip()
        else:
            first_section = content.find("## ")
            preamble = (
                content[:first_section].rstrip()
                if first_section >= 0 else content.rstrip()
            )
        if findings_index >= 0:
            findings = content[findings_index:].strip()
        else:
            findings = (
                f"{findings_heading}\n\n"
                "- Review the deterministic service table above and prioritize "
                "unexpected hosts, exposed services, and failed probes."
            )
        if not preamble:
            preamble = "# Phase 2: Reconnaissance"

        return (
            f"{preamble}\n\n"
            f"{summary_heading}\n\n{summary}\n\n"
            f"{services_heading}\n\n{services}\n\n"
            f"{findings}\n"
        )

    @staticmethod
    def _validate_compact_recon_projection(
        content: str, projection: dict
    ) -> tuple[bool, str]:
        """Require every deterministic device row in compact Recon output."""
        expected_rows = [
            str(row) for row in projection.get("markdown_service_rows", [])
        ]
        missing = [row for row in expected_rows if row not in content]
        if missing:
            return False, (
                "Compact Recon output diverges from deterministic evidence: "
                f"{len(missing)} service row(s) missing"
            )
        return True, "OK"

    def _recover_compact_recon_deliverable(
        self,
        config: runtime.AgentConfig,
        tools: list[dict],
        stream_callback: Callable[[dict], None] | None = None,
    ) -> bool:
        """Save a deterministic Recon report after a compact-model save stall."""
        if config.name != "recon" or not self._uses_compact_local_moe():
            return False
        projection = self._build_recon_evidence_projection()
        if len(projection.get("devices", [])) < 2:
            return False
        save_tool = next(
            (tool for tool in tools if tool.get("name") == "save_deliverable"),
            None,
        )
        if not save_tool or not callable(save_tool.get("function")):
            return False
        draft = self._finalize_compact_recon_markdown(
            "# Phase 2: Reconnaissance\n\n"
            "**Source:** Active network scans recovered after a compact-model "
            "save stall.\n\n"
            "## 1. Summary\n\n"
            "The deterministic evidence ledger is authoritative for host and "
            "service inventory.\n\n"
            "## 2. Discovered Services per Device\n\n"
            "Service rows are regenerated from recorded ARP and Nmap outputs.\n\n"
            "## 3. Key Findings\n\n"
            "- The compact model completed the required discovery and minimum "
            "port coverage but did not emit its final save tool call.\n"
            "- This recovered report contains only observations recorded in "
            "tool_calls.jsonl; failed or missing probes are not treated as "
            "evidence that a host or service is absent.\n"
            "- Review undocumented hosts, unexpected open ports, and scan "
            "failures before beginning vulnerability analysis.\n"
        )
        args = {"filename": config.deliverable_file, "content": draft}
        if stream_callback:
            stream_callback({
                "type": "tool_call", "name": "save_deliverable", "args": args,
            })
        try:
            result = save_tool["function"](**args)
        except Exception as exc:
            log.warning("Compact Recon recovery save failed: %s", exc)
            return False
        if stream_callback:
            stream_callback({
                "type": "tool_result",
                "name": "save_deliverable",
                "result": str(result)[:2000],
            })
        validator_fn = runtime.VALIDATORS.get(config.validator, runtime.VALIDATORS["default"])
        valid, _ = validator_fn(config.deliverable_file)
        return valid
