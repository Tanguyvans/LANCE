"""Pipeline orchestrator — executes agents in phase sequence."""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from src.agent.registry import AGENTS, AgentConfig
from src.agent.provider import LLMProvider
from src.agent.prompt_manager import load_prompt
from src.agent.cost_tracker import CostTracker
from src.agent.tools.graph_tools import (
    GRAPH_TOOLS,
    load_lab_context,
    get_attack_surface,
    get_risk_scores,
    get_device_info,
)
from src.agent.tools.recon_tools import RECON_TOOLS
from src.agent.tools.deliverable import DELIVERABLE_TOOLS, set_output_dir
from src.agent.validators import VALIDATORS

log = logging.getLogger(__name__)
OUTPUT_DIR = Path("output/agent")

TOOL_GROUPS: dict[str, list[dict]] = {
    "graph": GRAPH_TOOLS,
    "recon": RECON_TOOLS,
    "deliverable": DELIVERABLE_TOOLS,
}


class Pipeline:
    """Multi-phase agent pipeline with deliverable passing and cost tracking."""

    def __init__(
        self,
        provider: LLMProvider,
        dry_run: bool = False,
        phases: list[int] | None = None,
    ):
        self.provider = provider
        self.dry_run = dry_run
        self.phases = phases
        self.tracker = CostTracker(model=provider.model)
        self.context: dict = {}

        # Create timestamped run directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.run_dir = OUTPUT_DIR / timestamp
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Point deliverable tools and validators at this run dir
        set_output_dir(self.run_dir)
        import src.agent.validators as val_mod
        val_mod.OUTPUT_DIR = self.run_dir

    def run(self) -> dict[str, str]:
        """Execute the full pipeline. Returns {agent_name: status} dict."""
        # Load lab context (shared across all agents)
        lab = load_lab_context()
        self.context = {
            "device_count": str(lab["device_count"]),
            "link_count": str(lab["link_count"]),
            "cve_count": str(lab["cve_count"]),
            "top_risk": str(lab["top_risk"]),
        }

        print("Loading lab context...")
        print(
            f"  Devices: {lab['device_count']}, Links: {lab['link_count']}, "
            f"CVEs: {lab['cve_count']}, Top risk: {lab['top_risk']}"
        )

        # Get agents sorted by phase
        agents = sorted(AGENTS.values(), key=lambda a: a.phase)
        if self.phases:
            agents = [a for a in agents if a.phase in self.phases]

        results: dict[str, str] = {}

        for agent_config in agents:
            # Check prerequisites
            if not self._check_prerequisites(agent_config, results):
                log.warning("Skipping %s: prerequisites not met", agent_config.name)
                results[agent_config.name] = "skipped:prerequisites"
                continue

            # Check conditional execution
            if not self._check_conditional(agent_config):
                log.info(
                    "Skipping %s: conditional check failed (empty queue)",
                    agent_config.name,
                )
                results[agent_config.name] = "skipped:conditional"
                continue

            # Run the agent
            status = self._run_agent(agent_config)
            results[agent_config.name] = status

        # Print cost summary
        self.tracker.print_summary()

        # Save cost summary to run directory
        cost_path = self.run_dir / "cost_summary.json"
        cost_path.write_text(self.tracker.to_json(), encoding="utf-8")
        log.info("Cost summary saved to %s", cost_path)

        return results

    def _run_agent(self, config: AgentConfig) -> str:
        """Run a single agent phase."""
        # If this phase has device sub-agents, run them first
        if config.has_device_agents:
            self._run_device_agents(config)

        tools = self._resolve_tools(config)

        # Build prompt variables
        variables = {**self.context}
        variables["previous_deliverables"] = self._list_previous_deliverables()
        variables["expected_deliverable"] = config.deliverable_file

        # Load and compose prompt
        system_prompt = load_prompt(config.prompt_template, variables)

        # Print header
        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: {config.name.upper()}")
        print(f"  {config.description}")
        print(f"  Tools: {config.tools}")
        print(f"  Deliverable: {config.deliverable_file}")
        print(f"{'=' * 60}\n")

        # Run agent with cost tracking
        self.tracker.start_phase(config.name)
        result_text = self.provider.chat_with_tools(
            system_prompt=system_prompt,
            user_message=config.user_message,
            tools=tools,
            max_turns=config.max_turns,
            max_tokens=config.max_tokens,
            cost_tracker=self.tracker,
        )
        usage = self.tracker.end_phase()

        if usage:
            print(
                f"\n  Phase {config.phase} done: {usage.turns} turns, "
                f"${usage.cost_usd(self.tracker.model):.4f}"
            )

        # Validate deliverable
        validator_fn = VALIDATORS.get(config.validator, VALIDATORS["default"])
        valid, msg = validator_fn(config.deliverable_file)

        if valid:
            log.info("Phase %d deliverable validated: %s", config.phase, msg)
            print(f"  Deliverable validated: {config.deliverable_file}")
            return "completed"
        else:
            log.error("Phase %d deliverable FAILED: %s", config.phase, msg)
            print(f"  Deliverable FAILED validation: {msg}")
            print(f"  LLM final output: {result_text[:500]}")
            return f"failed:{msg}"

    def _run_device_agents(self, config: AgentConfig) -> None:
        """Run per-device sub-agents before the aggregator phase."""
        # Get devices with services from the attack surface
        surface = json.loads(get_attack_surface())
        scores_raw = json.loads(get_risk_scores())
        scores_by_id = {s["device_id"]: s for s in scores_raw}

        tools = self._resolve_tools(config)

        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: DEVICE SUB-AGENTS")
        print(f"  Launching {len(surface)} device-specific vulnerability agents")
        print(f"{'=' * 60}\n")

        for device in surface:
            device_id = device["id"]
            device_ip = device.get("ip", "unknown")
            device_type = device.get("type", "unknown")
            services = device.get("services", [])
            score_info = scores_by_id.get(device_id, {})

            # Get detailed device info for CVEs
            device_detail = json.loads(get_device_info(device_id))
            device_os = device_detail.get("os_version", device_detail.get("firmware", "unknown"))

            # Build services string
            services_str = ", ".join(
                f"{s.get('name', 'unknown')}:{s.get('port', '?')}"
                + (f" v{s['version']}" if s.get("version") else "")
                for s in services
            )

            # Build known CVEs string from risk scores
            known_cves = str(score_info.get("cve_count", 0)) + " CVEs"
            risk_score = str(score_info.get("risk_score", 0.0))

            deliverable_file = f"03_device_{device_id}.json"

            # Build variables for per-device prompt
            variables = {**self.context}
            variables["previous_deliverables"] = self._list_previous_deliverables()
            variables["expected_deliverable"] = deliverable_file
            variables["device_id"] = device_id
            variables["device_ip"] = device_ip
            variables["device_type"] = device_type
            variables["device_services"] = services_str
            variables["device_os"] = device_os
            variables["device_risk_score"] = risk_score
            variables["device_known_cves"] = known_cves

            system_prompt = load_prompt("vuln_device", variables)
            phase_name = f"vuln_{device_id}"

            print(f"  --- Sub-agent: {phase_name} ({device_ip}) ---")
            print(f"      Services: {services_str}")

            self.tracker.start_phase(phase_name)
            self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Analyse les vulnérabilités du device {device_id} ({device_ip}). "
                    f"Services : {services_str}. "
                    f"Sauvegarde ton livrable dans {deliverable_file}."
                ),
                tools=tools,
                max_turns=config.max_turns,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
            )
            usage = self.tracker.end_phase()

            if usage:
                print(
                    f"      Done: {usage.turns} turns, "
                    f"${usage.cost_usd(self.tracker.model):.4f}"
                )

    def _resolve_tools(self, config: AgentConfig) -> list[dict]:
        """Resolve tool group names to actual tool definitions."""
        tools = []
        for group_name in config.tools:
            if group_name == "recon" and self.dry_run:
                continue
            group = TOOL_GROUPS.get(group_name, [])
            tools.extend(group)
        return tools

    def _check_prerequisites(
        self, config: AgentConfig, results: dict[str, str]
    ) -> bool:
        """Check that all prerequisite deliverables exist or were skipped."""
        for prereq_name in config.prerequisites:
            status = results.get(prereq_name)
            if status in ("completed", "skipped:conditional"):
                continue
            # If prerequisite wasn't run yet, check deliverable on disk
            prereq_config = AGENTS.get(prereq_name)
            if prereq_config:
                path = self.run_dir / prereq_config.deliverable_file
                if not path.exists():
                    return False
        return True

    def _check_conditional(self, config: AgentConfig) -> bool:
        """Check conditional execution (e.g., vuln queue non-empty)."""
        if not config.conditional:
            return True
        path = self.run_dir / config.conditional
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            vulns = data.get("vulnerabilities", [])
            return len(vulns) > 0
        except (json.JSONDecodeError, KeyError):
            return False

    def _list_previous_deliverables(self) -> str:
        """List available deliverables for prompt variable."""
        if not self.run_dir.exists():
            return "Aucun (première phase)"
        files = sorted(f.name for f in self.run_dir.glob("*") if f.is_file())
        return ", ".join(files) if files else "Aucun (première phase)"
