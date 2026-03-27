"""Pipeline orchestrator — executes agents in phase sequence."""
from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import yaml

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
from src.agent.tools.skill_tools import SKILL_TOOLS, get_skills_metadata, set_skill_filter
from src.agent.validators import VALIDATORS

log = logging.getLogger(__name__)
OUTPUT_DIR = Path("output/agent")

TOOL_GROUPS: dict[str, list[dict]] = {
    "graph": GRAPH_TOOLS,
    "recon": RECON_TOOLS,
    "deliverable": DELIVERABLE_TOOLS,
    "skill": SKILL_TOOLS,
}


class Pipeline:
    """Multi-phase agent pipeline with deliverable passing and cost tracking."""

    def __init__(
        self,
        provider: LLMProvider,
        dry_run: bool = False,
        phases: list[int] | None = None,
        scenario_id: int | None = None,
        auto_teardown: bool = True,
    ):
        self.provider = provider
        self.dry_run = dry_run
        self.phases = phases
        self.scenario_id = scenario_id
        self.auto_teardown = auto_teardown
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

    def run(
        self,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> dict[str, str]:
        """Execute the full pipeline. Returns {agent_name: status} dict.

        Args:
            stream_callback: Optional callback for real-time events.
                Event types: pipeline_start, phase_start, text_chunk, tool_call,
                tool_result, turn_done, phase_done, pipeline_done.
        """
        # Load lab context (shared across all agents)
        lab = load_lab_context()
        # target_subnet: benchmark network when a scenario is active, real lab otherwise
        target_subnet = "192.168.100.0/24" if self.scenario_id is not None else "192.168.88.0/24"
        self.context = {
            "device_count": str(lab["device_count"]),
            "link_count": str(lab["link_count"]),
            "cve_count": str(lab["cve_count"]),
            "top_risk": str(lab["top_risk"]),
            "target_subnet": target_subnet,
            "scenario_context": "",
        }

        print("Loading lab context...")
        print(
            f"  Devices: {lab['device_count']}, Links: {lab['link_count']}, "
            f"CVEs: {lab['cve_count']}, Top risk: {lab['top_risk']}"
        )

        if stream_callback:
            stream_callback({
                "type": "pipeline_start",
                "device_count": lab["device_count"],
                "link_count": lab["link_count"],
                "cve_count": lab["cve_count"],
                "top_risk": lab["top_risk"],
            })

        # Load benchmark scenario context if specified
        if self.scenario_id is not None:
            scenario_context = self._load_scenario_context(self.scenario_id)
            if scenario_context:
                self.context["scenario_context"] = scenario_context
                print(f"  Benchmark scenario: S{self.scenario_id} — {scenario_context.splitlines()[0]}")

            # Save scenario metadata for evaluator
            meta = {"scenario_id": self.scenario_id, "run_dir": str(self.run_dir)}
            (self.run_dir / "scenario_meta.json").write_text(json.dumps(meta, indent=2))

            # Deploy benchmark VMs before starting the pipeline
            if not self.dry_run:
                deploy_ok = self._run_scenario_deploy(stream_callback)
                if not deploy_ok:
                    if stream_callback:
                        stream_callback({"type": "pipeline_done", "results": {}, "total_cost_usd": 0, "run_dir": str(self.run_dir)})
                    return {}

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
            status = self._run_agent(agent_config, stream_callback)
            results[agent_config.name] = status

        # Print cost summary
        self.tracker.print_summary()

        # Save cost summary to run directory
        cost_path = self.run_dir / "cost_summary.json"
        cost_path.write_text(self.tracker.to_json(), encoding="utf-8")
        log.info("Cost summary saved to %s", cost_path)

        if stream_callback:
            stream_callback({
                "type": "pipeline_done",
                "results": results,
                "total_cost_usd": round(self.tracker.total_cost(), 4),
                "run_dir": str(self.run_dir),
            })

        # Ingest run findings into ChromaDB for episodic memory
        try:
            from src.agent.knowledge.ingest import ingest_run_findings
            ingested = ingest_run_findings(self.run_dir, self.provider.model)
            if ingested:
                log.info("Ingested %d findings into run_history", ingested)
        except Exception as e:
            log.warning("Run history ingestion failed (non-fatal): %s", e)

        # Auto-teardown benchmark VMs when a scenario was deployed
        if self.scenario_id is not None and self.auto_teardown and not self.dry_run:
            self._run_teardown(stream_callback)

        return results

    def _run_playbook(self, playbook: str, stream_callback, event_type_start: str, event_type_done: str, extra_msg: str = "") -> bool:
        """Run an Ansible playbook and return True on success."""
        repo_root = Path(__file__).resolve().parents[2]
        cmd = [
            "ansible-playbook",
            f"benchmarks/ansible/playbooks/{playbook}",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={self.scenario_id}",
        ]
        print(f"\n{'=' * 60}")
        print(f"ANSIBLE: {playbook} (scenario {self.scenario_id})")
        print(f"{'=' * 60}\n")

        if stream_callback:
            stream_callback({"type": event_type_start, "scenario_id": self.scenario_id, "playbook": playbook})

        try:
            import os
            env = os.environ.copy()
            env["LANG"] = "en_US.UTF-8"
            env["LC_ALL"] = "en_US.UTF-8"
            result = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, timeout=600, env=env)
            success = result.returncode == 0
            output = (result.stdout + result.stderr)[-3000:]
            print(output)
        except subprocess.TimeoutExpired:
            success = False
            output = f"{playbook} timeout (600s)"
        except FileNotFoundError:
            success = False
            output = "ansible-playbook not found — deploy skipped"

        if stream_callback:
            stream_callback({"type": event_type_done, "scenario_id": self.scenario_id, "playbook": playbook, "success": success, "output": output})
        return success

    def _run_scenario_deploy(self, stream_callback: Callable[[dict], None] | None = None) -> bool:
        """Deploy and configure benchmark scenario VMs before pipeline starts."""
        # Pre-teardown any running scenario to avoid conflicts on shared network
        self._teardown_all_running_scenarios(stream_callback)

        # 03 — deploy VMs
        ok = self._run_playbook("03_deploy_scenario.yml", stream_callback, "deploy_start", "deploy_done")
        if not ok:
            log.error("Scenario deploy failed — aborting pipeline")
            return False
        # 04 — inject vulnerabilities
        ok = self._run_playbook("04_inject_vulns.yml", stream_callback, "inject_start", "inject_done")
        if not ok:
            log.warning("Vuln injection failed — continuing anyway")
        return True

    def _teardown_all_running_scenarios(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Teardown any currently running scenario before deploying a new one."""
        repo_root = Path(__file__).resolve().parents[2]
        # All possible scenario IDs from group_vars
        scenario_ids = [1, 2, 3, 4, 5, 6, 7]
        for sid in scenario_ids:
            if sid == self.scenario_id:
                continue  # Will be redeployed fresh
            # Check if any VM in this scenario's range exists
            import yaml as _yaml
            all_yml = repo_root / "benchmarks/ansible/group_vars/all/main.yml"
            try:
                data = _yaml.safe_load(all_yml.read_text())
                base = data["scenario_vmid_ranges"].get(str(sid))
                if not base:
                    continue
            except Exception:
                continue
            check = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "root@10.0.1.100", f"pct status {base} 2>/dev/null && echo EXISTS || true"],
                capture_output=True, text=True, timeout=10,
            )
            if "EXISTS" not in check.stdout:
                continue
            # Scenario is running — teardown
            log.info("Pre-teardown of running scenario S%d", sid)
            old_id = self.scenario_id
            self.scenario_id = sid
            self._run_teardown(stream_callback)
            self.scenario_id = old_id

    def _run_teardown(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Run 99_teardown.yml to clean up benchmark VMs after pipeline completes."""
        print(f"\n{'=' * 60}")
        print(f"TEARDOWN: Suppression du scénario S{self.scenario_id}")
        print(f"{'=' * 60}\n")

        if stream_callback:
            stream_callback({
                "type": "teardown_start",
                "scenario_id": self.scenario_id,
            })

        repo_root = Path(__file__).resolve().parents[2]
        cmd = [
            "ansible-playbook",
            "benchmarks/ansible/playbooks/99_teardown.yml",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={self.scenario_id}",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=300,
            )
            success = result.returncode == 0
            output = result.stdout[-2000:] if result.stdout else result.stderr[-2000:]
            print(output)
        except subprocess.TimeoutExpired:
            success = False
            output = "Teardown timeout (300s)"
            log.error("Teardown timeout for scenario %d", self.scenario_id)
        except FileNotFoundError:
            success = False
            output = "ansible-playbook not found — teardown skipped"
            log.warning("ansible-playbook not in PATH, skipping teardown")

        if stream_callback:
            stream_callback({
                "type": "teardown_done",
                "scenario_id": self.scenario_id,
                "success": success,
                "output": output,
            })

    def _load_scenario_context(self, scenario_id: int) -> str:
        """Load benchmark scenario IPs from ground_truth YAML and return a context string."""
        gt_path = Path("benchmarks/ground_truth") / f"scenario_{scenario_id}.yaml"
        if not gt_path.exists():
            log.warning("Scenario ground truth not found: %s", gt_path)
            return ""
        data = yaml.safe_load(gt_path.read_text())
        lines = [
            f"## Benchmark scenario S{scenario_id}: {data.get('scenario_name', '')}",
            f"Scan network: 192.168.100.0/24 (NOT 192.168.88.0/24 — that is the physical lab)",
            f"Gateway: 192.168.100.1 (OpenWrt router)",
            "Known target hosts (scan ALL of them):",
        ]
        router = data.get("topology", {}).get("router", {})
        if router:
            lines.append(f"  - {router.get('name', 'router')} ({router.get('ip', '192.168.100.1')}) — role: router")
        for svc in data.get("topology", {}).get("services", []):
            lines.append(f"  - {svc['name']} ({svc['ip']}) — role: {svc['role']}")
        return "\n".join(lines)

    def _run_agent(self, config: AgentConfig, stream_callback: Callable[[dict], None] | None = None) -> str:
        """Run a single agent phase."""
        # Set skill filter for this phase (hard filtering)
        filter_tags = config.skill_filter.get("tags") if config.skill_filter else None
        set_skill_filter(filter_tags)

        # If this phase has device sub-agents, run them first
        if config.has_device_agents:
            self._run_device_agents(config, stream_callback)

        tools = self._resolve_tools(config)

        # Build prompt variables
        variables = {**self.context}
        variables["previous_deliverables"] = self._list_previous_deliverables()
        variables["expected_deliverable"] = config.deliverable_file
        variables["available_skills"] = self._filter_skills(config)

        # Inject deliverable template if one exists
        template_path = Path(__file__).parent / "templates" / config.deliverable_file
        if template_path.exists():
            template = template_path.read_text(encoding="utf-8")
            template = template.replace("{{run_date}}", self.run_dir.name)
            template = template.replace("{{model}}", self.provider.model)
            variables["deliverable_template"] = template

        # Load and compose prompt
        system_prompt = load_prompt(config.prompt_template, variables)

        # Print header
        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: {config.name.upper()}")
        print(f"  {config.description}")
        print(f"  Tools: {config.tools}")
        print(f"  Deliverable: {config.deliverable_file}")
        print(f"{'=' * 60}\n")

        if stream_callback:
            stream_callback({
                "type": "phase_start",
                "phase": config.phase,
                "name": config.name,
                "description": getattr(config, "description", ""),
                "deliverable": config.deliverable_file,
            })

        # Run agent with cost tracking
        self.tracker.start_phase(config.name)
        result_text = self.provider.chat_with_tools(
            system_prompt=system_prompt,
            user_message=config.user_message,
            tools=tools,
            max_turns=config.max_turns,
            max_tokens=config.max_tokens,
            cost_tracker=self.tracker,
            stream_callback=stream_callback,
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

        status = "completed" if valid else f"failed:{msg}"

        if valid:
            log.info("Phase %d deliverable validated: %s", config.phase, msg)
            print(f"  Deliverable validated: {config.deliverable_file}")
        else:
            log.error("Phase %d deliverable FAILED: %s", config.phase, msg)
            print(f"  Deliverable FAILED validation: {msg}")
            print(f"  LLM final output: {result_text[:500]}")

        if stream_callback:
            stream_callback({
                "type": "phase_done",
                "phase": config.phase,
                "name": config.name,
                "status": status,
                "deliverable": config.deliverable_file,
                "cost_usd": round(usage.cost_usd(self.tracker.model), 4) if usage else 0,
                "turns": usage.turns if usage else 0,
            })

        return status

    def _run_device_agents(self, config: AgentConfig, stream_callback: Callable[[dict], None] | None = None) -> None:
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

        # Compute once — these are the same for all device sub-agents
        available_skills = self._filter_skills(config)
        previous_deliverables = self._list_previous_deliverables()

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
            variables["previous_deliverables"] = previous_deliverables
            variables["expected_deliverable"] = deliverable_file
            variables["available_skills"] = available_skills
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
                    f"Analyze vulnerabilities for device {device_id} ({device_ip}). "
                    f"Services: {services_str}. "
                    f"Save your deliverable to {deliverable_file}."
                ),
                tools=tools,
                max_turns=config.max_turns,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
                stream_callback=stream_callback,
            )
            usage = self.tracker.end_phase()

            if usage:
                print(
                    f"      Done: {usage.turns} turns, "
                    f"${usage.cost_usd(self.tracker.model):.4f}"
                )

    def _resolve_tools(self, config: AgentConfig) -> list[dict]:
        """Resolve tool references to actual tool definitions.

        Supports two resolution modes:
          1. Group name (e.g. "graph", "recon") → expand entire group
          2. Individual tool name (e.g. "nmap_scan") → find in any group

        Tool functions are wrapped to log calls and results to tool_calls.jsonl.
        """
        tools = []
        seen_names: set[str] = set()

        for ref in config.tools:
            if ref == "recon" and self.dry_run:
                continue

            # Try group resolution first
            if ref in TOOL_GROUPS:
                for tool in TOOL_GROUPS[ref]:
                    if tool["name"] not in seen_names:
                        tools.append(self._wrap_tool(tool))
                        seen_names.add(tool["name"])
                continue

            # Fall back to individual tool name lookup
            for group in TOOL_GROUPS.values():
                for tool in group:
                    if tool["name"] == ref and ref not in seen_names:
                        tools.append(self._wrap_tool(tool))
                        seen_names.add(ref)
                        break

        return tools

    def _wrap_tool(self, tool: dict) -> dict:
        """Wrap a tool function to log its calls and results to tool_calls.jsonl."""
        original_fn = tool["function"]
        if original_fn is None:
            return tool

        log_path = self.run_dir / "tool_calls.jsonl"
        tool_name = tool["name"]

        def logged_fn(**kwargs):
            result = original_fn(**kwargs)
            try:
                entry = json.dumps({
                    "tool": tool_name,
                    "args": kwargs,
                    "result": result[:5000] if isinstance(result, str) else str(result)[:5000],
                }, ensure_ascii=False, default=str)
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(entry + "\n")
            except Exception:
                pass  # Never break the pipeline for logging
            return result

        return {**tool, "function": logged_fn}

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

    def _filter_skills(self, config: AgentConfig) -> str:
        """Filter skills by tag intersection with config.skill_filter.

        Returns a formatted string listing matching skills for prompt injection.
        """
        if not config.skill_filter:
            return ""

        filter_tags = set(config.skill_filter.get("tags", []))
        if not filter_tags:
            return ""

        matched = [
            skill for skill in get_skills_metadata()
            if set(skill.get("tags", [])) & filter_tags
        ]

        if not matched:
            return "No matching skills for this phase."

        lines = []
        for s in matched:
            tags_str = ", ".join(s["tags"])
            lines.append(f"- **{s['name']}**: {s['description']} (tags: {tags_str})")

        return "\n".join(lines)

    def _list_previous_deliverables(self) -> str:
        """List available deliverables for prompt variable."""
        if not self.run_dir.exists():
            return "None (first phase)"
        files = sorted(f.name for f in self.run_dir.glob("*") if f.is_file())
        return ", ".join(files) if files else "None (first phase)"
