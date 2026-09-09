"""Scenario preparation, deployment ownership and teardown for one run."""
from __future__ import annotations
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
import os
import subprocess
import time
import yaml
import logging
from src.agent.core import runtime


log = logging.getLogger(__name__)


class ScenarioLifecycle:
    """Phase operations using the shared run state; no independent lifecycle."""

    def run_deploy_only(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Deploy benchmark scenario VMs without running any pentest phase.

        Runs Ansible deploy + inject + verify, then emits pipeline_done so the
        frontend closes the SSE connection cleanly.
        """
        if not self.scenario_id:
            if stream_callback:
                stream_callback({"type": "error", "message": "deploy_only requiert un scenario_id"})
                stream_callback({"type": "pipeline_done", "status": "failed", "results": {}, "total_cost_usd": 0, "run_dir": str(self.run_dir)})
            return
        if stream_callback:
            stream_callback({"type": "pipeline_start", "device_count": 0, "link_count": 0, "cve_count": 0, "top_risk": None, "execution_profile": self.execution_profile.name})
        success = self._run_scenario_deploy(stream_callback)
        if stream_callback:
            stream_callback({
                "type": "pipeline_done",
                "results": {"deploy": "completed" if success else "failed"},
                "status": "completed" if success else "failed",
                "total_cost_usd": 0,
                "run_dir": str(self.run_dir),
            })

    def _run_playbook(self, playbook: str, stream_callback, event_type_start: str, event_type_done: str) -> bool:
        """Run an Ansible playbook and return True on success."""
        repo_root = runtime.REPO_ROOT
        deployment = self._generated_deployment
        cmd = [
            "ansible-playbook",
            f"benchmarks/ansible/playbooks/{playbook}",
            "-i", "benchmarks/ansible/inventory.yml",
            "--vault-password-file", "/root/.vault_pass",
            "--extra-vars", f"scenario_id={self.scenario_id}",
        ]
        if deployment is not None:
            cmd.extend(["--extra-vars", f"@{deployment.overlay_path}"])
            source_scenario_id = deployment.source_scenario_id
        else:
            source_scenario_id = str(self.scenario_id)
        cmd.extend(["--extra-vars", f"source_scenario_id={source_scenario_id}"])
        print(f"\n{'=' * 60}")
        print(f"ANSIBLE: {playbook} (scenario {self.scenario_id})")
        print(f"{'=' * 60}\n")

        attempts = getattr(self, "_ansible_attempts", {})
        self._ansible_attempts = attempts
        attempts[playbook] = attempts.get(playbook, 0) + 1
        timestamp = datetime.now(timezone.utc).isoformat()
        context = {
            "scenario_id": self.scenario_id, "playbook": playbook,
            "attempt": attempts[playbook], "timestamp": timestamp,
        }
        if stream_callback:
            stream_callback({"type": event_type_start, **context})

        full_output = ""
        returncode = None
        timed_out = False
        started = time.monotonic()
        try:
            env = os.environ.copy()
            env["LANG"] = "en_US.UTF-8"
            env["LC_ALL"] = "en_US.UTF-8"
            # Large scenarios (S11/S12/S13 = 15-35 VMs) on a slow Proxmox can take
            # well over 10 min to clone. Configurable via ANSIBLE_PLAYBOOK_TIMEOUT.
            pb_timeout = int(os.environ.get("ANSIBLE_PLAYBOOK_TIMEOUT", "1800"))
            result = subprocess.run(cmd, cwd=str(repo_root), capture_output=True, text=True, timeout=pb_timeout, env=env)
            success = result.returncode == 0
            returncode = result.returncode
            full_output = result.stdout + result.stderr
        except subprocess.TimeoutExpired as exc:
            success = False
            timed_out = True
            # TimeoutExpired may contain bytes even with text=True. Preserve
            # the task output preceding the timeout instead of discarding it.
            for part in (exc.stdout, exc.stderr):
                full_output += part.decode("utf-8", errors="replace") if isinstance(part, bytes) else (part or "")
            full_output += f"\n{playbook} timeout ({pb_timeout}s)"
        except FileNotFoundError:
            success = False
            full_output = "ansible-playbook not found — opération non exécutée"

        duration = round(time.monotonic() - started, 3)
        output = full_output[-10000:]
        print(output, flush=True)

        log_file = None
        try:
            log_path = self.run_dir / f"ansible_{playbook.replace('.yml', '')}.log"
            # Append: a cleanup retry must not erase the first failure.
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(f"\n[{timestamp}] {playbook} — S{self.scenario_id} — tentative {context['attempt']}\n")
                handle.write(full_output)
                handle.write(f"\nRésultat: success={success} returncode={returncode} timeout={timed_out} duration_s={duration}\n")
            log_file = log_path.name
        except OSError:
            log.exception("Could not save Ansible log for %s", playbook)

        if stream_callback:
            stream_callback({
                "type": event_type_done, **context,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "success": success, "output": output, "returncode": returncode,
                "duration_s": duration, "timed_out": timed_out,
                "log_file": log_file, "log_saved": log_file is not None,
                "output_truncated": len(full_output) > len(output),
            })
        return success

    def _run_scenario_deploy(self, stream_callback: Callable[[dict], None] | None = None) -> bool:
        """Deploy and configure benchmark scenario VMs before pipeline starts."""
        if self.scenario_id is not None:
            scenario_id = str(self.scenario_id)
            export_store = runtime.default_export_store()
            if export_store.exists(scenario_id):
                exported = export_store.load(scenario_id)
                if exported["manifest"].get("mutation_policy") == "manual":
                    self._generated_deployment = runtime.ManualScenarioDeployment.prepare(
                        scenario_id, export_store=export_store
                    )
                else:
                    self._generated_deployment = runtime.GeneratedScenarioDeployment.prepare(scenario_id)
            elif runtime.ManualScenarioDeployment.exists(scenario_id):
                self._generated_deployment = runtime.ManualScenarioDeployment.prepare(scenario_id)
        # Pre-teardown any running scenario to avoid conflicts on shared network
        self._teardown_all_running_scenarios(stream_callback)

        # 03 — deploy VMs
        # From this point even an exception can leave partially created VMs.
        self._scenario_owned = True
        ok = self._run_playbook("03_deploy_scenario.yml", stream_callback, "deploy_start", "deploy_done")
        if not ok:
            log.error("Scenario deploy failed — aborting pipeline")
            self._run_teardown(stream_callback)
            return False
        # 04 — inject vulnerabilities
        ok = self._run_playbook("04_inject_vulns.yml", stream_callback, "inject_start", "inject_done")
        if not ok:
            log.error("Vuln injection failed — aborting pipeline and cleaning scenario")
            self._run_teardown(stream_callback)
            return False
        # 06 — verify all vulns are present before running the LLM. Benchmark
        # scoring is invalid when the expected vulnerable state is incomplete.
        ok_verify = self._run_playbook("06_verify.yml", stream_callback, "verify_start", "verify_done")
        if not ok_verify:
            log.error("Vuln verification failed — aborting pipeline and cleaning scenario")
            self._run_teardown(stream_callback)
            return False
        return True

    def _teardown_all_running_scenarios(self, stream_callback: Callable[[dict], None] | None = None) -> None:
        """Teardown any currently running scenario before deploying a new one."""
        repo_root = runtime.REPO_ROOT
        current_scenario_id = str(self.scenario_id) if self.scenario_id is not None else None

        # Generated variants use dynamic VMID ranges, so they are tracked by
        # local leases rather than by the official numeric catalogue.
        for active in runtime.GeneratedScenarioDeployment.active_leases():
            if active.scenario_id == current_scenario_id:
                continue
            log.info("Pre-teardown of running generated scenario %s", active.scenario_id)
            old_id, old_deployment = self.scenario_id, self._generated_deployment
            self.scenario_id = active.scenario_id
            self._generated_deployment = active
            self._run_teardown(stream_callback)
            self.scenario_id, self._generated_deployment = old_id, old_deployment

        # Load the historical inventory and the independently versioned v2
        # additions. main.yml is intentionally kept host-local on the master VM.
        all_yml = repo_root / "benchmarks/ansible/group_vars/all/main.yml"
        v2_yml = repo_root / "benchmarks/ansible/group_vars/all/scenarios_v2.yml"
        try:
            _all_data = yaml.safe_load(all_yml.read_text(encoding="utf-8")) or {}
            _v2_data = yaml.safe_load(v2_yml.read_text(encoding="utf-8")) or {}
            scenario_ranges = {
                **_all_data.get("scenario_vmid_ranges", {}),
                **_v2_data.get("scenario_vmid_ranges_v2", {}),
            }
            scenario_ids = [int(k) for k in scenario_ranges]
        except Exception:
            scenario_ranges = {}
            scenario_ids = list(range(1, 11))

        # Read Proxmox host IP from inventory (single source of truth)
        proxmox_host = "192.168.88.100"
        try:
            inv_yml = repo_root / "benchmarks/ansible/inventory.yml"
            inv = yaml.safe_load(inv_yml.read_text(encoding="utf-8"))
            proxmox_host = inv["all"]["hosts"]["proxmox"]["ansible_host"]
        except Exception:
            pass

        if stream_callback:
            stream_callback({"type": "info", "message": (
                f"Préparation S{self.scenario_id} : recherche des scénarios existants "
                f"sur {proxmox_host} (SSH), avant déploiement."
            )})
        ssh_failure_reported = False
        for sid in scenario_ids:
            if sid == self.scenario_id:
                continue  # Will be redeployed fresh
            # Check if any VM in this scenario's range exists
            try:
                base = scenario_ranges.get(str(sid))
                if not base:
                    continue
            except Exception:
                continue
            check = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
                 f"root@{proxmox_host}", f"(qm status {base} 2>/dev/null || pct status {base} 2>/dev/null) && echo EXISTS || true"],
                capture_output=True, text=True, timeout=10,
            )
            if check.returncode != 0 and not ssh_failure_reported:
                ssh_failure_reported = True
                if stream_callback:
                    stream_callback({"type": "warn", "message": (
                        f"Préparation : contrôle SSH impossible sur {proxmox_host}. "
                        "L'état des scénarios existants n'a pas pu être vérifié."
                    ), "output": check.stderr[-2000:]})
            if "EXISTS" not in check.stdout:
                continue
            # Scenario is running — teardown
            log.info("Pre-teardown of running scenario S%d", sid)
            old_id = self.scenario_id
            self.scenario_id = sid
            self._run_teardown(stream_callback)
            self.scenario_id = old_id

    def _run_teardown(self, stream_callback: Callable[[dict], None] | None = None) -> bool:
        """Run 99_teardown.yml to clean up benchmark VMs after pipeline completes."""
        if self._generated_deployment is None and self.scenario_id is not None:
            self._generated_deployment = runtime.GeneratedScenarioDeployment.from_lease(str(self.scenario_id))
        deployment = self._generated_deployment
        success = self._run_playbook("99_teardown.yml", stream_callback, "teardown_start", "teardown_done")
        if success and deployment is not None:
            deployment.release()
            if self._generated_deployment is deployment:
                self._generated_deployment = None
        if success:
            self._scenario_owned = False
        return success

    def _save_ground_truth(self):
        """Generate a custom development GT after the worker has finished.

        Preset ground truths stay in the evaluator store and are never copied to
        an active run directory.  Sealed runs are categorically forbidden here.
        """
        import shutil

        if self.sealed:
            raise RuntimeError("Ground truth access is forbidden in sealed workers")

        gt_dest = self.run_dir / "ground_truth.yaml"

        if self.custom_config:
            # Custom mode: generate GT dynamically from selected packs/vulns
            gt = self._generate_custom_gt()
            if gt:
                gt_dest.write_text(yaml.dump(gt, default_flow_style=False, allow_unicode=True, sort_keys=False))
                log.info("Custom ground truth generated: %d vulns", len(gt.get("vulnerabilities", [])))
                return

        # Legacy helper for explicit post-run development workflows only.  The
        # normal preset pipeline does not call this branch anymore.
        gt_path = runtime.resolve_ground_truth_path(self.scenario_id)
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
        """Build informed-mode context from public scenario/topology YAML only."""
        sid = str(scenario_id)
        scenario_path = runtime.resolve_scenario_path(sid)
        if not scenario_path.exists():
            log.warning("Public scenario definition not found: %s", scenario_path)
            return ""
        scenario = yaml.safe_load(scenario_path.read_text()) or {}
        topology_id = scenario.get("topology")
        topology_path = runtime.resolve_topology_path(sid, str(topology_id or ""))
        if not topology_id or not topology_path.exists():
            log.warning("Public topology not found: %s", topology_path)
            return ""
        topology = yaml.safe_load(topology_path.read_text()) or {}

        raw_subnets = topology.get("subnets")
        if not raw_subnets:
            raw_subnets = []
            for item in [topology.get("router", {}), *topology.get("services", [])]:
                ip = item.get("ip")
                if not ip:
                    continue
                parts = str(ip).split(".")
                if len(parts) == 4:
                    subnet = ".".join(parts[:3]) + ".0/24"
                    if subnet not in raw_subnets:
                        raw_subnets.append(subnet)
        raw_subnets = raw_subnets or [runtime.BENCHMARK_SUBNET]
        router = topology.get("router", {})
        router_ip = router.get("ip", "192.168.100.1")
        subnets_str = ", ".join(raw_subnets)
        mgmt_exclusion = "NOT 192.168.88.0/24 (physical lab) nor 192.168.100.0/24 (management)"
        lines = [
            f"## Benchmark scenario S{scenario_id}: {scenario.get('name', '')}",
            f"Scan networks: {subnets_str} ({mgmt_exclusion})",
            f"Gateway/router: {router_ip} (OpenWrt router — management IP 192.168.100.1 is NOT a scan target)",
            "Known target hosts — scan ALL using the VLAN IPs below (not 192.168.100.x):",
        ]
        if router:
            router_name = (router.get("name") or router.get("name_template", "s{sid}-router")).format(sid=sid)
            lines.append(f"  - {router_name} ({router_ip}) — role: router")
        for svc in topology.get("services", []):
            name = (svc.get("name") or svc.get("name_template", "s{sid}-device")).format(sid=sid)
            lines.append(f"  - {name} ({svc['ip']}) — role: {svc['role']}")
        return "\n".join(lines)

    def _load_scenario_tool_policy(self, scenario_id: int | str | None) -> dict:
        """Load an authored tool allowlist without consulting Ground Truth."""
        if scenario_id is None:
            return {}
        try:
            scenario_path = runtime.resolve_scenario_path(scenario_id)
            if not scenario_path.exists():
                return {}
            scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8")) or {}
            policy = scenario.get("tool_policy", {})
            return policy if isinstance(policy, dict) else {}
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            log.warning("Unable to load tool policy for scenario %s: %s", scenario_id, exc)
            return {}

    def _load_scenario_runtime_limits(self, scenario_id: int | str | None) -> None:
        """Load execution limits authored by the Scenario Lab.

        A scenario budget can only narrow the process-level budget. This keeps
        manual/generated scenarios from granting themselves more calls than a
        sealed execution context or an operator configured on the pipeline.
        """
        if scenario_id is None:
            return
        try:
            scenario_path = runtime.resolve_scenario_path(scenario_id)
            if not scenario_path.exists():
                return
            scenario = yaml.safe_load(scenario_path.read_text(encoding="utf-8")) or {}
            if not isinstance(scenario, dict):
                return
            self.scenario_lab_config = {
                key: scenario.get(key)
                for key in (
                    "lifecycle", "environment", "identity", "detection", "evaluation",
                    "objectives", "constraints", "compatibility", "data_fixtures",
                    "failure_modes",
                )
                if scenario.get(key) not in (None, {}, [])
            }
            metadata = scenario.get("metadata")
            metadata = metadata if isinstance(metadata, dict) else {}
            budget = scenario.get("tool_budget") or metadata.get("tool_budget") or {}
            if isinstance(budget, dict):
                value = budget.get("max_calls", budget.get("max_tool_calls"))
                if not isinstance(value, bool) and value is not None:
                    value = int(value)
                    if value < 1:
                        raise ValueError("max_calls must be >= 1")
                    self.max_tool_calls = (
                        value if self.max_tool_calls is None
                        else min(self.max_tool_calls, value)
                    )
            execution_constraints = (
                self.scenario_lab_config.get("constraints", {}).get("execution", {})
                if isinstance(self.scenario_lab_config.get("constraints"), dict)
                else {}
            )
            attempt_budget = execution_constraints.get("attempt_budget", {})
            if isinstance(attempt_budget, dict):
                attempts = attempt_budget.get("max_attempts", attempt_budget.get("max_calls"))
                if attempts is not None and not isinstance(attempts, bool):
                    attempts = int(attempts)
                    if attempts >= 1:
                        self.max_tool_calls = (
                            attempts if self.max_tool_calls is None
                            else min(self.max_tool_calls, attempts)
                        )
        except (OSError, UnicodeError, ValueError, TypeError, yaml.YAMLError) as exc:
            log.warning("Unable to load tool budget for scenario %s: %s", scenario_id, exc)
