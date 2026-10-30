"""Controller for one public, reset-before-each-arm D1/A1 pair.

Workers receive only validate_inventory's public input. Oracles are resolved
after both workers have ended, through the existing read-only comparator.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from types import SimpleNamespace
from uuid import uuid4

import yaml

from src.agent.audit_experiment import digest, validate_inventory
from src.benchmark.lab_lock import LabWaitCancelled, reserve_lab
from src.benchmark.scenario_exports import resolve_scenario_path, resolve_topology_path
from src.benchmark.tool_registry import ROLE_SERVICES

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output" / "policy_comparisons"


class PairPreparationError(RuntimeError):
    """Controller-authored diagnostic safe to show to the operator."""


def now():
    return datetime.now(timezone.utc).isoformat()


def public_spec(scenario_id: str) -> dict:
    from src.agent.batch import _parse_single_scenario_id
    sid = _parse_single_scenario_id(scenario_id)
    path = resolve_scenario_path(sid)
    scenario = yaml.safe_load(path.read_text(encoding="utf-8"))
    topology_path = resolve_topology_path(sid, scenario["topology"])
    topology = yaml.safe_load(topology_path.read_text(encoding="utf-8"))
    devices = []
    for raw, role in [(topology.get("router", {}), "router"),
                      *((item, item.get("role", "")) for item in topology.get("services", []))]:
        services = [{"name": item["name"], "port": item["port"], "protocol": "tcp"}
                    for item in ROLE_SERVICES.get(role, []) if item.get("protocol", "tcp") == "tcp"]
        if not raw.get("ip") or not services:
            raise ValueError("La topologie doit déclarer une adresse et des services TCP publics pour chaque équipement.")
        address = ipaddress.IPv4Address(raw["ip"])
        name = (raw.get("name") or raw.get("name_template", "s{sid}-router")).format(sid=sid)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
            raise ValueError("Identifiant d’équipement public invalide.")
        devices.append({"id": name, "ip": str(address), "role": role, "services": services})
    networks = {str(ipaddress.ip_network(f"{d['ip']}/24", strict=False)) for d in devices}
    if len(networks) != 1 or not devices or len(devices) > 64:
        raise ValueError("Ce parcours exige 1 à 64 équipements TCP dans un seul sous-réseau /24 public.")
    if len({d["id"] for d in devices}) != len(devices) or len({d["ip"] for d in devices}) != len(devices):
        raise ValueError("Les identifiants et adresses publics doivent être uniques.")
    # Includes authored configuration hashes, never its vulnerability content.
    import hashlib
    return {"scenario_id": sid, "name": scenario.get("name", sid), "devices": devices,
            "target_network": networks.pop(), "definition_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "topology_sha256": hashlib.sha256(topology_path.read_bytes()).hexdigest()}


def runtime_readiness() -> dict:
    from src.agent.core.runtime import tailscale_identity_present
    ready = (bool(os.environ.get("LANCE_LAB_LOCK")) and tailscale_identity_present()
             and bool(shutil.which("ansible-playbook")) and bool(shutil.which("nmap")))
    return {"available": ready, "reason": None if ready else
            "Le lancement exige le contrôleur nato, sa réservation de laboratoire, Ansible et Nmap."}


def verify_nato():
    if not runtime_readiness()["available"]:
        raise PairPreparationError("Le contrôleur nato n’est pas disponible.")
    inventory = yaml.safe_load((ROOT / "benchmarks/ansible/inventory.yml").read_text())
    host = str(ipaddress.ip_address(inventory["all"]["hosts"]["proxmox"]["ansible_host"]))
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                             f"root@{host}", "hostname"], capture_output=True, text=True, timeout=10)
    if result.returncode or result.stdout.strip() not in {"nato", "pve-nato"}:
        raise PairPreparationError("L’identité du nœud nato / pve-nato n’a pas pu être vérifiée.")


class PairRunner:
    def __init__(self, config: dict, *, root: Path | None = None):
        self.config = config
        self.spec = public_spec(config["scenario_id"])
        self.id = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H%M%S_") + uuid4().hex[:12]
        self.path = (root or OUTPUT) / self.id
        self.path.mkdir(parents=True)
        order = ["llm", "rules"] if config["comparison_order"] == "llm-first" else ["rules", "llm"]
        self.data = {"schema_version": 1, "id": self.id, "status": "pending", "started_at": now(),
                     "finished_at": None, "scenario": {"id": self.spec["scenario_id"], "name": self.spec["name"]},
                     "config": config, "order": order, "steps": [], "arms": {"rules": None, "llm": None},
                     "public_environment": self.spec,
                     "preflights": {}, "comparison": None, "cleanup": None, "error": None,
                     "scope": "analysis-verification", "environment_scope":
                     "Déploiement, injection, vérifications du playbook et disponibilité TCP ; pas une certification de toutes les propriétés attendues."}
        self.deployments = []
        self.callback = None
        self.save()

    def save(self):
        temporary = self.path / ".pair.tmp"
        temporary.write_text(json.dumps(self.data, ensure_ascii=False, indent=2, allow_nan=False))
        temporary.replace(self.path / "pair.json")

    def step(self, identifier, label, status, **extra):
        entry = next((item for item in self.data["steps"] if item["id"] == identifier), None)
        if entry is None:
            entry = {"id": identifier, "label": label}
            self.data["steps"].append(entry)
        entry.update(status=status, updated_at=now(), **extra)
        self.save()
        if self.callback:
            self.callback({"type": "comparison_step", "comparison_id": self.id, **entry})

    def _prepare(self, policy, stop_event):
        from src.agent.pipeline import Pipeline
        if stop_event.is_set():
            raise LabWaitCancelled("Arrêt demandé")
        if public_spec(self.config["scenario_id"]) != self.spec:
            raise PairPreparationError("La définition du scénario a changé depuis le lancement.")
        deployment = Pipeline(provider=SimpleNamespace(provider="", model=""),
                              scenario_id=self.spec["scenario_id"], auto_teardown=False,
                              output_dir=self.path / f"preparation-{policy}")
        self.deployments.append(deployment)
        # Deployment playbooks can be idempotent. Explicit removal is required
        # before BOTH arms; never equate a second deploy with a fresh reset.
        if not deployment._run_teardown(self.callback):
            raise PairPreparationError("La suppression du scénario avant remise en état a échoué.")
        success = deployment._run_scenario_deploy(self.callback)
        if not success:
            raise PairPreparationError("Le déploiement ou les vérifications du scénario ont échoué.")
        if stop_event.is_set():
            raise LabWaitCancelled("Arrêt après la préparation")
        return deployment

    def _observe(self, policy, stop_event):
        from src.agent.procedure_observations import parse_nmap
        network = ipaddress.ip_network(self.spec["target_network"])
        devices = []
        for device in self.spec["devices"]:
            if stop_event.is_set():
                raise LabWaitCancelled("Arrêt pendant le précontrôle")
            ports = ",".join(str(port) for port in sorted({s["port"] for s in device["services"]}))
            result = subprocess.run(["nmap", "-n", "-Pn", "-sT", "--open", "--host-timeout", "40s",
                                     "-p", ports, device["ip"]], capture_output=True, text=True, timeout=50)
            (self.path / f"preflight-{policy}-{device['id']}.log").write_text(result.stdout + result.stderr)
            observed = parse_nmap(result.stdout, network, target=device["ip"])
            hosts = observed["hosts"]
            if (result.returncode or observed["observations_truncated"] or observed["rejected_host_reports"]
                    or len(hosts) != 1 or not hosts[0]["services"]):
                raise PairPreparationError(f"Précontrôle TCP incomplet pour {device['id']}.")
            names = {s["port"]: s["name"] for s in device["services"]}
            services = [{"name": names[s["port"]], "port": s["port"], "protocol": "tcp"}
                        for s in hosts[0]["services"] if s["port"] in names]
            devices.append({**device, "services": sorted(services, key=lambda s: s["port"])})
        return devices

    def _execute(self, policy, inventory, stop_event):
        from src.agent.pipeline import Pipeline
        from src.agent.provider import LLMProvider
        provider = LLMProvider(provider=self.config["provider"], model=self.config["model"]) if policy == "llm" else None
        worker = Pipeline(provider=provider, decision_policy=policy, experiment_scope="analysis-verification",
                          audit_inventory=inventory, execution_profile="full", phases=[3, 4],
                          max_tool_calls=self.config["max_tool_calls"], max_duration_s=self.config["max_duration_s"],
                          max_cost_usd=self.config["max_cost_usd"],
                          comparison_unlimited=(self.config["max_duration_s"] is None and self.config["max_cost_usd"] is None))
        self.data["arms"][policy] = worker.run_dir.name
        self.save()

        def event(value):
            # A worker's terminal event must not finish the enclosing pair.
            if value.get("type") not in {"pipeline_done", "runner_done"} and self.callback:
                self.callback({**value, "comparison_id": self.id, "comparison_arm": policy,
                               "run_dir": str(worker.run_dir)})
        try:
            worker.run(stream_callback=event, stop_event=stop_event)
        finally:
            worker._update_run_meta({"comparison_id": self.id, "comparison_arm": policy})
        return worker.run_dir

    def run(self, *, callback, stop_event):
        # Keep the reservation until the final record and terminal callback,
        # including evaluation. A waiting deployment must not see a live pair.
        with ExitStack() as reservation:
            return self._run_pair(callback=callback, stop_event=stop_event, reservation=reservation)

    def _run_pair(self, *, callback, stop_event, reservation):
        self.callback = callback
        runs = {"rules": None, "llm": None}
        try:
            reservation.enter_context(reserve_lab(stop_event=stop_event, callback=callback))
            try:
                verify_nato()
                self.data["status"] = "running"
                self.save()
                common = None
                for policy in self.data["order"]:
                    self.step(f"prepare-{policy}", f"Remettre le scénario en état pour {'les règles' if policy == 'rules' else 'le modèle'}", "running")
                    self._prepare(policy, stop_event)
                    self.step(f"prepare-{policy}", "Remise en état et vérifications du scénario", "completed")
                    self.step(f"preflight-{policy}", "Vérifier l’inventaire TCP public", "running")
                    observed = self._observe(policy, stop_event)
                    valid = common is None or observed == common["devices"]
                    preflight = {"status": "valid" if valid else "invalid", "checked_at": now(),
                        "devices_sha256": digest(observed), "scope": "playbook-and-public-tcp-surface",
                        "devices": observed, "preparation_dir": str(self.deployments[-1].run_dir.relative_to(self.path))}
                    self.data["preflights"][policy] = preflight
                    (self.path / f"preflight-{policy}.json").write_text(json.dumps(preflight, indent=2))
                    self.save()
                    if not valid:
                        raise PairPreparationError("La surface TCP a changé entre les deux bras ; la paire est interrompue.")
                    self.step(f"preflight-{policy}", "Inventaire TCP vérifié et conservé", "completed")
                    if common is None:
                        common = validate_inventory({"schema_version": 1,
                            "provenance": "Topologie publique et ports TCP observés par le contrôleur après remise en état.",
                            "target_network": self.spec["target_network"], "devices": observed,
                            "experiment": {"id": self.id, "trial_id": self.id, "family_id": "ui-public-scenario",
                                "instance_id": f"scenario-{self.spec['scenario_id']}", "environment_sha256": digest(self.spec)}})
                        (self.path / "audit_inventory.json").write_text(json.dumps(common, indent=2))
                    self.step(f"audit-{policy}", "Analyse et vérification par règles" if policy == "rules" else "Analyse et vérification par le modèle", "running")
                    runs[policy] = self._execute(policy, common, stop_event)
                    meta = json.loads((runs[policy] / "run_meta.json").read_text())
                    self.step(f"audit-{policy}", "Analyse et vérification", meta.get("status", "incomplete"))
                    if stop_event.is_set():
                        raise LabWaitCancelled("Arrêt demandé")
            finally:
                if self.deployments:
                    self.step("cleanup", "Nettoyer le scénario", "running")
                    try:
                        self.data["cleanup"] = bool(self.deployments[-1]._run_teardown(callback))
                    except Exception:
                        self.data["cleanup"] = False
                    self.step("cleanup", "Nettoyer le scénario", "completed" if self.data["cleanup"] else "failed")
                    if not self.data["cleanup"]:
                        self.data["status"] = "partial"
        except LabWaitCancelled:
            self.data.update(status="stopped", error="Arrêt demandé ; les bras absents restent non exécutés.")
        except Exception as exc:
            self.data.update(status="failed", error=str(exc) if isinstance(exc, PairPreparationError) else
                             f"La comparaison a été interrompue ({type(exc).__name__}). Consultez la dernière étape et les traces.")
            for entry in self.data["steps"]:
                if entry["status"] == "running":
                    entry["status"] = "failed"
        finally:
            if self.data["status"] == "running":
                self.data["status"] = "completed"
            # Preserve failed workers even if run() raised before returning.
            from src.agent.pipeline import OUTPUT_DIR
            for policy, identifier in self.data["arms"].items():
                if identifier and runs[policy] is None:
                    runs[policy] = Path(OUTPUT_DIR) / identifier
            if any(runs.values()):
                try:
                    from src.benchmark.compare_policies import compare_runs
                    from src.benchmark.scenario_exports import resolve_ground_truth_path
                    result = compare_runs(runs["rules"], runs["llm"], resolve_ground_truth_path(self.spec["scenario_id"]))
                    self.data["comparison"] = result
                    if not result["comparable"] and self.data["status"] == "completed":
                        self.data["status"] = "incomplete"
                except Exception as exc:
                    self.data["error"] = f"Évaluation indisponible ({type(exc).__name__})."
                    self.data["status"] = "failed"
            self.data["finished_at"] = now()
            self.save()
            callback({"type": "comparison_done", "comparison_id": self.id, "status": self.data["status"]})
        return self.data
