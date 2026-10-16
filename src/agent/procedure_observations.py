"""Bounded Nmap observations and durable progress for catalogued procedures."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from src.agent.procedures import INVENTORY_PORTS, get_procedure


MAX_OBSERVATION_HOSTS = 256
MAX_OBSERVATION_SERVICES = 512
MAX_INVENTORY_HOSTS = 16
_REPORT = re.compile(r"Nmap scan report for ([0-9.]+)\Z")
_SERVICE = re.compile(r"(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?\Z")


def _address(value, network, target=None):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    if str(address) != value or address not in network or target and value != target:
        return None
    return value


def parse_nmap(stdout: str, network, *, target=None) -> dict:
    """Read fixed ``nmap -n`` text before its raw excerpt is truncated.

    Hostnames and out-of-scope reports are never executable destinations. Counts
    describe report lines; only explicit ``Host is up`` observations permit the
    inventory procedure to inspect a discovered address.
    """
    hosts = {}
    current = None
    reported = service_count = rejected = 0
    truncated = False
    for line in stdout.splitlines():
        if line.startswith("Nmap scan report for "):
            reported += 1
            match = _REPORT.fullmatch(line)
            address = _address(match[1], network, target) if match else None
            current = None
            if address is None:
                rejected += 1
                continue
            if address not in hosts:
                if len(hosts) >= MAX_OBSERVATION_HOSTS:
                    truncated = True
                    continue
                hosts[address] = {"ip": address, "status": "observed", "services": []}
            current = hosts[address]
        elif current is not None:
            if line.startswith("Host is up"):
                current["status"] = "up"
            match = _SERVICE.fullmatch(line.strip())
            if match and 1 <= int(match[1]) <= 65535:
                service_count += 1
                if service_count > MAX_OBSERVATION_SERVICES:
                    truncated = True
                    continue
                service = {"port": int(match[1]), "protocol": "tcp", "state": "open",
                           "name": match[2][:128], "detail": (match[3] or "")[:256]}
                if len(match[2]) > 128 or len(match[3] or "") > 256:
                    truncated = True
                if service not in current["services"]:
                    current["services"].append(service)
    return {"hosts": list(hosts.values()), "reported_hosts": reported,
            "reported_services": service_count, "rejected_host_reports": rejected,
            "observations_truncated": truncated}


class ProcedureProgress:
    """Derived results always retain references to the executor's raw ledger."""

    def __init__(self, script_id: str, network, run_dir: Path):
        self.network, self.run_dir = network, run_dir
        self.callback = None
        self.inspected = set()
        self.descriptor = get_procedure(script_id)
        self.data = {
            "schema_version": 1, "script_id": script_id, "version": self.descriptor["version"],
            "fingerprint": self.descriptor["fingerprint"],
            "procedure": {key: self.descriptor[key] for key in ("id", "title", "version", "fingerprint")},
            "status": "pending", "target_network": str(network) if network else None,
            "hosts": [], "counts": {"hosts": 0, "discovered_hosts": 0,
                                     "inspected_hosts": 0, "services": 0},
            "coverage": {
                "scope": {"smoke-v1": "offline", "discovery-v1": "host-discovery",
                          "service-inventory-v1": "tcp-service-inventory"}[script_id],
                "discovery_complete": False if network else None,
                "services_complete": False if script_id == "service-inventory-v1" else None,
                "host_limit": MAX_INVENTORY_HOSTS if script_id == "service-inventory-v1" else None,
                "ports": INVENTORY_PORTS if script_id == "service-inventory-v1" else None,
                "host_limit_reached": False, "skipped_hosts": [],
                "rejected_host_reports": 0,
                "observations_truncated": False, "raw_output_truncated": False,
                "partial": False, "incomplete_reasons": [],
            },
            "steps": [{**step, "status": "pending"} for step in self.descriptor["steps"]],
            "errors": [], "evidence_refs": [],
        }

    def publish(self):
        self.data["updated_at"] = datetime.now(timezone.utc).isoformat()
        temporary = self.run_dir / ".procedure_results.tmp"
        temporary.write_text(json.dumps(self.data, indent=2, ensure_ascii=False), encoding="utf-8")
        temporary.replace(self.run_dir / "procedure_results.json")
        if self.callback:
            # Freeze the payload: callers may retain it while subsequent steps mutate state.
            self.callback({"type": "procedure_results", "runner_kind": "scripted",
                           "script_id": self.data["script_id"], "run_dir": str(self.run_dir),
                           "results": json.loads(json.dumps(self.data))})

    def step(self, step_id, status, *, label=None, target=None):
        step = next((item for item in self.data["steps"] if item["id"] == step_id), None)
        if step is None:
            step = {"id": step_id, "label": label or step_id, "status": "pending"}
            result_index = next((index for index, item in enumerate(self.data["steps"])
                                 if item["id"] == "results"), len(self.data["steps"]))
            self.data["steps"].insert(result_index, step)
        step.update(status=status, updated_at=datetime.now(timezone.utc).isoformat())
        if target:
            step["target"] = target
        if self.callback:
            self.callback({"type": "procedure_step", "runner_kind": "scripted",
                           "script_id": self.data["script_id"], "run_dir": str(self.run_dir),
                           "step_id": step_id, "label": step["label"], "status": status,
                           **({"target": target} if target else {})})
        self.publish()

    def incomplete(self, reason):
        coverage = self.data["coverage"]
        coverage["partial"] = True
        if reason not in coverage["incomplete_reasons"]:
            coverage["incomplete_reasons"].append(reason)

    def record(self, entry):
        ref = entry.get("evidence_ref")
        if not ref or ref in self.data["evidence_refs"]:
            return
        self.data["evidence_refs"].append(ref)
        payload = entry.get("result")
        try:
            payload = json.loads(payload) if isinstance(payload, str) else payload
        except (TypeError, ValueError):
            payload = None
        if not isinstance(payload, dict):
            self.incomplete("unreadable_observation")
            self.publish()
            return
        name, args = entry.get("tool"), entry.get("args", {})
        target = args.get("target") if name == "nmap_scan" else None
        observation = payload.get("observations")
        if not isinstance(observation, dict):
            observation = parse_nmap(payload.get("stdout", ""), self.network, target=target)
            if payload.get("stdout_truncated"):
                self.incomplete("observation_unavailable_before_truncation")
        coverage = self.data["coverage"]
        coverage["raw_output_truncated"] |= bool(payload.get("stdout_truncated") or payload.get("stderr_truncated"))
        coverage["observations_truncated"] |= bool(observation.get("observations_truncated"))
        if coverage["observations_truncated"]:
            self.incomplete("observation_limit")
        if observation.get("rejected_host_reports"):
            coverage["rejected_host_reports"] += observation["rejected_host_reports"]
            self.incomplete("unusable_host_reports")
        for host in observation.get("hosts", [])[:MAX_OBSERVATION_HOSTS]:
            if not isinstance(host, dict):
                continue
            address = _address(host.get("ip"), self.network, target)
            if not address:
                self.incomplete("unusable_host_reports")
                continue
            saved = next((item for item in self.data["hosts"] if item["ip"] == address), None)
            if saved is None:
                if len(self.data["hosts"]) >= MAX_OBSERVATION_HOSTS:
                    self.incomplete("observation_limit")
                    continue
                saved = {"ip": address, "status": host.get("status", "observed"),
                         "services": [], "evidence_refs": []}
                self.data["hosts"].append(saved)
            if host.get("status") == "up":
                saved["status"] = "up"
            saved["evidence_refs"].append(ref)
            for service in host.get("services", [])[:MAX_OBSERVATION_SERVICES]:
                if (not isinstance(service, dict) or type(service.get("port")) is not int
                        or not 1 <= service["port"] <= 65535 or service.get("protocol") != "tcp"
                        or service.get("state") != "open"):
                    continue
                item = {key: service[key] for key in ("port", "protocol", "state", "name", "detail") if key in service}
                item["evidence_refs"] = [ref]
                existing = next((s for s in saved["services"] if s["port"] == item["port"] and s["protocol"] == item["protocol"]), None)
                if existing:
                    existing["evidence_refs"].append(ref)
                elif sum(len(h["services"]) for h in self.data["hosts"]) < MAX_OBSERVATION_SERVICES:
                    saved["services"].append(item)
                else:
                    self.incomplete("observation_limit")
        completed = (payload.get("return_code") == 0 and not payload.get("error")
                     and not payload.get("timed_out") and not payload.get("cancelled")
                     and (payload.get("scan_completed") is True or "Nmap done:" in payload.get("stdout", "")))
        if name == "nmap_discovery":
            coverage["discovery_complete"] = completed
            self.data["counts"]["discovered_hosts"] = observation.get("reported_hosts", 0)
        elif completed and target:
            if any(host.get("ip") == target and host.get("status") == "up"
                   for host in observation.get("hosts", [])):
                self.inspected.add(target)
            else:
                completed = False
        if not completed:
            self.incomplete("scan_incomplete")
            self.data["errors"].append({"kind": "scan_incomplete", "tool": name,
                                        "target": args.get("target"), "evidence_ref": ref,
                                        "return_code": payload.get("return_code"),
                                        "timed_out": bool(payload.get("timed_out")),
                                        "cancelled": bool(payload.get("cancelled"))})
        self.data["counts"].update(hosts=len(self.data["hosts"]), inspected_hosts=len(self.inspected),
                                   services=sum(len(h["services"]) for h in self.data["hosts"]))
        self.publish()

    def finish(self, status):
        self.data["status"] = status
        if status != "completed":
            self.incomplete(status)
            if status != "partial" and not self.data["errors"]:
                self.data["errors"].append({"kind": status})
        for step in list(self.data["steps"]):
            if step["status"] == "running":
                self.step(step["id"], "stopped" if status in {"stopped", "budget_exceeded"} else "failed")
        self.step("results", "running")
        self.step("results", "completed")
