"""Scenario target extraction for baseline tools.

Baseline tools such as CAI or PentGPT usually run against one host at a time.
This module turns the repository's scenario inventory into a stable per-device
target list so their results can still be evaluated at scenario level.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

import yaml


DEFAULT_ANSIBLE_VARS = Path("benchmarks/ansible/group_vars/all/main.yml")
DEFAULT_GT_DIR = Path("benchmarks/ground_truth")


@dataclass(frozen=True)
class BaselineTarget:
    ip: str
    name: str
    role: str
    device_id: str
    source: str = "service"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def load_scenario_targets(
    scenario_id: str | int,
    vars_file: Path = DEFAULT_ANSIBLE_VARS,
    include_router: bool = True,
) -> list[BaselineTarget]:
    """Return benchmark targets for a scenario.

    The router is included by default because several ground-truth findings live
    on the OpenWrt gateway. Service hosts come from the Ansible scenario matrix.
    """
    data = yaml.safe_load(vars_file.read_text()) or {}
    scenarios: dict[str, Any] = data.get("scenarios", {})
    sid = str(scenario_id)
    if sid not in scenarios:
        available = ", ".join(sorted(scenarios))
        raise ValueError(f"Unknown scenario '{sid}'. Available scenarios: {available}")

    scenario = scenarios[sid]
    targets: list[BaselineTarget] = []
    if include_router:
        targets.append(
            BaselineTarget(
                ip=str(data.get("benchmark_gateway", "192.168.100.1")),
                name=f"S{sid}-router",
                role="router",
                device_id=f"S{sid}-router",
                source="router",
            )
        )

    for service in scenario.get("services", []):
        name = str(service["name"])
        role = str(service.get("role", "unknown"))
        ip = str(service["ip"])
        targets.append(
            BaselineTarget(
                ip=ip,
                name=name,
                role=role,
                device_id=f"S{sid}-{name}",
            )
        )

    return targets


def write_targets_json(targets: list[BaselineTarget], output: Path) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        yaml.safe_dump([t.to_dict() for t in targets], sort_keys=False),
        encoding="utf-8",
    )
    return output


def load_ground_truth_targets(
    scenario_id: str | int,
    ground_truth_dir: Path = DEFAULT_GT_DIR,
) -> list[BaselineTarget]:
    """Return unique target IPs present in the scenario ground truth.

    This is the default for the paper baselines: per-IP tools receive exactly the
    IP list implied by the evaluation set, matching `plan_cai_comparison.md`.
    """
    sid = str(scenario_id)
    gt_file = ground_truth_dir / f"scenario_{sid}.yaml"
    if not gt_file.exists():
        raise FileNotFoundError(f"Ground truth not found: {gt_file}")
    data = yaml.safe_load(gt_file.read_text()) or {}
    seen: set[str] = set()
    targets: list[BaselineTarget] = []
    for vuln in data.get("vulnerabilities", []):
        ip = str(vuln.get("ip", "")).strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        device = str(vuln.get("device", ip))
        targets.append(
            BaselineTarget(
                ip=ip,
                name=device,
                role="ground_truth_target",
                device_id=f"S{sid}-{device}",
                source="ground_truth",
            )
        )
    return targets
