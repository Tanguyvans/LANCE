"""Baseline tool configuration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_CONFIG = Path("benchmarks/baselines/tools.example.yml")


@dataclass(frozen=True)
class ToolConfig:
    name: str
    command: str
    remote_workdir: str = "/opt/baseline-tools"
    output_glob: str = "{tool}_{scenario}_{ip}.json"
    timeout_seconds: int = 1800


def load_tool_config(tool: str, config_file: Path = DEFAULT_CONFIG) -> ToolConfig:
    if not config_file.exists():
        raise FileNotFoundError(f"Baseline config not found: {config_file}")
    data: dict[str, Any] = yaml.safe_load(config_file.read_text()) or {}
    tools = data.get("tools", {})
    if tool not in tools:
        available = ", ".join(sorted(tools))
        raise ValueError(f"Unknown baseline tool '{tool}'. Available tools: {available}")
    raw = tools[tool] or {}
    if "command" not in raw:
        raise ValueError(f"Baseline tool '{tool}' must define a command")
    return ToolConfig(
        name=tool,
        command=str(raw["command"]),
        remote_workdir=str(raw.get("remote_workdir", "/opt/baseline-tools")),
        output_glob=str(raw.get("output_glob", "{tool}_{scenario}_{ip}.json")),
        timeout_seconds=int(raw.get("timeout_seconds", 1800)),
    )
