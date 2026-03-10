"""YAML-based tool loader — converts declarative YAML definitions into
tool dicts compatible with the existing pipeline/provider format.

Subprocess-based tools (nmap, ssh-audit, curl, mosquitto_sub) get
auto-generated Python functions. Python-only tools (nvd_lookup) must
have their handler registered via register_python_handler().
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Callable

import yaml

from src.agent.tools.recon_tools import _run

log = logging.getLogger(__name__)

DEFINITIONS_DIR = Path(__file__).parent / "definitions"

REQUIRED_KEYS = {"name", "description", "parameters"}


def load_tool_yaml(path: Path) -> dict[str, Any]:
    """Parse and validate a single tool YAML file."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    missing = REQUIRED_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"Tool YAML {path.name} missing keys: {missing}")

    return data


def build_input_schema(tool_def: dict[str, Any]) -> dict[str, Any]:
    """Convert YAML parameter list to JSON Schema (input_schema format)."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    for param in tool_def["parameters"]:
        prop: dict[str, Any] = {
            "type": param["type"],
            "description": param["description"],
        }
        if "default" in param:
            prop["default"] = param["default"]

        properties[param["name"]] = prop

        if param.get("required", False):
            required.append(param["name"])

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


def build_subprocess_function(tool_def: dict[str, Any]) -> Callable[..., str]:
    """Generate a Python function that builds & runs the subprocess command.

    Supports parameter formats:
      - "positional": value appended to command list
      - "flag": [flag, str(value)] appended to command list
      - "port_suffix": value appended to previous positional arg with ":"
    """
    command = tool_def["command"]
    fixed_args = tool_def.get("args", [])
    timeout = tool_def.get("timeout", 30)
    params = tool_def["parameters"]

    def generated_fn(**kwargs: Any) -> str:
        cmd = [command] + list(fixed_args)
        positional_values = []

        for param in params:
            name = param["name"]
            value = kwargs.get(name, param.get("default"))

            if value is None:
                continue

            fmt = param.get("format", "positional")

            if fmt == "positional":
                positional_values.append(str(value))
            elif fmt == "flag":
                flag = param["flag"]
                cmd.extend([flag, str(value)])
            elif fmt == "port_suffix":
                if positional_values:
                    positional_values[-1] = f"{positional_values[-1]}:{value}"
                else:
                    positional_values.append(str(value))

        cmd.extend(positional_values)

        effective_timeout = timeout
        if "timeout" in kwargs:
            effective_timeout = int(kwargs["timeout"]) + 5

        return json.dumps(_run(cmd, timeout=effective_timeout))

    generated_fn.__name__ = tool_def["name"]
    generated_fn.__doc__ = tool_def["description"]
    return generated_fn


def load_all_tools(directory: Path | None = None) -> list[dict[str, Any]]:
    """Load all YAML tool definitions from a directory.

    Returns tool dicts in the same format as RECON_TOOLS:
    [{"name", "description", "input_schema", "function"}, ...]

    Python-only tools (handler: python) are included without a function;
    use register_python_handler() to attach one.
    """
    directory = directory or DEFINITIONS_DIR
    tools: list[dict[str, Any]] = []

    if not directory.exists():
        log.warning("Tool definitions directory not found: %s", directory)
        return tools

    for yaml_path in sorted(directory.glob("*.yaml")):
        try:
            tool_def = load_tool_yaml(yaml_path)
        except (ValueError, yaml.YAMLError) as e:
            log.error("Skipping invalid tool YAML %s: %s", yaml_path.name, e)
            continue

        if not tool_def.get("enabled", True):
            log.info("Skipping disabled tool: %s", tool_def["name"])
            continue

        tool_dict: dict[str, Any] = {
            "name": tool_def["name"],
            "description": tool_def["description"],
            "input_schema": build_input_schema(tool_def),
        }

        if tool_def.get("handler") == "python":
            tool_dict["function"] = None
        else:
            tool_dict["function"] = build_subprocess_function(tool_def)

        tools.append(tool_dict)

    log.info("Loaded %d tools from %s", len(tools), directory)
    return tools


def register_python_handler(
    tools: list[dict[str, Any]], name: str, fn: Callable
) -> None:
    """Attach a Python function to a tool that declared handler: python."""
    for tool in tools:
        if tool["name"] == name:
            tool["function"] = fn
            return
    raise KeyError(f"Tool '{name}' not found in loaded tools")
