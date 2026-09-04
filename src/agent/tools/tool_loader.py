"""YAML-based tool loader — converts declarative YAML definitions into
tool dicts compatible with the existing pipeline/provider format.

Subprocess-based tools (nmap, ssh-audit, curl, mosquitto_sub) get
auto-generated Python functions. Python-only tools (nvd_lookup) must
have their handler registered via register_python_handler().
"""

from __future__ import annotations

import importlib.util
import json
import logging
import shlex
import shutil
from pathlib import Path
from typing import Any, Callable

import yaml

log = logging.getLogger(__name__)

DEFINITIONS_DIR = Path(__file__).parent / "definitions"

REQUIRED_KEYS = {"name", "description", "parameters"}
HARDWARE_KEYS = {"name", "description"}

import hashlib

# Cache for deduplicating tool outputs (Stateful Tooling)
# Format: { "tool_name_target_context": {signature: original_line_or_response} }
#
# Important: cached repeats must replay the original evidence instead of
# replacing it with a summary. Phase 4 aggregation depends on the concrete
# tool output to decide whether a verdict is supported.
_TOOL_CACHE: dict[str, dict[str, str]] = {}


def reset_tool_cache() -> None:
    """Drop evidence cached by earlier pipeline runs in this process."""
    _TOOL_CACHE.clear()


def _get_payload_signature(payload_str: str) -> str:
    """Generate a signature based on payload type/structure rather than exact content."""
    payload_stripped = payload_str.strip()
    if payload_stripped.startswith("{") and payload_stripped.endswith("}"):
        try:
            data = json.loads(payload_stripped)
            if isinstance(data, dict):
                keys = ",".join(sorted(data.keys()))
                return f"json_keys:{keys}"
        except json.JSONDecodeError:
            pass
    return hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

def load_tool_yaml(path: Path) -> dict[str, Any]:
    """Parse and validate a single tool YAML file."""
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)

    is_hardware = data.get("type") == "hardware"
    required = HARDWARE_KEYS if is_hardware else REQUIRED_KEYS
    missing = required - set(data.keys())
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

    filter_lines = tool_def.get("filter_lines")
    max_output = tool_def.get("max_output")

    def generated_fn(**kwargs: Any) -> str:
        # Compact local models occasionally use the structured credential
        # shape (ip/user/password/command) for ssh_login. Normalize that
        # shape instead of silently dropping all arguments and running
        # `bash -c` without a command.
        if tool_def["name"] == "ssh_login" and not kwargs.get("command_string"):
            ip = str(kwargs.get("ip") or "").strip()
            user = str(kwargs.get("user") or "").strip()
            password = str(kwargs.get("password") or "")
            remote_command = str(kwargs.get("command") or "id").strip() or "id"
            if ip and user and password:
                try:
                    port = int(kwargs.get("port") or 22)
                except (TypeError, ValueError):
                    port = 22
                kwargs = {
                    "command_string": (
                        f"sshpass -p {shlex.quote(password)} ssh "
                        "-o StrictHostKeyChecking=no "
                        "-o UserKnownHostsFile=/dev/null "
                        "-o ConnectTimeout=5 "
                        f"-p {port} {shlex.quote(user)}@{ip} "
                        f"{shlex.quote(remote_command)}"
                    ),
                }
            else:
                return json.dumps({
                    "stdout": "",
                    "stderr": "ssh_login requires command_string or ip/user/password",
                    "return_code": 2,
                })
        cmd = [command] + list(fixed_args)
        positional_values = []

        for param in params:
            name = param["name"]
            value = kwargs.get(name, param.get("default"))

            if value is None:
                continue

            fmt = param.get("format", "positional")

            if fmt == "positional":
                raw = str(value)
                # For "bash -c" style tools, pass command_string as a single
                # argument — splitting would break shell commands.
                if command == "bash" and "-c" in fixed_args:
                    positional_values.append(raw)
                else:
                    # Split on commas/spaces so multi-target strings
                    # (e.g. "192.168.88.1,192.168.88.2") become separate args
                    parts = raw.replace(",", " ").split()
                    positional_values.extend(parts)
            elif fmt == "flag":
                flag = param["flag"]
                cmd.extend([flag, str(value)])
            elif fmt == "boolean_flag":
                if value:
                    flag = param["flag"]
                    cmd.append(flag)
            elif fmt == "port_suffix":
                if positional_values:
                    positional_values[-1] = f"{positional_values[-1]}:{value}"
                else:
                    positional_values.append(str(value))

        cmd.extend(positional_values)

        effective_timeout = timeout
        if "timeout" in kwargs:
            effective_timeout = int(kwargs["timeout"]) + 5

        # Legacy embedded SSH services frequently only offer SHA-1 KEX/ciphers.
        # Add compatibility flags for the declarative ssh_login tool while
        # preserving any explicit model-supplied options and command autonomy.
        if tool_def["name"] == "ssh_login" and command == "bash" and "-c" in fixed_args:
            command_string = next((str(v) for v in positional_values if str(v).strip()), "")
            if command_string and "KexAlgorithms=" not in command_string:
                legacy = (
                    "-o KexAlgorithms=+diffie-hellman-group14-sha1,"
                    "diffie-hellman-group-exchange-sha1 "
                    "-o HostKeyAlgorithms=+ssh-rsa "
                    "-o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc "
                )
                command_string = command_string.replace("ssh ", "ssh " + legacy, 1)
                first_value = next((str(x) for x in positional_values if str(x).strip()), "")
                positional_values = [
                    command_string if str(v) == first_value else v
                    for v in positional_values
                ]
                cmd = [command] + list(fixed_args)
                cmd.extend(positional_values)

        from src.agent.tools.recon_tools import _run
        result = _run(cmd, timeout=effective_timeout)

        stdout = result.get("stdout", "")
        tool_name = tool_def["name"]

        # --- Deduplication Cache Logic ---
        if tool_name == "mqtt_listen" and stdout:
            broker = kwargs.get("broker", "unknown")
            topic = kwargs.get("topic", "#")
            username = kwargs.get("username") or ""
            password = kwargs.get("password") or ""
            cache_key = f"mqtt_{broker}_{topic}_{username}_{password}"
            if cache_key not in _TOOL_CACHE:
                _TOOL_CACHE[cache_key] = {}

            new_lines = []
            replayed_lines = []
            for line in stdout.splitlines():
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    topic, payload = parts
                    sig = f"{topic}::{_get_payload_signature(payload)}"
                    if sig not in _TOOL_CACHE[cache_key]:
                        _TOOL_CACHE[cache_key][sig] = line
                        new_lines.append(line)
                    else:
                        replayed_lines.append(_TOOL_CACHE[cache_key][sig])
                else:
                    new_lines.append(line)  # Keep unparseable lines

            if not new_lines and stdout.strip():
                result["stdout"] = "\n".join(replayed_lines) if replayed_lines else stdout
                result["cache_replayed"] = True
                result["cache_note"] = "Duplicate MQTT payload structures replayed from the first observation."
            else:
                result["stdout"] = "\n".join(new_lines)

        elif tool_name == "curl_headers" and stdout:
            url = kwargs.get("url", "unknown")
            cache_key = f"curl_{url}"
            sig = hashlib.sha256(stdout.encode("utf-8")).hexdigest()

            if cache_key not in _TOOL_CACHE:
                _TOOL_CACHE[cache_key] = {}

            if sig in _TOOL_CACHE[cache_key]:
                result["stdout"] = _TOOL_CACHE[cache_key][sig]
                result["cache_replayed"] = True
                result["cache_note"] = "Identical HTTP response replayed from the first observation."
            else:
                _TOOL_CACHE[cache_key][sig] = stdout
        # ---------------------------------

        if filter_lines and result.get("stdout"):
            import re
            pattern = re.compile(filter_lines)
            lines = [l for l in result["stdout"].splitlines() if pattern.search(l)]
            result["stdout"] = "\n".join(lines)

        if max_output and result.get("stdout") and len(result["stdout"]) > max_output:
            result["stdout"] = result["stdout"][:max_output] + "\n[truncated]"

        rc_map = tool_def.get("return_code_map")
        if rc_map is not None:
            rc = result.get("return_code")
            if rc is not None:
                result["interpretation"] = rc_map.get(rc, f"unknown_return_code_{rc}")

        return json.dumps(result)

    generated_fn.__name__ = tool_def["name"]
    generated_fn.__doc__ = tool_def["description"]
    return generated_fn


def _build_hardware_description(tool_def: dict[str, Any]) -> str:
    """Build a rich description for hardware tools, embedding protocol commands."""
    lines = [tool_def["description"]]
    lines.append(f"\nCapabilities: {', '.join(tool_def.get('capabilities', []))}")

    for proto in tool_def.get("protocols", []):
        lines.append(f"\n## {proto['name']} ({proto.get('channels', 'N/A')})")
        lines.append(f"Software: {', '.join(proto.get('software', []))}")
        for cmd in proto.get("commands", []):
            lines.append(f"  - {cmd['description']}: `{cmd['cmd']}`")

    return "\n".join(lines)


def _build_hardware_function(tool_def: dict[str, Any]) -> Callable[..., str]:
    """Generate a function for hardware tools that returns command suggestions."""
    protocols = {p["name"]: p for p in tool_def.get("protocols", [])}

    def hardware_fn(**kwargs: Any) -> str:
        # If the tool has a command (e.g. hackrf_transfer), try to run it
        if "command" in tool_def:
            cmd = [tool_def["command"]] + list(tool_def.get("args", []))
            for param in tool_def.get("parameters", []):
                value = kwargs.get(param["name"], param.get("default"))
                if value is None:
                    continue
                fmt = param.get("format", "positional")
                if fmt == "flag":
                    cmd.extend([param["flag"], str(value)])
                elif fmt == "positional":
                    cmd.append(str(value))
            timeout = tool_def.get("timeout", 60)
            from src.agent.tools.recon_tools import _run
            return json.dumps(_run(cmd, timeout=timeout))

        # Otherwise return protocol-specific command suggestions
        target_proto = kwargs.get("protocol", kwargs.get("interface"))
        if target_proto and target_proto in protocols:
            proto = protocols[target_proto]
            return json.dumps({
                "type": "hardware_commands",
                "protocol": target_proto,
                "channels": proto.get("channels", "N/A"),
                "software": proto.get("software", []),
                "commands": proto.get("commands", []),
            })

        # Return all available protocols and commands
        return json.dumps({
            "type": "hardware_commands",
            "available_protocols": list(protocols.keys()),
            "all_commands": {
                name: p.get("commands", []) for name, p in protocols.items()
            },
        })

    hardware_fn.__name__ = tool_def["name"]
    hardware_fn.__doc__ = tool_def["description"]
    return hardware_fn


def load_all_tools(directory: Path | None = None) -> list[dict[str, Any]]:
    """Load all YAML tool definitions from a directory.

    Returns tool dicts in the same format as RECON_TOOLS:
    [{"name", "description", "input_schema", "function"}, ...]

    Supports three tool types:
      - subprocess (default): auto-generated shell commands
      - handler: python: Python-only, attach via register_python_handler()
      - type: hardware: physical attack tools with protocol-specific commands
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

        is_hardware = tool_def.get("type") == "hardware"

        if is_hardware:
            tool_dict: dict[str, Any] = {
                "name": tool_def["name"],
                "description": _build_hardware_description(tool_def),
                "input_schema": build_input_schema(tool_def) if tool_def.get("parameters") else {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
                "function": _build_hardware_function(tool_def),
                "hardware": True,
            }
        elif tool_def.get("handler") == "python":
            tool_dict = {
                "name": tool_def["name"],
                "description": tool_def["description"],
                "input_schema": build_input_schema(tool_def),
                "function": None,
            }
        else:
            tool_dict = {
                "name": tool_def["name"],
                "description": tool_def["description"],
                "input_schema": build_input_schema(tool_def),
                "function": build_subprocess_function(tool_def),
            }

        # Keep runtime capability metadata alongside the provider-facing tool
        # shape. The pipeline uses it to avoid exposing commands that are not
        # installed on the worker; the provider ignores these internal fields.
        tool_dict["command"] = tool_def.get("command")
        tool_dict["handler"] = tool_def.get("handler")
        tool_dict["requires_modules"] = tuple(tool_def.get("requires_modules", ()))
        tools.append(tool_dict)

    hw_count = sum(1 for t in tools if t.get("hardware"))
    sw_count = len(tools) - hw_count
    log.info("Loaded %d tools (%d software, %d hardware) from %s",
             len(tools), sw_count, hw_count, directory)
    return tools


def filter_unavailable_tools(
    tools: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Remove tools whose command or declared Python dependency is absent.

    Returns the filtered tools and a name-to-reason map suitable for run
    metadata. Tools without runtime metadata are preserved because they are
    pure Python/internal capabilities or protocol suggestions.
    """
    available: list[dict[str, Any]] = []
    unavailable: dict[str, str] = {}
    for tool in tools:
        name = str(tool.get("name") or "")
        command = tool.get("command")
        if command and shutil.which(str(command)) is None:
            unavailable[name] = f"missing_command:{command}"
            continue
        for module in tool.get("requires_modules", ()) or ():
            if importlib.util.find_spec(str(module)) is None:
                unavailable[name] = f"missing_python_module:{module}"
                break
        else:
            available.append(tool)
    return available, unavailable


def register_python_handler(
    tools: list[dict[str, Any]], name: str, fn: Callable
) -> None:
    """Attach a Python function to a tool that declared handler: python."""
    for tool in tools:
        if tool["name"] == name:
            tool["function"] = fn
            return
    raise KeyError(f"Tool '{name}' not found in loaded tools")
