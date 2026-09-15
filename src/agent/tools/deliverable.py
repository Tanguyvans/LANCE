"""Deliverable management tools for agents."""
from __future__ import annotations

import json
from pathlib import Path

from src.agent.artifacts import (
    is_private_agent_artifact,
    is_private_agent_artifact_path,
    resolve_run_artifact,
)


def _resolve_deliverable_path(filename: str, *, output_dir: Path) -> Path:
    """Resolve a deliverable path and guarantee it remains inside output_dir.

    ``Path.resolve`` follows existing symlinks, so this rejects both ordinary
    ``..`` traversal and a symlink in the run directory that points outside it.
    Absolute paths are rejected even when they happen to point back inside the
    output directory: tools should address deliverables by relative name only.
    """
    candidate = resolve_run_artifact(output_dir, filename)
    if is_private_agent_artifact(filename) or is_private_agent_artifact_path(candidate):
        raise ValueError("deliverable is not accessible to agents")
    return candidate


def _path_error(filename: str, exc: ValueError) -> str:
    return json.dumps({"error": f"Invalid deliverable path '{filename}': {exc}"})


def _sanitize_control_chars(s: str) -> str:
    """Escape literal control characters inside JSON string values using a state machine."""
    result = []
    in_string = False
    escape = False
    replacements = {'\n': '\\n', '\r': '\\r', '\t': '\\t'}
    for ch in s:
        if escape:
            result.append(ch)
            escape = False
        elif ch == '\\' and in_string:
            result.append(ch)
            escape = True
        elif ch == '"':
            result.append(ch)
            in_string = not in_string
        elif in_string and ch in replacements:
            result.append(replacements[ch])
        else:
            result.append(ch)
    return ''.join(result)


def _extract_json(content: str) -> str:
    """If content is not valid JSON, try to extract the first JSON object or array from it."""
    content = content.strip()
    # Already valid JSON
    try:
        json.loads(content)
        return content
    except json.JSONDecodeError:
        pass
    # Control characters in strings (e.g. literal \n in evidence field)
    try:
        sanitized = _sanitize_control_chars(content)
        json.loads(sanitized)
        return sanitized
    except json.JSONDecodeError:
        pass
    # Strip markdown code fences: ```json ... ``` or ``` ... ```
    import re
    m = re.search(r'```(?:json)?\s*\n?([\s\S]+?)\n?```', content)
    if m:
        candidate = m.group(1).strip()
        try:
            json.loads(candidate)
            return candidate
        except json.JSONDecodeError:
            pass
    # Last resort: find first { ... } block
    start = content.find('{')
    if start != -1:
        # Walk forward to find matching closing brace
        depth = 0
        for i, ch in enumerate(content[start:], start):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    candidate = content[start:i + 1]
                    try:
                        json.loads(candidate)
                        return candidate
                    except json.JSONDecodeError:
                        break
    return content


def save_deliverable(filename: str | None = None, content: str = "", *, output_dir: Path) -> str:
    """Save a deliverable file in the explicitly supplied run directory.

    The phase transaction supplies its expected filename when the model omits it.
    For JSON files, automatically extracts the JSON block if the LLM wrapped it in markdown.
    """
    if not filename:
        return json.dumps({"error": "save_deliverable: filename manquant et aucun livrable attendu défini pour cette phase"})
    if not content or not content.strip():
        return json.dumps({
            "ok": False,
            "error": "save_deliverable: content must be non-empty",
            "error_kind": "empty_deliverable",
        })
    try:
        path = _resolve_deliverable_path(filename, output_dir=output_dir)
    except ValueError as exc:
        return _path_error(filename, exc)
    path.parent.mkdir(parents=True, exist_ok=True)
    # For JSON deliverables, strip surrounding markdown if needed
    fallback_used = False
    if filename.endswith(".json"):
        original_content = content.strip()
        content = _extract_json(content)
        if content != original_content:
            fallback_used = True
    path.write_text(content, encoding="utf-8")
    return json.dumps({"status": "saved", "path": str(path), "size": len(content), "fallback_used": fallback_used})


def read_deliverable(filename: str, *, output_dir: Path) -> str:
    """Read a previous phase's deliverable."""
    try:
        path = _resolve_deliverable_path(filename, output_dir=output_dir)
    except ValueError as exc:
        return _path_error(filename, exc)
    if not path.exists() or not path.is_file():
        return json.dumps({"error": f"Deliverable '{filename}' not found"})
    content = path.read_text(encoding="utf-8")
    return json.dumps({"filename": filename, "content": content})


def list_deliverables(*, output_dir: Path) -> str:
    """List visible deliverables in the explicitly supplied run directory."""
    if not output_dir.exists():
        return json.dumps({"deliverables": []})
    visible = []
    for f in sorted(output_dir.glob("*")):
        try:
            safe_path = _resolve_deliverable_path(f.name, output_dir=output_dir)
        except ValueError:
            continue
        if safe_path.is_file():
            visible.append(f.name)
    return json.dumps({"deliverables": visible})


def aggregate_device_results(pattern: str = "03_device_*.json", *, output_dir: Path) -> str:
    """Aggregate all device vulnerability files into a single list of results."""
    pattern_path = Path(pattern)
    if pattern_path.is_absolute() or len(pattern_path.parts) != 1 or ".." in pattern_path.parts:
        return json.dumps({
            "vulnerabilities": [],
            "error": "Invalid aggregate pattern: only a filename glob inside the output directory is allowed",
        })
    results = []
    for f in sorted(output_dir.glob(pattern)):
        try:
            safe_path = _resolve_deliverable_path(f.name, output_dir=output_dir)
            data = json.loads(_extract_json(safe_path.read_text(encoding="utf-8")))
            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict):
                v = data.get("vulnerabilities", [])
                if isinstance(v, list):
                    results.extend(v)
                else:
                    results.append(data)
        except Exception as e:
            results.append({"error": f"Failed to parse {f.name}: {e}"})
    return json.dumps({"vulnerabilities": results}, ensure_ascii=False)


DELIVERABLE_TOOLS = [
    {
        "name": "save_deliverable",
        "description": (
            "Save the agent's deliverable file to output/agent/. "
            "The filename must match the expected deliverable for this phase."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Output filename (e.g. '01_graph_analysis.md')",
                },
                "content": {
                    "type": "string",
                    "description": "Full content of the deliverable",
                },
            },
            "required": ["filename", "content"],
        },
        "function": save_deliverable,
    },
    {
        "name": "read_deliverable",
        "description": "Read a previous phase's deliverable file to use as context.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {
                    "type": "string",
                    "description": "Deliverable filename to read (e.g. '01_graph_analysis.md')",
                },
            },
            "required": ["filename"],
        },
        "function": read_deliverable,
    },
    {
        "name": "list_deliverables",
        "description": "List all available deliverables from previous phases.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": list_deliverables,
    },
    {
        "name": "aggregate_device_results",
        "description": "Aggregate all device vulnerability files (03_device_*.json) into a single list of results.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern (default: '03_device_*.json')",
                },
            },
            "required": [],
        },
        "function": aggregate_device_results,
    },
]


def bind_deliverable_tool(tool: dict, output_dir: Path) -> dict:
    """Bind a catalog tool before execution/logging, without changing its schema.

    Only the catalog implementation is bound; an already wrapped tool is left
    intact. The directory is not an argument the model can override.
    """
    function = tool.get("function")
    implementations = {entry["name"]: entry["function"] for entry in DELIVERABLE_TOOLS}
    if function is None or function is not implementations.get(tool.get("name")):
        return tool
    root = Path(output_dir).resolve()

    def bound(**kwargs):
        return function(**kwargs, output_dir=root)

    return {**tool, "function": bound}
