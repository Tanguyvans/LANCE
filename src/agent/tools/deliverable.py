"""Deliverable management tools for agents."""
from __future__ import annotations

import json
from pathlib import Path

OUTPUT_DIR: Path = Path("output/agent")


def set_output_dir(path: Path) -> None:
    """Set the output directory (called by pipeline at init)."""
    global OUTPUT_DIR
    OUTPUT_DIR = path


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


def save_deliverable(filename: str, content: str) -> str:
    """Save a deliverable file to output/agent/.

    For JSON files, automatically extracts the JSON block if the LLM wrapped it in markdown.
    """
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
    # For JSON deliverables, strip surrounding markdown if needed
    if filename.endswith(".json"):
        content = _extract_json(content)
    path.write_text(content, encoding="utf-8")
    return json.dumps({"status": "saved", "path": str(path), "size": len(content)})


def read_deliverable(filename: str) -> str:
    """Read a previous phase's deliverable."""
    path = OUTPUT_DIR / filename
    if not path.exists():
        return json.dumps({"error": f"Deliverable '{filename}' not found"})
    content = path.read_text(encoding="utf-8")
    return json.dumps({"filename": filename, "content": content})


def list_deliverables() -> str:
    """List all deliverables in output/agent/."""
    if not OUTPUT_DIR.exists():
        return json.dumps({"deliverables": []})
    files = sorted(OUTPUT_DIR.glob("*"))
    return json.dumps({"deliverables": [f.name for f in files if f.is_file()]})


def aggregate_device_results(pattern: str = "03_device_*.json") -> str:
    """Aggregate all device vulnerability files into a single list of results."""
    results = []
    for f in sorted(OUTPUT_DIR.glob(pattern)):
        try:
            data = json.loads(_extract_json(f.read_text(encoding="utf-8")))
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
