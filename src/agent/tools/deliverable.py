"""Deliverable management tools for agents."""
from __future__ import annotations

import json
from pathlib import Path

OUTPUT_DIR: Path = Path("output/agent")


def set_output_dir(path: Path) -> None:
    """Set the output directory (called by pipeline at init)."""
    global OUTPUT_DIR
    OUTPUT_DIR = path


def save_deliverable(filename: str, content: str) -> str:
    """Save a deliverable file to output/agent/."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / filename
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
]
