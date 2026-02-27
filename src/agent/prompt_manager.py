"""Prompt template loader with @include() and {{variable}} interpolation."""
from __future__ import annotations

import re
from pathlib import Path

PROMPT_DIR = Path(__file__).parent / "prompts"
INCLUDE_RE = re.compile(r"@include\(([^)]+)\)")
VAR_RE = re.compile(r"\{\{(\w+)\}\}")
MAX_INCLUDE_DEPTH = 5


def load_prompt(name: str, variables: dict | None = None) -> str:
    """Load a prompt template by name (without .txt extension).

    1. Reads prompts/<name>.txt
    2. Recursively resolves @include(shared/_target.txt) directives
    3. Replaces {{variable}} placeholders with values from variables dict
    """
    path = PROMPT_DIR / f"{name}.txt"
    raw = path.read_text(encoding="utf-8")
    resolved = _resolve_includes(raw, depth=0)
    if variables:
        resolved = _interpolate(resolved, variables)
    return resolved


def _resolve_includes(text: str, depth: int) -> str:
    if depth > MAX_INCLUDE_DEPTH:
        return text

    def replacer(match: re.Match) -> str:
        include_path = PROMPT_DIR / match.group(1).strip()
        if include_path.exists():
            content = include_path.read_text(encoding="utf-8")
            return _resolve_includes(content, depth + 1)
        return f"[MISSING: {match.group(1).strip()}]"

    return INCLUDE_RE.sub(replacer, text)


def _interpolate(text: str, variables: dict) -> str:
    def replacer(match: re.Match) -> str:
        key = match.group(1)
        return str(variables.get(key, f"{{{{MISSING:{key}}}}}"))

    return VAR_RE.sub(replacer, text)
