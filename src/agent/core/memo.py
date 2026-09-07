"""Shared structural checks for model-authored Markdown memos."""
import re


def _looks_truncated_markdown(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    if stripped.count("```") % 2:
        return True
    tail = stripped.rsplit(None, 1)[-1].lower()
    return tail in {"and", "or", "with", "without", "because", "for", "to", "the"}


def _looks_unusable_model_memo(text: str) -> bool:
    stripped = (text or "").strip()
    lower = stripped.lower()
    if _looks_truncated_markdown(stripped):
        return True
    if re.search(r"```(?:[a-z0-9_-]+)?\s*```", stripped, re.IGNORECASE):
        return True
    return any(marker in lower for marker in (
        "[your name]",
        "[current date]",
        "[omit this line",
    ))
