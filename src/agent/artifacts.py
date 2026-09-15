"""Run-local artifact access; availability is not semantic evidence validation."""
import json
from pathlib import Path


def resolve_run_artifact(output_dir: Path, filename: str) -> Path:
    """Resolve a relative artifact inside one run, rejecting escaping symlinks."""
    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename must be a non-empty relative path")
    relative = Path(filename)
    if relative.is_absolute():
        raise ValueError("absolute deliverable paths are not allowed")
    root = Path(output_dir).resolve()
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("deliverable path escapes the output directory") from exc
    return candidate


PRIVATE_AGENT_ARTIFACT_NAMES: frozenset[str] = frozenset({
    "ground_truth.yaml",
    "provider_events.jsonl",
})


def is_private_agent_artifact(path: str | Path) -> bool:
    """Return whether a path names an artifact private to the agent runtime."""
    try:
        return Path(path).name in PRIVATE_AGENT_ARTIFACT_NAMES
    except (TypeError, ValueError):
        return False


def is_private_agent_artifact_path(path: str | Path) -> bool:
    """Check a path and its resolved target for private agent artifacts.

    Resolving the target prevents a symlink alias from making a private file
    appear under an otherwise harmless filename.
    """
    if is_private_agent_artifact(path):
        return True
    try:
        return is_private_agent_artifact(Path(path).resolve())
    except (OSError, RuntimeError, ValueError):
        return False


def artifact_available(root: Path, filename: str) -> bool:
    """Require a nonempty file within the run, with parseable JSON if relevant."""
    try:
        relative = Path(filename)
        if relative.is_absolute():
            return False
        path = (root / relative).resolve()
        path.relative_to(root.resolve())
        if not path.is_file() or path.stat().st_size == 0:
            return False
        if path.suffix == ".json":
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, (dict, list)):
                return False
        return True
    except (OSError, ValueError, UnicodeError, RuntimeError):
        return False
