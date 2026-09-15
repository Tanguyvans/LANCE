"""Run-local artifact access; availability is not semantic evidence validation."""
import json
from pathlib import Path


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
