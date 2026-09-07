"""Run-local artifact access; availability is not semantic evidence validation."""
import json
from pathlib import Path


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
