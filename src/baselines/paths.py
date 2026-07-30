"""Project-root-anchored paths so defaults work from any cwd."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def project_root() -> Path:
    """Return the absolute path of the NATO-SmartCity-IoT project root.

    Resolved from this file's location (`<root>/src/baselines/paths.py`).
    Stable as long as the package layout stays the same.
    """
    return Path(__file__).resolve().parent.parent.parent


def under_root(*parts: str | Path) -> Path:
    """Build a path under the project root from string parts."""
    return project_root().joinpath(*parts)
