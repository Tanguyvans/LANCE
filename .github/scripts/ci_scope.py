"""Only known documentation changes may use the lightweight CI path."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess


DOCUMENT_ROOTS = ("docs/", "research/")
DOCUMENT_SUFFIXES = {".md", ".tex", ".pdf", ".bib", ".png", ".jpg", ".jpeg", ".svg", ".webp"}
DOCUMENT_FILES = {
    "README.md", "AGENTS.md", "LICENSE", "tests/README.md",
    "src/agent/phases/README.md", "model_training/README.md",
}


def documentation_only(paths: list[str]) -> bool:
    return all(
        path in DOCUMENT_FILES or (
            path.startswith(DOCUMENT_ROOTS)
            and Path(path).suffix.lower() in DOCUMENT_SUFFIXES
        )
        for path in paths
    )


def comparison_base(event_name: str, event: dict, ref: str) -> str | None:
    # Manual runs and releases always exercise the complete validation path.
    if ref.startswith("refs/tags/"):
        return None
    if event_name == "push":
        base = event.get("before")
    elif event_name == "pull_request":
        base = event.get("pull_request", {}).get("base", {}).get("sha")
    else:
        return None
    if not isinstance(base, str) or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", base):
        return None
    return base if set(base) != {"0"} else None


def changed_paths(base: str, *, cwd: Path | None = None) -> list[str]:
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{base}^{{commit}}"], cwd=cwd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if exists.returncode:
        # Pushes can contain several commits; checkout's shallow parent is
        # insufficient. Fetch only the authoritative event base when needed.
        subprocess.run(
            ["git", "fetch", "--no-tags", "--depth=1", "origin", base],
            cwd=cwd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    result = subprocess.run(
        ["git", "diff", "--no-renames", "--name-only", "-z", base, "HEAD"],
        cwd=cwd, check=True, stdout=subprocess.PIPE,
    )
    # Disabling rename detection keeps both the removed and added paths.
    return [path.decode("utf-8", errors="surrogateescape")
            for path in result.stdout.split(b"\0") if path]


def classify(event_name: str, event: dict, ref: str, *, cwd: Path | None = None) -> tuple[bool, str]:
    base = comparison_base(event_name, event, ref)
    if base is None:
        return True, ""
    try:
        return not documentation_only(changed_paths(base, cwd=cwd)), base
    except (OSError, subprocess.CalledProcessError):
        print("Could not establish changed paths; running complete CI.")
        return True, ""


def main() -> None:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        full, base = classify(
            os.environ.get("GITHUB_EVENT_NAME", ""), event,
            os.environ.get("GITHUB_REF", ""),
        )
    except (KeyError, OSError, ValueError, TypeError, AttributeError):
        print("Could not read event metadata; running complete CI.")
        full, base = True, ""
    output = f"full={str(full).lower()}\nbase={base}\n"
    print(output, end="")
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as handle:
        handle.write(output)


if __name__ == "__main__":
    main()
