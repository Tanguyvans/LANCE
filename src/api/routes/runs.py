"""Runs route — list, read, and download past pipeline runs."""
from __future__ import annotations

import io
import json
import re
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

router = APIRouter()

ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT / "output" / "agent"


def _extract_cost(run_dir: Path) -> float | None:
    """Try to extract total cost from 05_report.md or any deliverable."""
    for f in sorted(run_dir.glob("*.md"), reverse=True):
        try:
            text = f.read_text()
            m = re.search(r"TOTAL.*?\$([\d.]+)", text)
            if m:
                return float(m.group(1))
        except Exception:
            pass
    return None


def _detect_scenario(run_dir: Path) -> str | None:
    """Detect scenario ID from scenario_meta.json if present."""
    meta = run_dir / "scenario_meta.json"
    if meta.exists():
        try:
            data = json.loads(meta.read_text())
            sid = data.get("scenario_id")
            return f"S{sid}" if sid is not None else None
        except Exception:
            pass
    return None


def _run_status(run_dir: Path) -> str:
    """Infer run status from deliverable files."""
    files = list(run_dir.glob("*"))
    names = [f.name for f in files]
    if "05_report.md" in names:
        return "done"
    if any(n.startswith("04_") for n in names):
        return "partial"
    return "incomplete"


@router.get("")
def list_runs():
    """Return all past runs sorted newest first."""
    if not OUTPUT_DIR.exists():
        return []
    runs = []
    for d in sorted(OUTPUT_DIR.iterdir(), reverse=True):
        if not d.is_dir():
            continue
        files = sorted(f.name for f in d.iterdir() if f.is_file())
        runs.append({
            "id": d.name,
            "files": files,
            "cost": _extract_cost(d),
            "scenario": _detect_scenario(d),
            "status": _run_status(d),
        })
    return runs


@router.get("/{run_id}")
def get_run(run_id: str):
    """Return metadata and file list for a specific run."""
    run_dir = OUTPUT_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail="Run not found")
    files = sorted(f.name for f in run_dir.iterdir() if f.is_file())
    return {
        "id": run_id,
        "files": files,
        "cost": _extract_cost(run_dir),
        "scenario": _detect_scenario(run_dir),
        "status": _run_status(run_dir),
    }


@router.get("/{run_id}/{filename}")
def get_run_file(run_id: str, filename: str):
    """Return the content of a specific deliverable file."""
    run_dir = OUTPUT_DIR / run_id
    filepath = run_dir / filename
    if not run_dir.exists() or not filepath.exists():
        raise HTTPException(status_code=404, detail="File not found")
    # Security: ensure path stays within run_dir
    try:
        filepath.resolve().relative_to(run_dir.resolve())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid path")

    content = filepath.read_text(errors="replace")
    ext = filepath.suffix.lower()
    if ext == ".json":
        try:
            return {"filename": filename, "type": "json", "content": json.loads(content)}
        except json.JSONDecodeError:
            pass
    return {"filename": filename, "type": "text", "content": content}


@router.get("/{run_id}/download/zip")
def download_run(run_id: str):
    """Download all deliverables for a run as a zip archive."""
    run_dir = OUTPUT_DIR / run_id
    if not run_dir.exists():
        raise HTTPException(status_code=404, detail="Run not found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(run_dir.iterdir()):
            if f.is_file():
                zf.write(f, f.name)
    buf.seek(0)
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={run_id}.zip"},
    )
