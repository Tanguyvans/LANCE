from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_history_phase_pills_resolve_current_and_legacy_artifacts():
    javascript = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")
    mapping_start = javascript.index("const PHASE_FILES")
    phase_mapping = javascript[
        mapping_start : javascript.index("initResizeHandles();", mapping_start)
    ]

    assert "5: ['05_intrusion.json', '05_report.md']" in phase_mapping
    assert "6: ['06_report.md', '05_report.md']" in phase_mapping
    assert "activeRunFiles.includes(candidate)" in phase_mapping
    assert "activeRunFiles = Array.isArray(run.files) ? run.files : []" in javascript
    assert "const PHASE_FILE = {" not in javascript
