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


def test_file_viewer_resets_scroll_position_on_each_open():
    css = (ROOT / "src" / "static" / "style.css").read_text(encoding="utf-8")
    assert "overflow-anchor: none;" in css

    for relative_path in ("src/static/app.js", "src/static_docker/app.js"):
        javascript = (ROOT / relative_path).read_text(encoding="utf-8")
        reset_start = javascript.index("function resetScrollPosition")
        reset_helper = javascript[
            reset_start : javascript.index("function switchDetailTab", reset_start)
        ]

        assert "element.scrollTop = 0;" in reset_helper
        assert "element.scrollLeft = 0;" in reset_helper
        assert "requestAnimationFrame(reset);" in reset_helper
        assert (
            "resetScrollPosition(document.getElementById('detail-panel-report'))"
            in javascript
        )

        viewer_start = javascript.index("async function viewFile")
        viewer = javascript[
            viewer_start : javascript.index("async function downloadRun", viewer_start)
        ]
        modal_open = viewer.index("overlay.classList.add('open');")
        reset_scroll = viewer.index("resetScrollPosition(body);")
        assert modal_open < reset_scroll

        close_start = javascript.index("function closeModal")
        close_modal = javascript[
            close_start : javascript.index("document.addEventListener('keydown'", close_start)
        ]
        reset_on_close = close_modal.index("resetScrollPosition")
        modal_close = close_modal.index("overlay.classList.remove('open');")
        assert reset_on_close < modal_close
