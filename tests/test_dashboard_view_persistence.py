from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_main_view_is_persisted_and_restored_safely():
    javascript = (ROOT / "src" / "static" / "app.js").read_text(encoding="utf-8")

    assert "const VIEW_STORAGE_KEY = 'lance.activeView';" in javascript
    assert "new Set(['main', 'benchmark', 'scenario-lab'])" in javascript
    assert "window.localStorage.getItem(VIEW_STORAGE_KEY)" in javascript
    assert "window.localStorage.setItem(VIEW_STORAGE_KEY, view)" in javascript
    assert "return VALID_VIEWS.has(stored) ? stored : 'main';" in javascript
    assert "view = VALID_VIEWS.has(view) ? view : 'main';" in javascript

    nav_start = javascript.index("// View nav")
    nav_end = javascript.index("// Detail tabs", nav_start)
    navigation_init = javascript[nav_start:nav_end]
    assert "switchView(getStoredView());" in navigation_init


def test_persisted_views_match_dashboard_navigation():
    html = (ROOT / "src" / "static" / "index.html").read_text(encoding="utf-8")

    for view in ("main", "benchmark", "scenario-lab"):
        assert f'data-view="{view}"' in html
