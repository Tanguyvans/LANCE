"""The canonical dashboard works without the retired V2 source directory."""
import re

import pytest
from fastapi.testclient import TestClient

from src.api.main import app, STATIC_DIR


@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client


def test_dashboard_and_its_local_assets_are_served(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.text == (STATIC_DIR / "index.html").read_text(encoding="utf-8")
    assert response.headers["cache-control"] == "no-cache, no-store, must-revalidate"

    assets = re.findall(r'(?:src|href)="(/static/[^\"]+)"', response.text)
    assert "/static/cytoscape.min.js" in assets
    assert "/static/scenario_generator.js" in assets
    for path in assets:
        asset = client.get(path)
        assert asset.status_code == 200, path
        assert asset.content, path
        assert asset.headers["cache-control"] == "no-cache, no-store, must-revalidate"


def test_legacy_monitor_bookmark_redirects_to_the_dashboard(client):
    response = client.get("/v2", follow_redirects=False)
    assert response.status_code == 308
    assert response.headers["location"] == "/"
    assert client.get("/v2").text == client.get("/").text


@pytest.mark.parametrize("filename", ["index.html", "app.js", "generator.js", "style.css"])
def test_retired_monitor_assets_are_not_served(client, filename):
    assert client.get(f"/static_v2/{filename}").status_code == 404
