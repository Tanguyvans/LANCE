"""Application-level FastAPI configuration tests."""

from fastapi.testclient import TestClient

from src.api.main import app


def test_large_responses_are_gzip_compressed():
    response = TestClient(app).get("/", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"


def test_live_pipeline_status_is_not_given_public_cache_headers():
    response = TestClient(app).get("/api/pipeline/status")

    assert response.status_code == 200
    assert "cache-control" not in response.headers
