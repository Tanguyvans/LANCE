"""Application-level FastAPI configuration tests."""

from fastapi.testclient import TestClient

from src.api.main import app


def test_large_responses_are_gzip_compressed():
    response = TestClient(app).get("/", headers={"Accept-Encoding": "gzip"})

    assert response.status_code == 200
    assert response.headers["content-encoding"] == "gzip"
