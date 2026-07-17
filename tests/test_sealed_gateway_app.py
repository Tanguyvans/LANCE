"""Trust-boundary tests for the evaluator-owned sealed UI/gateway."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from src.api.main import app as public_app
from src.api.sealed_main import app as sealed_app


ROOT = Path(__file__).resolve().parents[1]


def _route_paths(app) -> set[str]:
    return {route.path for route in app.routes if hasattr(route, "path")}


def test_public_master_has_no_sealed_api_or_token_ui():
    paths = _route_paths(public_app)
    assert not any(path.startswith("/api/sealed") for path in paths)

    client = TestClient(public_app)
    response = client.get("/")
    assert response.status_code == 200
    assert "inp-sealed-token" not in response.text
    assert "Évaluation scellée" not in response.text


def test_evaluator_app_exposes_only_sealed_surface_and_assets():
    paths = _route_paths(sealed_app)
    assert "/" in paths
    assert "/healthz" in paths
    assert "/api/sealed/suites" in paths
    assert "/api/sealed/suites/{suite_id}" in paths
    assert not any(
        path.startswith(prefix)
        for path in paths
        for prefix in ("/api/pipeline", "/api/runs", "/api/topology", "/api/models")
    )


def test_evaluator_ui_is_same_origin_no_store_and_csp_hardened():
    client = TestClient(sealed_app, base_url="https://localhost")
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in response.headers["content-security-policy"]
    assert "connect-src 'self'" in response.headers["content-security-policy"]
    assert 'id="token"' in response.text
    assert "/assets/app.js" in response.text

    script = client.get("/assets/app.js")
    assert script.status_code == 200
    assert script.headers["cache-control"] == "no-store, max-age=0"
    assert "localStorage" not in script.text
    assert "sessionStorage" not in script.text
    assert "/api/sealed" in script.text
    assert "/api/runs" not in script.text


def test_evaluator_rejects_untrusted_host_and_cross_origin_preflight():
    client = TestClient(sealed_app, base_url="https://localhost")
    assert client.get("/", headers={"Host": "attacker.invalid"}).status_code == 400

    preflight = client.options(
        "/api/sealed/suites",
        headers={
            "Origin": "https://attacker.invalid",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Sealed-Launch-Token",
        },
    )
    assert preflight.status_code == 405
    assert "access-control-allow-origin" not in preflight.headers


def test_evaluator_fails_closed_without_private_configuration(monkeypatch):
    for name in (
        "SEALED_CONTROLLER_URL",
        "SEALED_CONTROLLER_TOKEN",
        "SEALED_CONTROLLER_PUBLIC_KEY",
        "SEALED_LAUNCH_TOKEN",
        "SEALED_ZERO_RETENTION_PROVIDERS",
        "SEALED_RUNNER_COMMIT",
        "SEALED_RUNNER_IMAGE_DIGEST",
    ):
        monkeypatch.delenv(name, raising=False)

    client = TestClient(sealed_app, base_url="https://localhost")
    response = client.post(
        "/api/sealed/suites",
        headers={"X-Sealed-Launch-Token": "never-accepted"},
        json={"model": "org/model-3b", "provider": "local-zdr"},
    )
    assert response.status_code == 503
    assert response.json() == {"detail": "Sealed evaluation is unavailable"}
    assert response.headers["cache-control"] == "no-store, max-age=0"


def test_design_contains_no_public_sealed_gateway_secret_names_on_master():
    master_deploy = (ROOT / "benchmarks/ansible/playbooks/deploy_master.yml").read_text(
        encoding="utf-8"
    )
    master_vault = (
        ROOT / "benchmarks/ansible/group_vars/vault_master.yml.example"
    ).read_text(encoding="utf-8")
    for forbidden in (
        "SEALED_CONTROLLER_TOKEN",
        "SEALED_LAUNCH_TOKEN",
        "SEALED_CONTROLLER_PUBLIC_KEY",
        "vault_sealed_controller",
    ):
        assert forbidden not in master_deploy
        assert forbidden not in master_vault
