"""Dynamic model selector API tests."""
from __future__ import annotations


def test_dynamic_codex_and_openrouter_catalogs(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "models.db"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "configured")

    from src.api.routes import models

    router_model = {
        "id": "vendor/current-tool-model",
        "name": "Current Tool Model",
        "description": "fresh",
        "context_length": 128_000,
        "created": 1,
        "pricing": {"prompt": "0.000001", "completion": "0.000002"},
        "supported_parameters": ["tools"],
        "architecture": {"output_modalities": ["text"]},
    }
    monkeypatch.setattr(
        models, "_load_openrouter_catalog", lambda **_kwargs: [router_model]
    )
    monkeypatch.setattr(models, "_load_pricing", lambda: {
        router_model["id"]: {"input": 1.0, "output": 2.0}
    })
    monkeypatch.setattr(models, "get_codex_catalog", lambda **_kwargs: {
        "available": True,
        "account_type": "chatgpt",
        "plan_type": "pro",
        "error": None,
        "auth_command": "codex login",
        "models": [{
            "id": "gpt-current",
            "label": "GPT Current",
            "description": "current",
            "recommended": True,
            "reasoning_efforts": ["medium"],
            "default_reasoning_effort": "medium",
            "service_tiers": [],
            "upgrade": None,
        }],
    })

    response = models.list_models()
    by_id = {model["id"]: model for model in response["models"]}

    assert by_id["gpt-current"]["provider"] == "codex"
    assert by_id["gpt-current"]["subscription"] is True
    assert by_id["gpt-current"]["available"] is True
    assert by_id[router_model["id"]]["provider"] == "openrouter"
    assert by_id[router_model["id"]]["input_per_mtok"] == 1.0
    assert response["providers"]["codex"]["plan_type"] == "pro"
    assert response["providers"]["openrouter"]["model_count"] == 1


def test_subscription_without_credentials_is_not_available(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "models.db"))
    monkeypatch.delenv("MINIMAX_API_KEY", raising=False)
    from src.api.routes import models

    monkeypatch.setattr(models, "_load_openrouter_catalog", lambda **_kwargs: [])
    monkeypatch.setattr(models, "_load_pricing", lambda: {})
    monkeypatch.setattr(models, "get_codex_catalog", lambda **_kwargs: {
        "available": False,
        "account_type": None,
        "plan_type": None,
        "models": [],
        "error": "not logged in",
        "auth_command": "codex login",
    })

    response = models.list_models()
    minimax = [model for model in response["models"] if model["provider"] == "minimax"]
    assert minimax
    assert all(model["available"] is False for model in minimax)
