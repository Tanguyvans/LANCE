"""Removed providers cannot run, while historical records remain available."""
import sys
from unittest.mock import Mock

import pytest

from src.agent.provider import LLMProvider


def test_removed_provider_rejected_before_registry_or_client_setup(monkeypatch):
    resolve = Mock(side_effect=AssertionError("must not query registry"))
    monkeypatch.setattr("src.agent.provider._resolve_provider_cfg", resolve)
    with pytest.raises(ValueError, match="Anthropic is no longer supported"):
        LLMProvider(provider="anthropic", model="historical-model")
    resolve.assert_not_called()


def test_no_implicit_provider_or_legacy_cloud_model():
    with pytest.raises(TypeError):
        LLMProvider()
    with pytest.raises(ValueError, match="explicit model"):
        LLMProvider(provider="openrouter")


@pytest.mark.parametrize("environment,arguments", [
    (None, []), (None, ["--provider", "anthropic"]), ("anthropic", []),
])
def test_cli_rejects_missing_or_removed_provider_without_starting(monkeypatch, environment, arguments):
    from src.agent import __main__ as cli
    if environment is None:
        monkeypatch.delenv("AGENT_PROVIDER", raising=False)
    else:
        monkeypatch.setenv("AGENT_PROVIDER", environment)
    monkeypatch.setattr(sys, "argv", ["agent", *arguments])
    create = Mock(side_effect=AssertionError("must not create a provider"))
    monkeypatch.setattr(cli, "LLMProvider", create)
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    create.assert_not_called()


@pytest.mark.parametrize("environment,arguments,expected", [
    (None, ["--provider", "minimax"], "minimax"),
    ("local", [], "local"),
    ("anthropic", ["--provider", "qwen"], "qwen"),
])
def test_cli_preserves_explicit_provider_choice(monkeypatch, environment, arguments, expected):
    from src.agent import __main__ as cli
    if environment is None:
        monkeypatch.delenv("AGENT_PROVIDER", raising=False)
    else:
        monkeypatch.setenv("AGENT_PROVIDER", environment)
    monkeypatch.setattr(sys, "argv", ["agent", *arguments])
    create = Mock(side_effect=RuntimeError("offline provider boundary"))
    monkeypatch.setattr(cli, "LLMProvider", create)
    with pytest.raises(RuntimeError, match="offline provider boundary"):
        cli.main()
    assert create.call_args.kwargs["provider"] == expected


def test_seed_does_not_create_removed_provider_or_delete_history(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "registry.db"))
    from src.db import database as db, seed
    db.init_db()
    seed.seed_providers()
    assert db.get_provider("anthropic") is None
    assert db.get_provider("minimax") is not None
    db.upsert_provider("anthropic", default_model="historical-model")
    db.upsert_model("historical-model", provider="anthropic")
    seed.seed_providers()
    assert db.get_provider("anthropic")["default_model"] == "historical-model"
    assert db.get_model("historical-model") is not None
