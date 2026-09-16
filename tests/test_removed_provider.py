"""Removed providers cannot run, while historical records remain available."""
import sys
import json
from unittest.mock import Mock

import pytest

from src.agent.provider import LLMProvider, REMOVED_PROVIDERS


@pytest.mark.parametrize("provider", sorted(REMOVED_PROVIDERS))
def test_removed_provider_rejected_before_registry_or_client_setup(monkeypatch, provider):
    resolve = Mock(side_effect=AssertionError("must not query registry"))
    monkeypatch.setattr("src.agent.provider._resolve_provider_cfg", resolve)
    with pytest.raises(ValueError, match="is no longer supported"):
        LLMProvider(provider=provider, model="historical-model")
    resolve.assert_not_called()


def test_no_implicit_provider_or_legacy_cloud_model():
    with pytest.raises(TypeError):
        LLMProvider()
    with pytest.raises(ValueError, match="no longer supported"):
        LLMProvider(provider="openrouter")


@pytest.mark.parametrize("environment,arguments", [
    (None, []), (None, ["--provider", "anthropic"]), ("anthropic", []),
    (None, ["--provider", "codex"]), ("codex", []),
    (None, ["--provider", "openrouter"]), ("openrouter", []),
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


@pytest.mark.parametrize("provider", sorted(REMOVED_PROVIDERS))
def test_seed_does_not_create_removed_provider_or_delete_history(tmp_path, monkeypatch, provider):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "registry.db"))
    from src.db import database as db, seed
    db.init_db()
    seed.seed_providers()
    assert db.get_provider(provider) is None
    assert db.get_provider("minimax") is not None
    db.upsert_provider(provider, default_model="historical-model")
    db.upsert_model("historical-model", provider=provider)
    seed.seed_providers()
    assert db.get_provider(provider)["default_model"] == "historical-model"
    assert db.get_model("historical-model") is not None


@pytest.mark.parametrize("provider", sorted(REMOVED_PROVIDERS))
def test_api_rejects_retired_provider_before_background_execution(provider):
    from pydantic import ValidationError
    from src.api.routes.pipeline import StartRequest, BatchRequest
    from src.api.routes.runs import LLMJudgeRequest
    with pytest.raises(ValidationError, match="no longer supported"):
        StartRequest(model="old-model", provider=provider)
    with pytest.raises(ValidationError, match="no longer supported"):
        BatchRequest(model="old-model", provider=provider, batch_ids=["1"])
    with pytest.raises(ValidationError, match="no longer supported"):
        LLMJudgeRequest(model="old-model", provider=provider)


def test_api_requires_explicit_provider_and_model():
    from pydantic import ValidationError
    from src.api.routes.pipeline import StartRequest, BatchRequest
    with pytest.raises(ValidationError):
        StartRequest()
    with pytest.raises(ValidationError):
        BatchRequest(batch_ids=["1"])


@pytest.mark.parametrize("provider", [None, *sorted(REMOVED_PROVIDERS)])
def test_worker_rejects_missing_or_retired_provider_before_contract_loading(monkeypatch, provider):
    from src.agent import worker
    monkeypatch.delenv("AGENT_PROVIDER", raising=False)
    args = ["worker", "--contract", "unused-contract.json"]
    if provider:
        args += ["--provider", provider]
    monkeypatch.setattr(sys, "argv", args)
    load = Mock(side_effect=AssertionError("must not load contract"))
    monkeypatch.setattr(worker, "_load_contract", load)
    with pytest.raises(SystemExit) as error:
        worker.main()
    assert error.value.code == 2
    load.assert_not_called()


@pytest.mark.parametrize("metadata,expected_provider,expected_status", [
    ({"model": "old/gpt", "provider": "openrouter", "status": "failed"}, "openrouter", "failed"),
    ({"model": "gpt-old", "provider": "codex", "status": "completed"}, "codex", "completed"),
    ({"model": "qwen-local"}, "unknown", "partial"),
])
def test_history_backfill_does_not_guess_provider_or_success(tmp_path, monkeypatch, metadata, expected_provider, expected_status):
    from src.db import database as db, seed
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "registry.db"))
    root = tmp_path / "runs"
    run = root / "historical-run"
    run.mkdir(parents=True)
    (run / "run_meta.json").write_text(json.dumps(metadata))
    (run / "06_report.md").write_text("A report is not an execution verdict.")
    monkeypatch.setattr(seed, "_OUTPUT_DIR", root)
    db.init_db()
    assert seed.backfill_runs() == 1
    with db.get_conn() as conn:
        row = conn.execute("SELECT provider, status FROM runs").fetchone()
    assert row["provider"] == expected_provider
    assert row["status"] == expected_status
