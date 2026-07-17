"""Runtime non-retention guards for the sealed worker entry point."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from src.agent import worker


def _contract_payload() -> dict:
    return {
        "schema_version": "1",
        "session_id": "12345678-1234-4234-8234-123456789abc",
        "scenario_id": "20",
        "split": "eval-sealed",
        "benchmark_version": "2.0.0",
        "scope": {"ingress_cidrs": ["10.77.20.0/24"], "entrypoints": []},
        "limits": {
            "expires_at": "2999-01-01T00:00:00+00:00",
            "max_cost_usd": 1.0,
            "max_tool_calls": 10,
        },
        "artifact_schema_version": "1",
    }


def _prepare_worker(tmp_path: Path, monkeypatch, fake_pipeline) -> tuple[Path, Path]:
    monkeypatch.chdir(tmp_path)
    for name in tuple(os.environ):
        if name not in worker._WORKER_ENV_ALLOWLIST and (
            name.startswith(("AWS_", "AZURE_", "GOOGLE_", "GITHUB_", "SEALED_"))
            or any(marker in name.upper() for marker in worker._SECRET_NAME_MARKERS)
        ):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SEALED_INFERENCE_BASE_URL", "http://inference-gateway:8080/v1")

    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps(_contract_payload()), encoding="utf-8")
    output = tmp_path / "scratch"
    receipt = tmp_path / "control" / "receipt.json"

    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "Pipeline", fake_pipeline)
    monkeypatch.setattr(worker, "LLMProvider", lambda **_kwargs: object())
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "worker",
            "--contract", str(contract),
            "--model", "org/model-3b",
            "--output-dir", str(output),
            "--receipt", str(receipt),
        ],
    )
    return output, receipt


def test_worker_emits_only_file_receipt_and_no_stdout(tmp_path, monkeypatch, capsys):
    class FakePipeline:
        def __init__(self, **_kwargs):
            self.run_dir = tmp_path / "scratch" / "run"
            self.run_dir.mkdir(parents=True)

        def run(self):
            print("PRIVATE-CANARY finding host=10.77.20.9")
            (self.run_dir / "run_meta.json").write_text("{}", encoding="utf-8")
            return {"private": "PRIVATE-CANARY"}

    _output, receipt_path = _prepare_worker(tmp_path, monkeypatch, FakePipeline)
    worker.main()

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert receipt["status"] == "complete"
    assert receipt["session_id"] == _contract_payload()["session_id"]
    assert "scenario_id" not in receipt
    assert "run_dir" not in receipt
    assert "pipeline_results" not in receipt
    assert "PRIVATE-CANARY" not in receipt_path.read_text(encoding="utf-8")


def test_worker_failure_receipt_never_serializes_exception(tmp_path, monkeypatch, capsys):
    class FailingPipeline:
        def __init__(self, **_kwargs):
            self.run_dir = tmp_path / "scratch" / "run"

        def run(self):
            raise RuntimeError("PRIVATE-CANARY prompt and tool result")

    _output, receipt_path = _prepare_worker(tmp_path, monkeypatch, FailingPipeline)

    with pytest.raises(SystemExit) as exc:
        worker.main()

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    raw = receipt_path.read_text(encoding="utf-8")
    assert "PRIVATE-CANARY" not in raw
    assert json.loads(raw) == {
        "session_id": _contract_payload()["session_id"],
        "status": "failed",
    }


@pytest.mark.parametrize(
    "name",
    [
        "OPENROUTER_API_KEY",
        "HF_TOKEN",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "SEALED_LAUNCH_TOKEN",
    ],
)
def test_worker_refuses_any_provider_or_control_secret(tmp_path, monkeypatch, name):
    class NeverPipeline:
        def __init__(self, **_kwargs):
            raise AssertionError("pipeline must not start")

    _output, _receipt = _prepare_worker(tmp_path, monkeypatch, NeverPipeline)
    monkeypatch.setenv(name, "must-not-enter-worker")

    with pytest.raises(SystemExit) as exc:
        worker.main()

    assert exc.value.code == 2


def test_worker_pipeline_receives_only_allowlisted_environment(tmp_path, monkeypatch):
    observed = {}

    class FakePipeline:
        def __init__(self, **_kwargs):
            observed.update(os.environ)
            self.run_dir = tmp_path / "scratch" / "run"
            self.run_dir.mkdir(parents=True)

        def run(self):
            (self.run_dir / "run_meta.json").write_text("{}", encoding="utf-8")

    monkeypatch.setenv("BENIGN_BUT_UNNEEDED", "must-be-removed")
    _output, _receipt = _prepare_worker(tmp_path, monkeypatch, FakePipeline)
    # _prepare_worker intentionally preserves unknown non-secret variables so
    # the worker's allowlist, not the test fixture, proves their removal.
    monkeypatch.setenv("BENIGN_BUT_UNNEEDED", "must-be-removed")
    worker.main()

    assert "BENIGN_BUT_UNNEEDED" not in observed
    assert observed["SEALED_INFERENCE_BASE_URL"] == "http://inference-gateway:8080/v1"
    assert observed["HOME"].startswith(str(tmp_path))
    assert all(
        name in worker._WORKER_ENV_ALLOWLIST or name in {"HOME", "TMPDIR", "XDG_CACHE_HOME"}
        for name in observed
    )
