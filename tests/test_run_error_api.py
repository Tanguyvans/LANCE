"""Independent offline integration checks for persisted failure diagnostics."""
import json
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import openai
import pytest
from fastapi import HTTPException

from src.agent.cost_tracker import CostTracker
from src.agent.pipeline import Pipeline
from src.api.routes import runs


@pytest.fixture
def failed_run(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    instance = Pipeline.__new__(Pipeline)
    instance.run_dir = tmp_path / "offline-full-diagnostic"
    instance.run_dir.mkdir()
    instance.auto_teardown = True
    instance.dry_run = False
    instance.provider = SimpleNamespace(
        provider="ollama-umons", model="offline",
        client=SimpleNamespace(api_key="configured-api-key-for-offline-test"),
    )
    instance.tracker = CostTracker(model="offline", provider="ollama-umons")
    instance._run_teardown = Mock(return_value=True)
    instance._persist_run = Mock()
    instance._update_run_meta({
        "execution_profile": "full", "benchmark_split": "dev-public",
    })
    return instance


def _fail_intrusion(pipeline, exception, cause=None):
    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "intrusion"
        pipeline._run_results["exploitation"] = "completed"
        raise exception from cause

    pipeline._execute_run = execute
    with pytest.raises(type(exception)) as caught:
        pipeline.run()
    assert caught.value is exception
    pipeline._run_teardown.assert_called_once()
    pipeline._persist_run.assert_called_once_with("failed")
    assert not (pipeline.run_dir / "05_intrusion.json").exists()
    assert not (pipeline.run_dir / "06_report.md").exists()
    assert runs.get_run(pipeline.run_dir.name)["status"] == "failed"
    meta = runs.get_run_file(pipeline.run_dir.name, "run_meta.json")["content"]
    assert meta["execution_profile"] == "full"
    assert meta["results"] == {
        "exploitation": "completed", "intrusion": "failed:exception",
    }
    assert meta["run_error"]["phase"] == "intrusion"
    assert meta["run_error"]["exception_class"] == type(exception).__name__
    assert meta["run_error"]["traceback"][-1]["function"] == "execute"
    assert "run_error.json" in runs.get_run(pipeline.run_dir.name)["files"]
    sidecar = runs.get_run_file(pipeline.run_dir.name, "run_error.json")["content"]
    assert sidecar == meta["run_error"]
    return meta


def test_real_sdk_timeout_cause_is_readable_in_run_api(failed_run):
    request = httpx.Request("POST", "https://offline.invalid/v1/chat/completions")
    exception = openai.APITimeoutError(request=request)
    cause = httpx.ReadTimeout("upstream response timed out", request=request)
    meta = _fail_intrusion(failed_run, exception, cause)
    serialized = json.dumps(meta)
    assert "APITimeoutError" in serialized
    assert "ReadTimeout" in serialized
    assert "upstream response timed out" in serialized
    assert meta["run_error"]["exception_chain"][1]["relation"] == "cause"


def test_real_sdk_bad_request_does_not_archive_request_body(failed_run):
    request = httpx.Request(
        "POST", "https://offline.invalid/v1/chat/completions",
        headers={"Authorization": "Bearer configured-api-key-for-offline-test"},
    )
    body = {"error": {
        "message": "Context length exceeded",
        "type": "invalid_request_error",
        "request": {"messages": [{
            "role": "user", "content": "private-prompt-content-never-archive",
        }]},
    }}
    response = httpx.Response(400, request=request, json=body)
    exception = openai.BadRequestError(
        f"Error code: 400 - {body}", response=response, body=body,
    )
    meta = _fail_intrusion(failed_run, exception)
    serialized = json.dumps(meta)
    assert "BadRequestError" in serialized
    assert "Context length exceeded" in serialized
    assert meta["run_error"]["status_code"] == 400
    assert meta["run_error"]["error_type"] == "invalid_request_error"
    for artifact in failed_run.run_dir.glob("*.json"):
        content = artifact.read_text()
        assert "private-prompt-content-never-archive" not in content
        assert "configured-api-key-for-offline-test" not in content


@pytest.mark.parametrize("status,exception_type", [
    (429, openai.RateLimitError), (500, openai.InternalServerError),
])
def test_real_sdk_unwrapped_error_body_is_preserved_safely(
    failed_run, status, exception_type,
):
    body = {
        "message": "Provider temporarily unavailable",
        "type": "provider_unavailable",
        "request": {"prompt": "private-request-never-archive"},
    }
    request = httpx.Request("POST", "https://offline.invalid/v1/chat/completions")
    response = httpx.Response(status, request=request, json=body)
    exception = exception_type(f"Error code: {status} - {body}", response=response, body=body)
    meta = _fail_intrusion(failed_run, exception)
    assert meta["run_error"]["status_code"] == status
    assert meta["run_error"]["message"] == body["message"]
    assert "private-request-never-archive" not in json.dumps(meta)


def test_diagnostic_does_not_open_sealed_artifacts(failed_run):
    _fail_intrusion(failed_run, RuntimeError("offline phase failure"))
    failed_run._update_run_meta({"benchmark_split": "eval-sealed"})
    detail = runs.get_run(failed_run.run_dir.name)
    assert detail["status"] == "failed"
    assert detail["files"] == []
    for artifact in failed_run.run_dir.glob("*.json"):
        with pytest.raises(HTTPException) as caught:
            runs.get_run_file(failed_run.run_dir.name, artifact.name)
        assert caught.value.status_code == 403


def test_configured_credentials_are_masked_before_persistence(failed_run):
    key = "long-configured-key-" + "k" * 600 + "-private-key-tail"
    failed_run.provider.client.api_key = key
    failed_run.scenario_lab_config = {
        "credentials": {"iot": {"value": "private-device-credential"}},
    }
    _fail_intrusion(
        failed_run, RuntimeError(f"rejected {key}; private-device-credential"),
    )
    for artifact in failed_run.run_dir.glob("*.json"):
        text = artifact.read_text()
        assert "long-configured-key-" not in text
        assert "private-key-tail" not in text
        assert "private-device-credential" not in text


def test_old_failed_run_without_diagnostic_is_still_readable(tmp_path, monkeypatch):
    monkeypatch.setattr(runs, "OUTPUT_DIR", tmp_path)
    run_dir = tmp_path / "legacy-failed-run"
    run_dir.mkdir()
    original = {"status": "failed", "execution_profile": "full"}
    (run_dir / "run_meta.json").write_text(json.dumps(original))
    assert runs.get_run(run_dir.name)["status"] == "failed"
    assert runs.get_run_file(run_dir.name, "run_meta.json")["content"] == original
