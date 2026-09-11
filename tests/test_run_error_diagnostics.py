"""Focused tests for secret-safe terminal failure diagnostics."""
import json
import subprocess
import sys
from pathlib import Path
from threading import Event
from unittest.mock import Mock

import pytest

from src.agent.core.run_diagnostics import build_run_error_diagnostic
from src.agent.cost_tracker import BudgetExceeded, CostTracker
from src.agent.pipeline import Pipeline


def test_unclosed_escaped_secret_cannot_stall_cleanup():
    # A subprocess timeout makes pathological regex backtracking a bounded
    # test failure instead of hanging the test runner (or production cleanup).
    script = r'''
from src.agent.core.run_diagnostics import build_run_error_diagnostic
for count in (20000, 20001):
    message = "password='" + "\\" * count
    result = build_run_error_diagnostic(RuntimeError(message), phase="intrusion")
    assert result["message"] == "password='[REDACTED]"
'''
    subprocess.run([sys.executable, "-c", script], timeout=5, check=True, capture_output=True)


def test_explicitly_configured_short_secret_is_masked():
    diagnostic = build_run_error_diagnostic(
        RuntimeError("authentication rejected: p7!"),
        phase="intrusion", secret_values={"p7!"},
    )
    assert "p7!" not in json.dumps(diagnostic)


def test_diagnostic_redacts_credentials_and_omits_source_lines_and_locals():
    secret = "configured-secret-value"
    local_prompt = "prompt-local-value"
    try:
        local_value = local_prompt
        raise RuntimeError(
            "POST https://operator:password-value@example.invalid/api?token=query-token "
            f"Authorization: Bearer {secret} api_key={secret}"
        )
    except RuntimeError as exc:
        diagnostic = build_run_error_diagnostic(
            exc,
            phase="intrusion",
            secret_values={secret, "password-value", "query-token"},
        )

    serialized = json.dumps(diagnostic)
    assert diagnostic["phase"] == "intrusion"
    assert diagnostic["exception_class"] == "RuntimeError"
    assert "[REDACTED]" in serialized
    assert secret not in serialized
    assert "password-value" not in serialized
    assert "query-token" not in serialized
    assert local_prompt not in serialized
    assert all(set(frame) == {"file", "line", "function"}
               for frame in diagnostic["traceback"])
    assert all("source" not in frame and "locals" not in frame
               for frame in diagnostic["traceback"])
    assert "local_value" not in serialized


def test_redaction_happens_before_output_boundary_and_masks_quoted_spaces():
    secret = "secret-that-crosses-the-output-boundary"
    message = "x" * 1010 + secret + " password='quoted\nvalue with spaces'"
    diagnostic = build_run_error_diagnostic(
        RuntimeError(message), phase="recon", secret_values={secret}
    )

    serialized = json.dumps(diagnostic)
    assert secret not in serialized
    assert secret[:12] not in serialized
    assert "quoted\\nvalue with spaces" not in serialized


def test_redaction_handles_escaped_and_unclosed_quoted_assignments():
    diagnostic = build_run_error_diagnostic(
        RuntimeError("password='escaped\\' secret' password='unclosed secret"),
        phase="recon",
    )

    serialized = json.dumps(diagnostic)
    assert "escaped" not in diagnostic["message"]
    assert "unclosed secret" not in serialized


def test_traceback_keeps_innermost_frames():
    def recurse(depth):
        if depth:
            return recurse(depth - 1)
        return leaf()

    def leaf():
        raise RuntimeError("deep failure")

    try:
        recurse(40)
    except RuntimeError as exc:
        diagnostic = build_run_error_diagnostic(exc, phase="intrusion")

    assert len(diagnostic["traceback"]) == 32
    assert diagnostic["traceback"][-1]["function"] == "leaf"


def test_successful_run_has_no_fake_diagnostic(tmp_path):
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.run_dir = tmp_path
    pipeline.auto_teardown = True
    pipeline.dry_run = False
    pipeline.tracker = Mock(spec=CostTracker)
    pipeline.tracker.to_json.return_value = json.dumps({"total_cost_usd": 0})
    pipeline.tracker.total_cost.return_value = 0
    pipeline.tracker.total_tokens.return_value = (0, 0)
    pipeline.tracker.summary.return_value = {"phases": []}
    pipeline.tracker.budget_exhausted = False
    pipeline._run_teardown = Mock(return_value=True)
    pipeline._persist_run = Mock()
    pipeline._execute_run = Mock(return_value={})

    assert pipeline.run() == {}

    metadata = json.loads((tmp_path / "run_meta.json").read_text())
    assert "run_error" not in metadata
    assert not (tmp_path / "run_error.json").exists()


def test_sidecar_failure_does_not_change_primary_exception_or_metadata(tmp_path, monkeypatch):
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.run_dir = tmp_path
    pipeline.auto_teardown = True
    pipeline.dry_run = False
    pipeline.tracker = Mock(spec=CostTracker)
    pipeline.tracker.to_json.return_value = json.dumps({"total_cost_usd": 0})
    pipeline.tracker.total_cost.return_value = 0
    pipeline.tracker.total_tokens.return_value = (0, 0)
    pipeline.tracker.summary.return_value = {"phases": []}
    pipeline.tracker.budget_exhausted = False
    pipeline._run_teardown = Mock(return_value=True)
    pipeline._persist_run = Mock()
    original = RuntimeError("primary failure")

    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "intrusion"
        raise original

    pipeline._execute_run = execute
    write_text = Path.write_text

    def fail_sidecar(path, *args, **kwargs):
        if path.name.startswith(".run_error."):
            raise OSError("sidecar unavailable")
        return write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_sidecar)

    with pytest.raises(RuntimeError) as caught:
        pipeline.run()

    assert caught.value is original
    metadata = json.loads((tmp_path / "run_meta.json").read_text())
    assert metadata["status"] == "failed"
    assert metadata["run_error"]["exception_class"] == "RuntimeError"
    pipeline._run_teardown.assert_called_once()


def _minimal_pipeline(tmp_path):
    pipeline = Pipeline.__new__(Pipeline)
    pipeline.run_dir = tmp_path
    pipeline.auto_teardown = True
    pipeline.dry_run = False
    pipeline.tracker = Mock(spec=CostTracker)
    pipeline.tracker.to_json.return_value = json.dumps({"total_cost_usd": 0})
    pipeline.tracker.total_cost.return_value = 0
    pipeline.tracker.total_tokens.return_value = (0, 0)
    pipeline.tracker.summary.return_value = {"phases": []}
    pipeline.tracker.budget_exhausted = False
    pipeline._run_teardown = Mock(return_value=True)
    pipeline._persist_run = Mock()
    return pipeline


def test_metadata_failure_and_cleanup_failure_keep_primary_diagnostic(tmp_path):
    pipeline = _minimal_pipeline(tmp_path)
    pipeline._update_run_meta = Mock(side_effect=OSError("metadata unavailable"))
    pipeline._run_teardown = Mock(side_effect=OSError("cleanup unavailable"))
    original = RuntimeError("primary failure")

    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "intrusion"
        raise original

    pipeline._execute_run = execute
    with pytest.raises(RuntimeError) as caught:
        pipeline.run()

    assert caught.value is original
    sidecar = json.loads((tmp_path / "run_error.json").read_text())
    assert sidecar["exception_class"] == "RuntimeError"
    pipeline._run_teardown.assert_called_once()


def test_diagnostic_builder_failure_never_masks_primary_exception(tmp_path, monkeypatch):
    pipeline = _minimal_pipeline(tmp_path)
    original = RuntimeError("original intrusion failure")

    def execute(*_):
        pipeline._scenario_owned = True
        pipeline._active_phase = "intrusion"
        raise original

    pipeline._execute_run = execute
    monkeypatch.setattr(
        "src.agent.pipeline.build_run_error_diagnostic",
        Mock(side_effect=ValueError("diagnostic failed")),
    )
    with pytest.raises(RuntimeError) as caught:
        pipeline.run()
    assert caught.value is original
    pipeline._run_teardown.assert_called_once()
    meta = json.loads((tmp_path / "run_meta.json").read_text())
    assert meta["status"] == "failed"
    assert "run_error" not in meta
    assert not (tmp_path / "run_error.json").exists()


def test_budget_exception_is_diagnostic_without_changing_budget_status(tmp_path):
    pipeline = _minimal_pipeline(tmp_path)
    pipeline._execute_run = Mock(side_effect=BudgetExceeded("limit reached"))

    with pytest.raises(BudgetExceeded):
        pipeline.run()

    metadata = json.loads((tmp_path / "run_meta.json").read_text())
    assert metadata["status"] == "budget_exceeded"
    assert metadata["run_error"]["exception_class"] == "BudgetExceeded"


def test_normal_stop_has_no_primary_error_diagnostic(tmp_path):
    pipeline = _minimal_pipeline(tmp_path)
    stop = Event()

    def execute(*_):
        stop.set()
        return {}

    pipeline._execute_run = execute
    pipeline.run(stop_event=stop)

    metadata = json.loads((tmp_path / "run_meta.json").read_text())
    assert metadata["status"] == "stopped"
    assert "run_error" not in metadata
    assert not (tmp_path / "run_error.json").exists()


def test_sidecar_replaces_symlink_without_touching_external_target(tmp_path):
    pipeline = _minimal_pipeline(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("external content")
    sidecar = tmp_path / "run_error.json"
    sidecar.symlink_to(outside)
    pipeline._execute_run = Mock(side_effect=RuntimeError("primary failure"))

    with pytest.raises(RuntimeError):
        pipeline.run()

    assert outside.read_text() == "external content"
    assert sidecar.is_file()
    assert not sidecar.is_symlink()
    assert json.loads(sidecar.read_text())["exception_class"] == "RuntimeError"
