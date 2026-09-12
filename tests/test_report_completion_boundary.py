"""Provider completion reasons must survive all the way to report status."""
import json

import httpx
import pytest

from src.agent.phases.registry import run_phase
from src.agent.registry import AGENTS
from tests.test_provider_deadline import make_provider, sdk_response
from tests.test_report_review_regressions import report_run


@pytest.mark.parametrize("profile", ["full", "compact"])
@pytest.mark.parametrize("reason,expected", [
    ("length", "partial:memo_truncated"),
    ("content_filter", "partial:memo_incomplete"),
    ("stop", "completed"),
])
def test_real_provider_finish_reason_controls_note_promotion(report_run, profile, reason, expected):
    pipeline = report_run(profile, "ok")
    requests = []
    def respond(request):
        requests.append(request)
        payload = sdk_response("local")
        payload["choices"][0]["finish_reason"] = reason
        # Even a last full sentence must not hide the provider's length limit.
        payload["choices"][0]["message"]["content"] = "Review the linked evidence."
        return httpx.Response(200, json=payload)
    provider, _ = make_provider("local", httpx.MockTransport(respond))
    pipeline.provider = provider
    original = (pipeline.run_dir / "04_exploitation.json").read_bytes()
    try:
        assert run_phase(pipeline, AGENTS["report"]) == expected
    finally:
        provider.client.close()
    assert len(requests) == 1
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["phase6_finish_reason"] == reason
    assert meta["phase6_report_contract"] == "report-v2"
    assert (pipeline.run_dir / "06_report_analysis.md").exists() == (reason == "stop")
    assert (pipeline.run_dir / "06_report.md").exists()
    assert (pipeline.run_dir / "04_exploitation.json").read_bytes() == original
    assert pipeline.tracker.total_tokens() == (10, 3)


def test_completion_metadata_is_per_call_and_fallback_updates_reason():
    responses = ["error", "length", "stop"]
    def respond(_):
        payload = sdk_response("local")
        payload["choices"][0]["finish_reason"] = responses.pop(0)
        return httpx.Response(200, json=payload)
    provider, _ = make_provider("local", httpx.MockTransport(respond))
    first, second = {"stale": True}, {"finish_reason": "length"}
    try:
        provider.chat_with_tools("s", "u", [], max_turns=1, completion_metadata=first)
        provider.chat_with_tools("s", "u", [], max_turns=1, completion_metadata=second)
        assert first == {"finish_reason": "length"}
        assert second == {"finish_reason": "stop"}
        provider.chat_with_tools("s", "u", [], max_turns=0, completion_metadata=second)
        assert second == {}
    finally:
        provider.client.close()
