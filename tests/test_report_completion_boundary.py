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
    assert len(requests) == (8 if reason == "length" else 4)
    meta = json.loads((pipeline.run_dir / "run_meta.json").read_text())
    assert meta["phase6_finish_reason"] == reason
    assert meta["phase6_report_contract"] == "sectioned-report"
    assert meta["phase6_section_count"] == 4
    assert (pipeline.run_dir / "06_report_analysis.md").exists() == (reason == "stop")
    assert (pipeline.run_dir / "06_report.md").exists()
    assert (pipeline.run_dir / "04_exploitation.json").read_bytes() == original
    assert pipeline.tracker.total_tokens() == ((80, 24) if reason == "length" else (40, 12))


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
        assert first["finish_reason"] == "length"
        assert second["finish_reason"] == "stop"
        assert first["output_tokens"] == second["output_tokens"] == 3
        assert first["reasoning_tokens"] is None
        provider.chat_with_tools("s", "u", [], max_turns=0, completion_metadata=second)
        assert second == {}
    finally:
        provider.client.close()


def test_reasoning_option_is_per_call_and_survives_fallback():
    requests = []
    def respond(request):
        requests.append(json.loads(request.content))
        payload = sdk_response("ollama-test")
        payload["choices"][0]["finish_reason"] = "error" if len(requests) == 1 else "stop"
        payload["choices"][0]["message"]["reasoning"] = "private reasoning"
        payload["usage"]["completion_tokens_details"] = {"reasoning_tokens": 2}
        return httpx.Response(200, json=payload)

    provider, _ = make_provider("ollama-test", httpx.MockTransport(respond))
    metadata = {}
    try:
        provider.chat_with_tools("s", "u", [], max_turns=1, reasoning_effort="none", completion_metadata=metadata)
        provider.chat_with_tools("s", "u", [], max_turns=1)
    finally:
        provider.client.close()
    assert [r.get("reasoning_effort") for r in requests] == ["none", "none", None]
    assert metadata["reasoning_tokens"] == 2
    assert metadata["reasoning_chars"] == len("private reasoning")
    assert "private reasoning" not in json.dumps(metadata)


@pytest.mark.parametrize("provider_name,effort", [("ollama", "none"), ("ollama-umons", "none"), ("local", None), ("qwen", None)])
def test_report_reasoning_request_is_limited_to_ollama(report_run, provider_name, effort):
    requests = []
    def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=sdk_response(provider_name))
    p = report_run("full", "ok")
    provider, _ = make_provider(provider_name, httpx.MockTransport(respond))
    p.provider = provider
    try:
        assert run_phase(p, AGENTS["report"]) == "completed"
    finally:
        provider.client.close()
    assert len(requests) == 4
    assert all(r.get("reasoning_effort") == effort for r in requests)
    assert all("tools" not in r for r in requests)
