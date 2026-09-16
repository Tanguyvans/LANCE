"""Verification guidance must preserve the declared HTTP transport and service."""
import json
from urllib.parse import urlsplit

import pytest

from src.agent.phases.verification.contract import (
    _phase4_requirement_matches,
    _phase4_verification_plan,
)
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("finding_type,tool", [
    ("data_exposure", "http_get"),
    ("missing_header", "curl_headers"),
    ("info_disclosure", "curl_headers"),
    ("code_injection", "http_request"),
    ("insecure_update", "http_request"),
    ("misconfiguration", "http_get"),
])
@pytest.mark.parametrize("service,port,origin,effective_port", [
    ("https", None, "https://192.0.2.40", 443),
    ("https", 8443, "https://192.0.2.40:8443", 8443),
    ("https", 80, "https://192.0.2.40:80", 80),
    ("http", None, "http://192.0.2.40", 80),
    ("http", 443, "http://192.0.2.40:443", 443),
])
def test_http_plan_preserves_transport_and_port(
    compact, finding_type, tool, service, port, origin, effective_port,
):
    finding = {
        "type": finding_type, "service": service,
        "device_ip": "192.0.2.40", "port": port,
        "endpoint": "/resources?tenant=A%2FB",
    }
    plan = _phase4_verification_plan(finding, compact=compact)
    assert plan["tool"] == tool
    assert plan["port"] == effective_port
    assert plan["args_hint"]["url"] == origin + finding["endpoint"]
    assert _phase4_requirement_matches(plan, tool, plan["args_hint"])

    expected = urlsplit(plan["args_hint"]["url"])
    for wrong_url in (
        expected._replace(scheme="http" if service == "https" else "https").geturl(),
        expected._replace(netloc=f"192.0.2.41:{effective_port}").geturl(),
        expected._replace(netloc=f"192.0.2.40:{effective_port + 1}").geturl(),
        expected._replace(path="/other").geturl(),
        expected._replace(query="tenant=B").geturl(),
    ):
        assert not _phase4_requirement_matches(
            plan, tool, {**plan["args_hint"], "url": wrong_url},
        )


@pytest.mark.parametrize("profile", ["full", "compact"])
@pytest.mark.parametrize("finding_type", ["data_exposure", "code_injection"])
def test_worker_prompt_and_fallback_keep_https_origin(
    profile, finding_type, mock_provider, output_dir, monkeypatch,
):
    mock_provider.provider = "local-moe"
    mock_provider.model = "lance-moe"
    pipeline = Pipeline(provider=mock_provider, execution_profile=profile)
    finding = {
        "id": "V1", "device_id": "web", "device_ip": "192.0.2.40",
        "type": finding_type, "service": "https", "port": 8443,
        "endpoint": "/resources", "details": "Synthetic HTTPS finding",
    }
    (pipeline.run_dir / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [finding],
    }))
    calls = []

    def fake_probe(**kwargs):
        calls.append(kwargs)
        return json.dumps({"return_code": 1, "stderr": "Fixture: no proof"})

    monkeypatch.setattr(pipeline, "_resolve_tools", lambda _: [
        {"name": name, "description": name, "input_schema": {}, "function": fake_probe}
        for name in ("http_get", "http_request", "curl_headers")
    ])
    pipeline._run_exploit_agents(AGENTS["exploitation"])
    prompt = mock_provider.chat_with_tools.call_args.kwargs["system_prompt"]
    assert "https://192.0.2.40:8443/resources" in prompt
    assert "http://192.0.2.40" not in prompt
    if profile == "compact":
        assert calls
        assert all(call["url"] == "https://192.0.2.40:8443/resources" for call in calls)
    # An executable plan is guidance, not evidence of a vulnerability.
    aggregate = json.loads((pipeline.run_dir / "04_exploitation.json").read_text())
    assert aggregate["summary"]["confirmed"] == 0
