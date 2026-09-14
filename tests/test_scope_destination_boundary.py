"""Regression tests for the Phase 5 destination boundary."""

import json
from threading import Lock
from types import SimpleNamespace

import pytest

from src.agent.core.executor import wrap_tool
from src.agent.phases.intrusion.scope import _intrusion_scope_violation


SUBNET = "192.0.2.0/24"


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/?target=192.0.2.11",
        "https://evil.example/#192.0.2.11",
        "https://user192.0.2.11:password@evil.example/",
    ],
)
def test_external_url_cannot_hide_in_scope_ipv4_in_non_hostname_parts(url):
    refusal = _intrusion_scope_violation("http_get", {"url": url}, SUBNET)

    assert refusal is not None
    assert refusal["error_kind"] == "intrusion_target_unverifiable"


def test_in_scope_url_ignores_external_query_data():
    refusal = _intrusion_scope_violation(
        "http_get",
        {"url": "https://192.0.2.11/device?next=https://198.51.100.7/#external"},
        SUBNET,
    )

    assert refusal is None


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.1.example.com",
        "192.0.2.11.example.com/path",
    ],
)
def test_hostname_that_only_starts_with_an_in_scope_ipv4_is_refused(value):
    refusal = _intrusion_scope_violation("curl_headers", {"host": value}, SUBNET)

    assert refusal is not None
    assert refusal["error_kind"] == "intrusion_target_unverifiable"


def test_ipv4_literal_with_trailing_garbage_is_refused():
    refusal = _intrusion_scope_violation(
        "http_get", {"url": "http://192.0.2.11garbage/path"}, SUBNET
    )

    assert refusal is not None
    assert refusal["error_kind"] == "intrusion_target_unverifiable"


@pytest.mark.parametrize(
    "field,value",
    [
        ("ip", "192.0.2.11"),
        ("target", "192.0.2.0/25"),
        ("target", "192.0.2.10, 192.0.2.11/32"),
    ],
)
def test_direct_ipv4_cidr_and_target_list_inside_scope_are_allowed(field, value):
    assert _intrusion_scope_violation("nmap_scan", {field: value}, SUBNET) is None


@pytest.mark.parametrize("tool_name", ["ssh_exec", "ssh_login"])
def test_structured_ssh_command_destination_is_checked_for_both_tools(tool_name):
    kwargs = {
        "ip": "192.0.2.11",
        "user": "admin",
        "password": "admin",
        "command": "curl http://198.51.100.7/",
    }

    refusal = _intrusion_scope_violation(tool_name, kwargs, SUBNET)

    assert refusal is not None
    assert refusal["error_kind"] == "intrusion_command_out_of_scope"


def test_structured_ssh_login_local_id_command_is_allowed():
    assert _intrusion_scope_violation(
        "ssh_login",
        {
            "ip": "192.0.2.11",
            "user": "admin",
            "password": "admin",
            "command": "id",
        },
        SUBNET,
    ) is None


def test_ssh_login_command_string_form_remains_supported():
    assert _intrusion_scope_violation(
        "ssh_login",
        {"command_string": "ssh admin@192.0.2.11 'id'"},
        SUBNET,
    ) is None


@pytest.mark.parametrize("profile", ["full", "compact"])
def test_wrap_tool_refuses_before_fake_function_for_external_url(profile, tmp_path):
    calls = []

    def fake_function(**kwargs):
        calls.append(kwargs)
        return {"network": "must not run"}

    run = SimpleNamespace(
        run_dir=tmp_path,
        _artifact_log_lock=Lock(),
        max_tool_calls=None,
        _tool_call_count=0,
        context={"target_subnet": SUBNET},
        execution_profile=SimpleNamespace(name=profile),
    )
    tool = {"name": "http_get", "function": fake_function}

    receipt = json.loads(
        wrap_tool(run, tool, phase=5, agent="intrusion")["function"](
            url="https://evil.example/?target=192.0.2.11"
        )
    )

    assert receipt["ok"] is False
    assert receipt["error_kind"] == "intrusion_target_unverifiable"
    assert calls == []
