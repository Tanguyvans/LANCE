"""Execution profile and completion-window regression tests."""
import json
from unittest.mock import MagicMock

import pytest

from src.agent.execution_profiles import (
    PHASE3_FULL_TOOL_NAMES,
    filter_profile_tools,
    phase3_tool_names,
    resolve_execution_profile,
    resolve_execution_profile_for_model,
)
from src.agent.provider import LLMProvider
from src.api.routes.pipeline import BatchRequest, StartRequest
from src.api.routes.runs import _extract_execution_profile


def _openai_tool_response(name: str, arguments: dict, call_id: str):
    tool_call = MagicMock()
    tool_call.function.name = name
    tool_call.function.arguments = json.dumps(arguments)
    tool_call.id = call_id
    message = MagicMock(content=None, tool_calls=[tool_call])
    return MagicMock(
        choices=[MagicMock(finish_reason="tool_calls", message=message)],
        usage=None,
    )


def test_execution_profile_defaults_and_validation():
    assert resolve_execution_profile(None).name == "full"
    compact = resolve_execution_profile(" COMPACT ")
    assert compact.routed_tools is True
    assert compact.limits_for_phase(1, 20, 4096) == (12, 2048)
    assert compact.limits_for_phase(2, 50, 4096) == (50, 1536)
    assert compact.limits_for_phase(5, 80, 16384) == (50, 2048)
    assert compact.limits_for_phase(6, 25, 16384) == (12, 4096)
    assert StartRequest().execution_profile == "auto"
    assert (
        BatchRequest(batch_ids=["1"], execution_profile="compact").execution_profile
        == "compact"
    )
    with pytest.raises(ValueError, match="Unknown execution profile"):
        resolve_execution_profile("wide")


def test_auto_profile_uses_active_parameters_before_total_parameters():
    resolution = resolve_execution_profile_for_model(
        "auto",
        "moe/model",
        model_metadata={
            "parameter_count_b": 671,
            "active_parameter_count_b": 21,
            "profile_policy": "auto",
        },
    )

    assert resolution.profile.name == "compact"
    assert resolution.resolution_basis == "active_parameters"
    assert resolution.metadata()["profile_parameter_basis"] == "active"


def test_auto_profile_uses_total_parameters_and_32b_threshold():
    compact = resolve_execution_profile_for_model(
        "auto", "dense/32b", model_metadata={"parameter_count_b": 32}
    )
    full = resolve_execution_profile_for_model(
        "auto", "dense/70b", model_metadata={"parameter_count_b": 70}
    )

    assert compact.profile.name == "compact"
    assert full.profile.name == "full"
    assert full.resolution_basis == "total_parameters"


def test_profile_resolution_priority_and_missing_metadata_fallback():
    model_override = resolve_execution_profile_for_model(
        "auto",
        "dense/70b",
        model_metadata={"parameter_count_b": 70, "profile_policy": "compact"},
    )
    run_override = resolve_execution_profile_for_model(
        "full",
        "dense/3b",
        model_metadata={"parameter_count_b": 3, "profile_policy": "compact"},
    )
    missing = resolve_execution_profile_for_model(
        "auto", "unknown/model", model_metadata={}
    )

    assert model_override.profile.name == "compact"
    assert model_override.resolution_basis == "model_override"
    assert run_override.profile.name == "full"
    assert run_override.resolution_basis == "run_override"
    assert missing.profile.name == "full"
    assert missing.resolution_basis == "missing_parameters"


def test_compact_generic_phases_keep_required_tools_and_remove_noise():
    names = [
        "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
        "save_deliverable", "http_get", "mqtt_listen", "sqlmap", "nuclei_scan",
        "searchsploit", "get_network_topology", "get_device_info",
        "get_attack_surface", "get_attack_paths", "get_risk_scores",
        "search_knowledge", "ftp_list", "ssh_exec", "ssh_login",
        "telnet_connect", "try_credential", "udp_send",
    ]
    tools = [{"name": name} for name in names]

    compact = resolve_execution_profile("compact")
    compact_graph = {tool["name"] for tool in filter_profile_tools(compact, 1, tools)}
    compact_recon = {tool["name"] for tool in filter_profile_tools(compact, 2, tools)}
    compact_intrusion = {tool["name"] for tool in filter_profile_tools(compact, 5, tools)}
    compact_report = {tool["name"] for tool in filter_profile_tools(compact, 6, tools)}

    assert compact_graph == {
        "get_network_topology", "get_device_info", "get_attack_surface",
        "get_attack_paths", "get_risk_scores", "read_deliverable",
        "save_deliverable",
    }
    assert compact_recon == {
        "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
        "save_deliverable",
    }
    assert {"sqlmap", "nuclei_scan", "searchsploit"}.isdisjoint(compact_recon)
    assert compact_intrusion == {
        "ftp_list", "http_get", "mqtt_listen", "read_deliverable", "udp_send",
        "save_deliverable", "ssh_exec", "ssh_login", "telnet_connect",
        "try_credential",
    }
    assert compact_report == {
        "read_deliverable", "save_deliverable",
    }
    assert filter_profile_tools(resolve_execution_profile("full"), 2, tools) is tools


def test_full_phase3_profile_exposes_complete_safe_surface():
    names = phase3_tool_names(resolve_execution_profile("full"), {}, {})
    assert names == PHASE3_FULL_TOOL_NAMES
    assert {"http_request", "mtls_request", "udp_send", "save_deliverable"} <= names


def test_compact_phase3_profile_routes_from_discovered_services():
    profile = resolve_execution_profile("compact")
    websocket_names = phase3_tool_names(
        profile,
        {"id": "broker", "ip": "192.0.2.10"},
        {"services": [{"port": 9001, "service": "mqtt-ws"}]},
    )
    coap_names = phase3_tool_names(
        profile,
        {"id": "sensor", "ip": "192.0.2.20"},
        {"services": [{"port": 5683, "protocol": "udp", "service": "coap"}]},
    )

    assert {"curl_headers", "http_get", "http_request"} <= websocket_names
    assert "udp_send" not in websocket_names
    assert "udp_send" in coap_names
    assert "save_deliverable" in websocket_names & coap_names


def test_profile_metadata_falls_back_after_corrupt_run_meta(tmp_path):
    (tmp_path / "run_meta.json").write_text("not-json", encoding="utf-8")
    (tmp_path / "scenario_meta.json").write_text(
        json.dumps({"execution_profile": "compact"}), encoding="utf-8"
    )

    assert _extract_execution_profile(tmp_path) == "compact"


def test_openai_loop_reserves_final_turns_for_required_deliverable():
    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "openrouter"
    provider.model = "test"
    provider.client = MagicMock()
    provider.client.chat.completions.create.side_effect = [
        _openai_tool_response("scan", {"target": "a"}, "scan-1"),
        _openai_tool_response("scan", {"target": "b"}, "scan-2"),
        _openai_tool_response(
            "save_deliverable",
            {"filename": "03_device_a_vulns.json", "content": "{}"},
            "save-1",
        ),
    ]
    scan = MagicMock(return_value=json.dumps({"ok": True}))
    save = MagicMock(return_value=json.dumps({"status": "saved"}))
    tools = [
        {"name": "scan", "description": "scan", "input_schema": {}, "function": scan},
        {
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {},
            "function": save,
        },
    ]

    provider.chat_with_tools(
        "system",
        "user",
        tools,
        max_turns=4,
        required_tool="save_deliverable",
        terminate_after_tool="save_deliverable",
    )

    requests = provider.client.chat.completions.create.call_args_list
    assert len(requests) == 3
    assert [tool["function"]["name"] for tool in requests[0].kwargs["tools"]] == [
        "scan",
        "save_deliverable",
    ]
    assert [tool["function"]["name"] for tool in requests[-1].kwargs["tools"]] == [
        "save_deliverable"
    ]
    assert scan.call_count == 2
    save.assert_called_once()
