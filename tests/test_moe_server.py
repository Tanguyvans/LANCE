"""Focused tests for Qwen tool-call parsing in the local HMoE server."""
from __future__ import annotations

import json

from src.agent.moe_server import _parse_qwen_tool_calls


def _first_call(text: str) -> tuple[str, dict]:
    content, calls = _parse_qwen_tool_calls(text)
    assert len(calls) == 1
    return content, calls[0]


def test_parses_native_qwen_tool_call() -> None:
    content, call = _first_call(
        '<tool_call>{"name":"nmap_scan","arguments":{"target":"192.0.2.1"}}</tool_call>'
    )
    assert content == ""
    assert call["function"]["name"] == "nmap_scan"
    assert json.loads(call["function"]["arguments"]) == {"target": "192.0.2.1"}


def test_repairs_missing_outer_brace_from_moe() -> None:
    _, call = _first_call(
        '<tool_call>{"name":"get_attack_surface","arguments":{}</tool_call>'
    )
    assert call["function"]["name"] == "get_attack_surface"
    assert json.loads(call["function"]["arguments"]) == {}


def test_repairs_wrong_root_closer_from_moe() -> None:
    _, call = _first_call(
        '<tool_call>{"name":"nmap_scan","arguments":{"target":"192.0.2.1"}]</tool_call>'
    )
    assert json.loads(call["function"]["arguments"]) == {"target": "192.0.2.1"}


def test_repairs_unterminated_deliverable_closed_with_wrong_tag() -> None:
    _, call = _first_call(
        '<tool_call>{"name":"save_deliverable","arguments":'
        '{"filename":"01_graph_analysis.md","content":"# Report\\n\\nDone\\n\\n</tool_response>'
    )
    assert call["function"]["name"] == "save_deliverable"
    assert json.loads(call["function"]["arguments"]) == {
        "filename": "01_graph_analysis.md",
        "content": "# Report\n\nDone\n\n",
    }


def test_rejects_non_object_arguments() -> None:
    content, calls = _parse_qwen_tool_calls(
        '<tool_call>{"name":"nmap_scan","arguments":"192.0.2.1"}</tool_call>'
    )
    assert content == ""
    assert calls == []


def test_parses_multiple_calls_and_preserves_prose() -> None:
    content, calls = _parse_qwen_tool_calls(
        'Starting. <tool_call>{"name":"a","arguments":{}}</tool_call>'
        '<tool_call>{"name":"b","arguments":{"x":1}}</tool_call>'
    )
    assert content == "Starting."
    assert [call["function"]["name"] for call in calls] == ["a", "b"]
