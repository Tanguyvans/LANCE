"""Focused tests for Qwen tool-call parsing in the local HMoE server."""
from __future__ import annotations

import json

from src.agent.moe_server import (
    Message,
    _attach_runtime_state,
    _build_execution_state,
    _compact_hf_messages,
    _forced_recovery_tool,
    _generation_token_budget,
    _parse_qwen_tool_calls,
    _prepare_prompt,
    _select_model_tools,
)


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



def _assistant_call(call_id: str, name: str, arguments: dict) -> Message:
    return Message(
        role="assistant",
        tool_calls=[{
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)},
        }],
    )


def test_execution_state_tracks_rejected_save_and_missing_requirement() -> None:
    messages = [
        _assistant_call("save-1", "save_deliverable", {
            "filename": "02_recon.md", "content": "draft",
        }),
        Message(
            role="tool",
            tool_call_id="save-1",
            content=json.dumps({
                "ok": False,
                "error_kind": "recon_contract_incomplete",
                "missing_requirements": [{
                    "requirement": "phase1_context",
                    "tool": "read_deliverable",
                    "filename": "01_graph_analysis.md",
                }],
            }),
        ),
    ]

    state = _build_execution_state(messages)

    assert state["rejected_saves"] == 1
    assert state["outstanding_requirements"][0]["requirement"] == "phase1_context"
    assert _forced_recovery_tool(state, [{
        "type": "function",
        "function": {"name": "read_deliverable"},
    }]) == ("read_deliverable", {"filename": "01_graph_analysis.md"})


def test_execution_state_uses_proactive_recon_progress_before_save() -> None:
    messages = [
        _assistant_call("arp-1", "arp_scan", {}),
        Message(
            role="tool",
            tool_call_id="arp-1",
            content=json.dumps({
                "hosts": [{"ip": "192.168.100.12"}],
                "recon_progress": {
                    "ready_to_save": False,
                    "missing_requirements": [{
                        "requirement": "subnet_discovery",
                        "tool": "nmap_discovery",
                        "target": "192.168.100.0/24",
                    }],
                    "targets": [{
                        "target": "192.168.100.12",
                        "device_id": "s1-web",
                        "missing_ports": [22, 80, 443],
                    }],
                },
            }),
        ),
    ]

    state = _build_execution_state(messages)

    assert state["rejected_saves"] == 0
    assert state["outstanding_requirements"][0]["requirement"] == "subnet_discovery"
    assert state["recon_progress"]["targets"][0]["target"] == "192.168.100.12"
    assert _forced_recovery_tool(state, [{
        "type": "function",
        "function": {"name": "nmap_discovery"},
    }]) == ("nmap_discovery", {"target": "192.168.100.0/24"})


def test_successful_recovery_clears_outstanding_requirement() -> None:
    messages = [
        _assistant_call("save-1", "save_deliverable", {"content": "draft"}),
        Message(role="tool", tool_call_id="save-1", content=json.dumps({
            "ok": False,
            "error_kind": "recon_contract_incomplete",
            "missing_requirements": [{
                "requirement": "phase1_context",
                "tool": "read_deliverable",
                "filename": "01_graph_analysis.md",
            }],
        })),
        _assistant_call("read-1", "read_deliverable", {
            "filename": "01_graph_analysis.md",
        }),
        Message(role="tool", tool_call_id="read-1", content='{"content":"graph"}'),
    ]

    state = _build_execution_state(messages)

    assert state["outstanding_requirements"] == []
    assert state["successful_counts"] == {"read_deliverable": 1}
    assert _forced_recovery_tool(state, []) is None


def test_runtime_state_is_attached_to_latest_message() -> None:
    enriched = _attach_runtime_state(
        [{"role": "tool", "content": '{"ok":false}'}],
        {
            "successful_counts": {"arp_scan": 1},
            "rejected_saves": 1,
            "outstanding_requirements": [{
                "requirement": "phase1_context",
                "tool": "read_deliverable",
                "filename": "01_graph_analysis.md",
            }],
        },
    )
    assert "RUNTIME EXECUTION STATE" in enriched[-1]["content"]
    assert "read_deliverable" in enriched[-1]["content"]
    assert "Do NOT call save_deliverable" in enriched[-1]["content"]


def test_runtime_state_reports_target_coverage_and_ready_to_save() -> None:
    enriched = _attach_runtime_state(
        [{"role": "tool", "content": '{"status":"ok"}'}],
        {
            "successful_counts": {"nmap_scan": 4},
            "rejected_saves": 0,
            "outstanding_requirements": [],
            "recon_progress": {
                "ready_to_save": True,
                "targets": [{
                    "target": "192.168.100.12",
                    "device_id": "s1-web",
                    "missing_ports": [],
                }],
            },
        },
    )

    assert "192.168.100.12 (s1-web): complete" in enriched[-1]["content"]
    assert "call save_deliverable exactly once" in enriched[-1]["content"]
    assert "do not run another baseline scan" in enriched[-1]["content"]


def test_compaction_removes_large_rejected_draft_and_keeps_call_identity() -> None:
    messages = [
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "save-1",
                "type": "function",
                "function": {
                    "name": "save_deliverable",
                    "arguments": {"filename": "02_recon.md", "content": "x" * 5000},
                },
            }],
        },
        {"role": "tool", "tool_call_id": "save-1", "content": '{"ok":false}'},
    ]

    compacted = _compact_hf_messages(messages, aggressive=True)

    arguments = compacted[0]["tool_calls"][0]["function"]["arguments"]
    assert arguments["content"].startswith("[rejected draft compacted:")
    assert compacted[0]["tool_calls"][0]["id"] == "save-1"
    assert compacted[1]["tool_call_id"] == "save-1"



def test_contract_recovery_refuses_non_recon_or_mutating_tool() -> None:
    state = {
        "outstanding_requirements": [{
            "requirement": "unexpected",
            "tool": "ssh_exec",
            "target": "192.0.2.1",
        }],
    }
    tools = [{"type": "function", "function": {"name": "ssh_exec"}}]
    assert _forced_recovery_tool(state, tools) is None


def test_prepare_prompt_compacts_history_over_training_budget() -> None:
    class FakeTokenizer:
        def apply_chat_template(self, messages, **kwargs):
            return json.dumps(messages)

        def __call__(self, prompt, **kwargs):
            return {"input_ids": list(range(max(1, len(prompt) // 10)))}

    messages = []
    for index in range(8):
        call_id = f"scan-{index}"
        messages.extend([
            _assistant_call(call_id, "nmap_scan", {"target": f"192.0.2.{index}"}),
            Message(
                role="tool",
                tool_call_id=call_id,
                content=json.dumps({"stdout": "unimportant output\n" * 400}),
            ),
        ])

    prompt, tokens, compacted = _prepare_prompt(
        FakeTokenizer(),
        messages,
        tools=None,
        state={
            "successful_counts": {"nmap_scan": 8},
            "rejected_saves": 0,
            "outstanding_requirements": [],
        },
        context_budget=1000,
    )

    assert compacted is True
    assert tokens < 1000
    assert "stdout_summary" in prompt



def test_recon_model_sees_only_core_tool_schemas() -> None:
    names = [
        "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
        "save_deliverable", "ssh_audit", "nuclei_scan", "list_skills",
    ]
    tools = [
        {"type": "function", "function": {"name": name, "parameters": {}}}
        for name in names
    ]
    selected = _select_model_tools("recon", tools)
    assert {
        tool["function"]["name"] for tool in selected
    } == {
        "arp_scan", "nmap_discovery", "nmap_scan", "read_deliverable",
        "save_deliverable",
    }
    ready = _select_model_tools("recon", tools, {
        "recon_progress": {"ready_to_save": True},
    })
    assert [tool["function"]["name"] for tool in ready] == ["save_deliverable"]
    assert _select_model_tools("exploit", tools) == tools



def test_compaction_summarizes_large_latest_success_but_preserves_contract_error() -> None:
    scan = [{
        "role": "tool",
        "tool_call_id": "scan-1",
        "content": json.dumps({
            "stdout": ("closed port detail\n" * 500) + "22/tcp open ssh OpenSSH 9.6\n",
        }),
    }]
    compacted_scan = _compact_hf_messages(scan, aggressive=True)
    assert len(compacted_scan[0]["content"]) < 1000
    assert "22/tcp open ssh" in compacted_scan[0]["content"]

    error_content = json.dumps({
        "ok": False,
        "error_kind": "recon_contract_incomplete",
        "missing_requirements": [{
            "requirement": "phase1_context",
            "tool": "read_deliverable",
        }],
        "error": "x" * 5000,
    })
    compacted_error = _compact_hf_messages([{
        "role": "tool", "tool_call_id": "save-1", "content": error_content,
    }], aggressive=True)
    assert compacted_error[0]["content"] == error_content



def test_vuln_generation_budget_prevents_runaway_output() -> None:
    assert _generation_token_budget("vuln", 4096, 4000, 6144) == 1024
    assert _generation_token_budget("vuln", 768, 4000, 6144) == 768
    assert _generation_token_budget("vuln", 4096, 7000, 6144) == 256
    assert _generation_token_budget("secretary", 4096, 7000, 6144) == 4096
