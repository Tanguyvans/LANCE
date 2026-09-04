"""Tests for the local Codex subscription bridge."""
from __future__ import annotations

from collections import deque
import json

from src.agent import codex_app_server as codex


def test_catalog_uses_chatgpt_plan_without_exposing_email(monkeypatch):
    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, params, timeout=15):
            if method == "account/read":
                return {
                    "account": {
                        "type": "chatgpt",
                        "email": "secret@example.test",
                        "planType": "pro",
                    },
                    "requiresOpenaiAuth": True,
                }
            assert method == "model/list"
            return {
                "data": [{
                    "id": "gpt-current",
                    "displayName": "GPT Current",
                    "description": "Current model",
                    "hidden": False,
                    "isDefault": True,
                    "supportedReasoningEfforts": [
                        {"reasoningEffort": "medium", "description": "Balanced"}
                    ],
                    "defaultReasoningEffort": "medium",
                    "serviceTiers": [],
                    "upgrade": None,
                }],
                "nextCursor": None,
            }

    monkeypatch.setattr(codex.shutil, "which", lambda _name: "/bin/codex")
    monkeypatch.setattr(codex, "_CodexProcess", FakeSession)
    catalog = codex._read_codex_catalog()

    assert catalog["available"] is True
    assert catalog["plan_type"] == "pro"
    assert catalog["models"][0]["id"] == "gpt-current"
    assert "email" not in json.dumps(catalog).lower()


def test_dynamic_tool_call_is_executed_and_returned(monkeypatch):
    class FakeSession:
        def __init__(self):
            self.events = deque([
                {"id": 41, "result": {"turn": {"id": "turn-1"}}},
                {
                    "id": 7,
                    "method": "item/tool/call",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "callId": "call-1",
                        "tool": "save_deliverable",
                        "arguments": {"value": "ok"},
                    },
                },
                {
                    "method": "thread/tokenUsage/updated",
                    "params": {
                        "tokenUsage": {
                            "last": {"inputTokens": 12, "outputTokens": 5}
                        }
                    },
                },
                {
                    "method": "item/completed",
                    "params": {"item": {"type": "agentMessage", "text": "done"}},
                },
                {
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turn": {"id": "turn-1", "status": "completed"},
                    },
                },
            ])
            self.responses = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, params, timeout=15):
            assert method == "thread/start"
            assert params["dynamicTools"][0]["name"] == "save_deliverable"
            return {"thread": {"id": "thread-1"}}

        def send(self, method, params=None, request=True):
            assert method == "turn/start"
            return 41

        def next_event(self, _timeout):
            return self.events.popleft()

        def respond(self, request_id, result):
            self.responses.append((request_id, result))

        def interrupt(self, _thread_id, _turn_id):
            return None

    session = FakeSession()
    monkeypatch.setattr(codex, "_CodexProcess", lambda: session)
    called = []

    def execute(name, args, tool_map):
        called.append((name, args))
        return tool_map[name](**args)

    result, usage = codex.run_codex_turn(
        model="gpt-current",
        system_prompt="system",
        user_message="go",
        tools=[{
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {"type": "object", "properties": {"value": {"type": "string"}}},
            "function": lambda value: json.dumps({"ok": True, "value": value}),
        }],
        execute_tool=execute,
        max_turns=3,
        max_tokens=100,
        required_tool="save_deliverable",
        strict_required_tool=True,
    )

    assert result == "done"
    assert usage == {"input_tokens": 12, "output_tokens": 5}
    assert called == [("save_deliverable", {"value": "ok"})]
    assert session.responses[0][0] == 7
    assert session.responses[0][1]["success"] is True


def test_provider_dispatches_to_codex_bridge(monkeypatch):
    from src.agent import provider as provider_module

    monkeypatch.setattr(codex, "get_codex_catalog", lambda: {
        "available": True,
        "models": [{"id": "gpt-current", "recommended": True}],
    })
    monkeypatch.setattr(codex, "run_codex_turn", lambda **_kwargs: (
        "codex-result", {"input_tokens": 3, "output_tokens": 2}
    ))

    provider = provider_module.LLMProvider(provider="codex", model="gpt-current")
    result = provider.chat_with_tools("system", "user", [])

    assert result == "codex-result"
    assert provider.last_usage == {"input_tokens": 3, "output_tokens": 2}
