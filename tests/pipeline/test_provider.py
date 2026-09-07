"""Provider tool loops, retry guards, and terminal calls."""
import json
from unittest.mock import MagicMock
import pytest


class TestRepeatingToolDetector:
    """Tests for the repeating tool detector in LLMProvider loops."""

    def test_openai_loop_warns_on_repeat(self):
        """Calling the same tool 3x in a row injects a warning instead of executing."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        call_count = {"n": 0}

        def dummy_tool():
            call_count["n"] += 1
            return "result"

        tool_map = {"dummy": dummy_tool}

        # Simulate 4 turns: each turn the model calls dummy() with same args
        turn = [0]
        responses = []
        for i in range(4):
            msg = MagicMock()
            msg.content = None
            msg.tool_calls = [MagicMock()]
            msg.tool_calls[0].function.name = "dummy"
            msg.tool_calls[0].function.arguments = "{}"
            msg.tool_calls[0].id = f"call_{i}"
            choice = MagicMock()
            choice.finish_reason = "tool_calls"
            choice.message = msg
            responses.append(MagicMock(choices=[choice], usage=None))

        # 5th response: no tool call, end loop
        final_msg = MagicMock()
        final_msg.content = "Done."
        final_msg.tool_calls = None
        final_choice = MagicMock()
        final_choice.finish_reason = "stop"
        final_choice.message = final_msg
        responses.append(MagicMock(choices=[final_choice], usage=None))

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = responses

        api_tools = [{"type": "function", "function": {"name": "dummy", "description": "d", "parameters": {}}}]
        tools = [{"name": "dummy", "description": "d", "input_schema": {}, "function": dummy_tool}]

        provider.chat_with_tools(
            system_prompt="sys", user_message="go", tools=tools, max_turns=10
        )

        # Warning triggers on 3rd identical call — only 2 actual executions
        assert call_count["n"] == 2

    def test_openai_loop_can_disable_generic_repeat_guard(self):
        """Recon's own contract can retain control after repeated model calls."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"
        execute = MagicMock(return_value='{"status":"ok"}')

        responses = []
        for index in range(4):
            tool_call = MagicMock()
            tool_call.function.name = "scan"
            tool_call.function.arguments = '{}'
            tool_call.id = f"call_{index}"
            message = MagicMock(content=None, tool_calls=[tool_call])
            responses.append(MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            ))
        responses.append(MagicMock(
            choices=[MagicMock(
                finish_reason="stop",
                message=MagicMock(content="Done.", tool_calls=None),
            )],
            usage=None,
        ))
        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = responses

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "scan", "description": "scan",
                "input_schema": {}, "function": execute,
            }],
            max_turns=10,
            repeat_guard=False,
        )

        assert execute.call_count == 4

    def test_unadvertised_save_deliverable_returns_structured_rejection(self):
        """A learned completion call must not become a KeyError in memo mode."""
        from src.agent.provider import LLMProvider

        result = json.loads(LLMProvider._execute_tool(
            "save_deliverable",
            {"filename": "04_exploits/result.json", "content": "{}"},
            {"mqtt_listen": MagicMock()},
        ))

        assert result["ok"] is False
        assert result["error_kind"] == "tool_not_available"
        assert result["tool"] == "save_deliverable"
        assert result["available_tools"] == ["mqtt_listen"]

    def test_openai_loop_can_terminate_legacy_unavailable_save_without_tool_event(self):
        """Local memo mode can stop old save calls without executing or streaming them."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        save_call = MagicMock()
        save_call.function.name = "save_deliverable"
        save_call.function.arguments = '{"filename":"05_intrusion.json","content":"{}"}'
        save_call.id = "call_save"
        message = MagicMock(content="Memo only.", tool_calls=[save_call])
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="tool_calls", message=message)],
            usage=None,
        )
        stream_events = []
        execute = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "try_credential", "description": "try",
                "input_schema": {}, "function": execute,
            }],
            max_turns=10,
            stream_callback=stream_events.append,
            terminate_on_unavailable_tools={"save_deliverable"},
        )

        assert result == "Memo only."
        execute.assert_not_called()
        assert provider.client.chat.completions.create.call_count == 1
        assert not [event for event in stream_events if event.get("type") == "tool_call"]
        assert stream_events[-1]["terminated_by"] == "save_deliverable"

    def test_openai_loop_terminates_after_successful_tool(self):
        """A successful terminal tool call must not trigger another model turn."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        save_call = MagicMock()
        save_call.function.name = "save_deliverable"
        save_call.function.arguments = '{"filename":"result.md","content":"done"}'
        save_call.id = "call_save"

        message = MagicMock()
        message.content = "Saving the completed deliverable."
        message.tool_calls = [save_call]
        choice = MagicMock(finish_reason="tool_calls", message=message)

        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[choice], usage=None
        )
        save = MagicMock(return_value='{"status":"saved"}')
        tools = [{
            "name": "save_deliverable",
            "description": "save",
            "input_schema": {},
            "function": save,
        }]

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=tools,
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        assert result == "Saving the completed deliverable."
        assert provider.client.chat.completions.create.call_count == 1
        save.assert_called_once_with(filename="result.md", content="done")

    def test_openai_loop_skips_calls_after_successful_terminal_tool(self):
        """Sibling calls after a successful terminal save must not execute."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def tool_call(name, arguments, call_id):
            call = MagicMock()
            call.function.name = name
            call.function.arguments = json.dumps(arguments)
            call.id = call_id
            return call

        message = MagicMock(
            content="Campaign complete.",
            tool_calls=[
                tool_call("action", {"step": "before"}, "call_before"),
                tool_call(
                    "save_deliverable",
                    {"filename": "05_intrusion.json", "content": "{}"},
                    "call_save",
                ),
                tool_call("action", {"step": "after"}, "call_after"),
            ],
        )
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="tool_calls", message=message)],
            usage=None,
        )
        action = MagicMock(return_value='{"ok":true}')
        save = MagicMock(return_value='{"status":"saved"}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "action", "description": "act", "input_schema": {}, "function": action},
                {"name": "save_deliverable", "description": "save", "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        action.assert_called_once_with(step="before")
        save.assert_called_once_with(filename="05_intrusion.json", content="{}")

    def test_openai_loop_strict_required_tool_reprompts_after_text_only_turn(self):
        """Strict required tools prevent compact agents from ending with prose only."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        text_message = MagicMock(content="Trying", tool_calls=None)
        complete_call = MagicMock()
        complete_call.function.name = "complete_intrusion_campaign"
        complete_call.function.arguments = '{}'
        complete_call.id = "call_complete"
        complete_message = MagicMock(content=None, tool_calls=[complete_call])

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(finish_reason="stop", message=text_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="tool_calls", message=complete_message)], usage=None),
        ]
        complete = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
        )

        assert result == "Trying"
        assert provider.client.chat.completions.create.call_count == 2
        first_request = provider.client.chat.completions.create.call_args_list[0].kwargs
        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        assert "tool_choice" not in first_request
        assert second_request["tool_choice"] == "required"
        complete.assert_called_once_with()

    def test_openai_loop_stops_strict_required_tool_no_tool_stall(self):
        """Strict required-tool mode must not burn the full turn budget on empty prose."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"
        empty_message = MagicMock(content=None, tool_calls=None)
        provider.client = MagicMock()
        provider.client.chat.completions.create.return_value = MagicMock(
            choices=[MagicMock(finish_reason="stop", message=empty_message)],
            usage=None,
        )
        complete = MagicMock(return_value='{"ok": true}')

        result = provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=50,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
        )

        assert result == "(required tool complete_intrusion_campaign not called after repeated reminders)"
        assert provider.client.chat.completions.create.call_count == 3
        complete.assert_not_called()

    def test_openai_loop_recovers_compact_required_tool_after_stalls(self):
        """Compact Phase 5 keeps forcing an action instead of returning after 3 stalls."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        empty_message = MagicMock(content=None, tool_calls=None)
        terminal_call = MagicMock()
        terminal_call.function.name = "complete_intrusion_campaign"
        terminal_call.function.arguments = "{}"
        terminal_call.id = "call_complete"
        terminal_message = MagicMock(content=None, tool_calls=[terminal_call])

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="stop", message=empty_message)], usage=None),
            MagicMock(choices=[MagicMock(finish_reason="tool_calls", message=terminal_message)], usage=None),
        ]
        complete = MagicMock(return_value='{"ok": true}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[{
                "name": "complete_intrusion_campaign",
                "description": "complete",
                "input_schema": {},
                "function": complete,
            }],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
            recover_required_tool_on_stall=True,
        )

        assert provider.client.chat.completions.create.call_count == 4
        complete.assert_called_once_with()
        for call in provider.client.chat.completions.create.call_args_list[1:]:
            assert call.kwargs["tool_choice"] == "required"

    def test_openai_loop_forces_recon_save_after_completion_signal(self):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = '{}'
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("read_deliverable", "call_read"),
            response("save_deliverable", "call_save"),
        ]
        read = MagicMock(return_value=json.dumps({
            "ok": False,
            "error_kind": "recon_completion_required",
        }))
        save = MagicMock(return_value='{"status":"saved"}')

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "read_deliverable", "description": "read", "input_schema": {}, "function": read},
                {"name": "save_deliverable", "description": "save", "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
            strict_required_tool=True,
            force_tool_on_stall=True,
        )

        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        assert second_request["tool_choice"] == "required"
        assert [
            tool["function"]["name"] for tool in second_request["tools"]
        ] == ["save_deliverable"]
        read.assert_called_once_with()
        save.assert_called_once_with()

    @pytest.mark.parametrize(
        ("force_ready", "expected_tools", "expected_required"),
        [
            (True, ["save_deliverable"], True),
            (False, ["nmap_scan", "read_deliverable", "save_deliverable"], False),
        ],
    )
    def test_openai_loop_scopes_recon_ready_completion_to_opt_in(
        self, force_ready, expected_tools, expected_required
    ):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = "{}"
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("nmap_scan", "call_scan"),
            response("save_deliverable", "call_save"),
        ]
        scan = MagicMock(return_value=json.dumps({
            "stdout": "baseline complete",
            "recon_progress": {"ready_to_save": True},
        }))
        save = MagicMock(return_value="{\"status\":\"saved\"}")

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "nmap_scan", "description": "scan", "input_schema": {},
                 "function": scan},
                {"name": "read_deliverable", "description": "read",
                 "input_schema": {}, "function": MagicMock()},
                {"name": "save_deliverable", "description": "save",
                 "input_schema": {}, "function": save},
            ],
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
            strict_required_tool=True,
            force_tool_on_stall=True,
            force_completion_on_recon_ready=force_ready,
        )

        second_request = provider.client.chat.completions.create.call_args_list[1].kwargs
        if expected_required:
            assert second_request["tool_choice"] == "required"
        else:
            assert "tool_choice" not in second_request
        assert [
            tool["function"]["name"] for tool in second_request["tools"]
        ] == expected_tools
        scan.assert_called_once_with()
        save.assert_called_once_with()


    def test_openai_loop_reopens_compact_intrusion_tools_after_rejected_completion(self):
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = "{}"
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            return MagicMock(
                choices=[MagicMock(finish_reason="tool_calls", message=message)],
                usage=None,
            )

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("mqtt_listen", "mqtt-1"),
            response("mqtt_listen", "mqtt-2"),
            response("mqtt_listen", "mqtt-3"),
            response("complete_intrusion_campaign", "complete-1"),
            response("try_credential", "try-1"),
            response("complete_intrusion_campaign", "complete-2"),
        ]
        mqtt = MagicMock(return_value="{\"status\":\"ok\"}")
        try_credential = MagicMock(return_value="{\"success\":false}")
        complete = MagicMock(side_effect=[
            "{\"ok\":false,\"error_kind\":\"intrusion_contract_incomplete\"}",
            "{\"ok\":true,\"status\":\"campaign_complete\"}",
        ])

        provider.chat_with_tools(
            system_prompt="sys",
            user_message="go",
            tools=[
                {"name": "mqtt_listen", "description": "mqtt", "input_schema": {},
                 "function": mqtt},
                {"name": "try_credential", "description": "try", "input_schema": {},
                 "function": try_credential},
                {"name": "complete_intrusion_campaign", "description": "complete",
                 "input_schema": {}, "function": complete},
            ],
            max_turns=10,
            required_tool="complete_intrusion_campaign",
            terminate_after_tool="complete_intrusion_campaign",
            strict_required_tool=True,
            force_tool_on_stall=True,
            reopen_intrusion_tools_on_contract_error=True,
        )

        repair_request = provider.client.chat.completions.create.call_args_list[4].kwargs
        assert repair_request["tool_choice"] == "required"
        assert [
            tool["function"]["name"] for tool in repair_request["tools"]
        ] == ["mqtt_listen", "try_credential", "complete_intrusion_campaign"]
        try_credential.assert_called_once_with()
        assert complete.call_count == 2


    def test_openai_loop_detects_interleaved_cycle_and_forces_completion(self):
        """Interleaved duplicate calls must switch the model to save-only mode."""
        from src.agent.provider import LLMProvider

        provider = LLMProvider.__new__(LLMProvider)
        provider.provider = "openrouter"
        provider.model = "test"

        def response(tool_name, arguments, call_id):
            tool_call = MagicMock()
            tool_call.function.name = tool_name
            tool_call.function.arguments = arguments
            tool_call.id = call_id
            message = MagicMock(content=None, tool_calls=[tool_call])
            choice = MagicMock(finish_reason="tool_calls", message=message)
            return MagicMock(choices=[choice], usage=None)

        provider.client = MagicMock()
        provider.client.chat.completions.create.side_effect = [
            response("scan", '{"target":"a"}', "call_a1"),
            response("scan", '{"target":"b"}', "call_b1"),
            response("scan", '{"target":"a"}', "call_a2"),
            response("scan", '{"target":"b"}', "call_b2"),
            response("scan", '{"target":"a"}', "call_a3"),
            response(
                "save_deliverable",
                '{"filename":"result.md","content":"done"}',
                "call_save",
            ),
        ]
        scan = MagicMock(return_value='{"status":"scanned"}')
        save = MagicMock(return_value='{"status":"saved"}')
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
            system_prompt="sys",
            user_message="go",
            tools=tools,
            max_turns=10,
            required_tool="save_deliverable",
            terminate_after_tool="save_deliverable",
        )

        assert scan.call_count == 4
        save.assert_called_once_with(filename="result.md", content="done")
        final_request_tools = (
            provider.client.chat.completions.create.call_args_list[-1]
            .kwargs["tools"]
        )
        assert [tool["function"]["name"] for tool in final_request_tools] == [
            "save_deliverable"
        ]
