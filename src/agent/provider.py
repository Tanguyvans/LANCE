"""LLM provider abstraction with tool-calling loop.

Supports Anthropic (native tool_use) and OpenRouter (OpenAI-compatible function_calling).
Tools are defined once and translated to each provider's format internally.
"""

import json
import logging
import os

log = logging.getLogger(__name__)

# Tool definition format (internal):
# {
#     "name": str,
#     "description": str,
#     "input_schema": dict (JSON Schema),
#     "function": callable(kwargs) -> str
# }


class LLMProvider:
    """Unified LLM interface with synchronous tool-calling loop."""

    def __init__(self, provider: str = "anthropic", model: str | None = None):
        self.provider = provider
        if provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic()
            self.model = model or "claude-sonnet-4-20250514"
        elif provider == "openrouter":
            import openai
            self.client = openai.OpenAI(
                base_url="https://openrouter.ai/api/v1",
                api_key=os.environ.get("OPENROUTER_API_KEY"),
            )
            self.model = model or "anthropic/claude-sonnet-4"
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def chat_with_tools(
        self,
        system_prompt: str,
        user_message: str,
        tools: list[dict],
        max_turns: int = 30,
        cost_tracker=None,
    ) -> str:
        """Synchronous tool-calling loop. Returns the final text response."""
        tool_map = {t["name"]: t["function"] for t in tools}

        if self.provider == "anthropic":
            return self._anthropic_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker)
        else:
            return self._openrouter_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker)

    # ── Anthropic (native tool_use) ──────────────────────────────

    def _anthropic_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None):
        api_tools = [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            }
            for t in tools
        ]
        messages = [{"role": "user", "content": user_message}]

        for turn in range(max_turns):
            log.info("Turn %d/%d (anthropic)", turn + 1, max_turns)
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                tools=api_tools,
                messages=messages,
            )

            # Collect text and tool_use blocks
            text_parts = []
            tool_calls = []
            for block in response.content:
                if block.type == "text":
                    text_parts.append(block.text)
                elif block.type == "tool_use":
                    tool_calls.append(block)

            if text_parts:
                log.info("LLM: %s", text_parts[0][:200])

            # Track cost
            if cost_tracker and hasattr(response, "usage"):
                cost_tracker.record_turn(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    tool_call_count=len(tool_calls),
                )

            # If no tool calls, we're done
            if not tool_calls:
                return "\n".join(text_parts)

            # Add assistant message (with all content blocks)
            messages.append({"role": "assistant", "content": response.content})

            # Execute each tool call and collect results
            tool_results = []
            for tc in tool_calls:
                result = self._execute_tool(tc.name, tc.input, tool_map)
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": result,
                    }
                )
            messages.append({"role": "user", "content": tool_results})

        return "(max turns reached)"

    # ── OpenRouter / OpenAI-compatible ───────────────────────────

    def _openrouter_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None):
        api_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ]

        for turn in range(max_turns):
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=api_tools,
                max_tokens=4096,
            )
            choice = response.choices[0]
            message = choice.message

            # Track cost
            if cost_tracker and response.usage:
                cost_tracker.record_turn(
                    input_tokens=response.usage.prompt_tokens or 0,
                    output_tokens=response.usage.completion_tokens or 0,
                    tool_call_count=len(message.tool_calls or []),
                )

            # If no tool calls, we're done
            if not message.tool_calls:
                return message.content or ""

            if message.content:
                log.info("LLM: %s", message.content[:200])

            # Add assistant message
            messages.append(message)

            # Execute each tool call
            for tc in message.tool_calls:
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                result = self._execute_tool(tc.function.name, args, tool_map)
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    }
                )

        return "(max turns reached)"

    # ── Tool execution ───────────────────────────────────────────

    @staticmethod
    def _execute_tool(name: str, args: dict, tool_map: dict) -> str:
        log.info("Executing tool: %s(%s)", name, json.dumps(args, ensure_ascii=False)[:200])
        try:
            result = tool_map[name](**args)
            if not isinstance(result, str):
                result = json.dumps(result, ensure_ascii=False, default=str)
            log.info("Tool result: %s", result[:500])
            return result
        except Exception as e:
            error_msg = f"Error executing {name}: {e}"
            log.error(error_msg)
            return error_msg
