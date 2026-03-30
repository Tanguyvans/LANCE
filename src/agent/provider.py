"""LLM provider abstraction with tool-calling loop.

Supports Anthropic (native tool_use) and OpenRouter (OpenAI-compatible function_calling).
Tools are defined once and translated to each provider's format internally.
"""
from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable

log = logging.getLogger(__name__)

# Tool definition format (internal):
# {
#     "name": str,
#     "description": str,
#     "input_schema": dict (JSON Schema),
#     "function": callable(kwargs) -> str
# }


OPENAI_PROVIDERS = {
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": "anthropic/claude-sonnet-4",
    },
    "minimax": {
        "base_url": "https://api.minimax.io/v1",
        "api_key_env": "MINIMAX_API_KEY",
        "default_model": "MiniMax-M2",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/paas/v4",
        "api_key_env": "GLM_API_KEY",
        "default_model": "glm-4-flash",
    },
    "qwen": {
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key_env": "DASHSCOPE_API_KEY",
        "default_model": "qwen-plus",
    },
}


class LLMProvider:
    """Unified LLM interface with synchronous tool-calling loop."""

    def __init__(self, provider: str = "anthropic", model: str | None = None):
        self.provider = provider
        if provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic()
            self.model = model or "claude-sonnet-4-20250514"
        elif provider in OPENAI_PROVIDERS:
            import openai
            cfg = OPENAI_PROVIDERS[provider]
            self.client = openai.OpenAI(
                base_url=cfg["base_url"],
                api_key=os.environ.get(cfg["api_key_env"]),
            )
            self.model = model or cfg["default_model"]
        else:
            raise ValueError(f"Unknown provider: {provider}. Available: anthropic, {', '.join(OPENAI_PROVIDERS)}")

    def chat_with_tools(
        self,
        system_prompt: str,
        user_message: str,
        tools: list[dict],
        max_turns: int = 30,
        max_tokens: int = 4096,
        cost_tracker=None,
        stream_callback: Callable[[dict], None] | None = None,
        required_tool: str | None = None,
    ) -> str:
        """Synchronous tool-calling loop. Returns the final text response.

        Args:
            stream_callback: Optional callback called with event dicts in real-time.
                Event types: text_chunk, tool_call, tool_result, turn_done.
            required_tool: If set, inject a reminder if the LLM tries to finish
                without having called this tool at least once.
        """
        tool_map = {t["name"]: t["function"] for t in tools}

        if self.provider == "anthropic":
            return self._anthropic_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool)
        else:
            return self._openai_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool)

    # ── Anthropic (native tool_use) ──────────────────────────────

    def _anthropic_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None):
        api_tools = [
            {
                "name": t["name"],
                "description": t["description"],
                "input_schema": t["input_schema"],
            }
            for t in tools
        ]
        messages = [{"role": "user", "content": user_message}]
        required_tool_called = False

        for turn in range(max_turns):
            log.info("Turn %d/%d (anthropic)", turn + 1, max_turns)
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
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
                if stream_callback:
                    stream_callback({"type": "text_chunk", "text": "\n".join(text_parts), "turn": turn + 1})

            # Track cost
            if cost_tracker and hasattr(response, "usage"):
                cost_tracker.record_turn(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                    tool_call_count=len(tool_calls),
                )

            if required_tool and any(tc.name == required_tool for tc in tool_calls):
                required_tool_called = True

            # If no tool calls — inject reminder or stop
            if not tool_calls:
                if not required_tool_called:
                    if turn == 0:
                        reminder = "Do not narrate. Call the first tool now without any preamble."
                    else:
                        reminder = f"You have not called '{required_tool}' yet. Call save_deliverable now with the complete content."
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": reminder})
                    log.warning("Injecting tool reminder (turn %d)", turn + 1)
                    continue
                if stream_callback:
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return "\n".join(text_parts)

            if stream_callback:
                stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})

            # Add assistant message (with all content blocks)
            messages.append({"role": "assistant", "content": response.content})

            # Execute tool calls in parallel when multiple are requested
            if len(tool_calls) > 1:
                from concurrent.futures import ThreadPoolExecutor
                if stream_callback:
                    for tc in tool_calls:
                        stream_callback({"type": "tool_call", "name": tc.name, "args": tc.input})
                futures = {}
                with ThreadPoolExecutor(max_workers=min(len(tool_calls), 8)) as pool:
                    for tc in tool_calls:
                        f = pool.submit(self._execute_tool, tc.name, tc.input, tool_map)
                        futures[f] = tc
                tool_results = []
                for tc in tool_calls:
                    f = next(f for f, t in futures.items() if t is tc)
                    result = f.result()
                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": tc.name, "result": result[:500]})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": result,
                    })
            else:
                tool_results = []
                for tc in tool_calls:
                    if stream_callback:
                        stream_callback({"type": "tool_call", "name": tc.name, "args": tc.input})
                    result = self._execute_tool(tc.name, tc.input, tool_map)
                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": tc.name, "result": result[:500]})
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tc.id,
                        "content": result,
                    })
            messages.append({"role": "user", "content": tool_results})

        return "(max turns reached)"

    # ── OpenRouter / OpenAI-compatible ───────────────────────────

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None):
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

        malformed_retries = 0
        required_tool_called = False
        for turn in range(max_turns):
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                tools=api_tools,
                max_tokens=max_tokens,
                parallel_tool_calls=False,
            )
            if not response.choices:
                log.warning("Empty response from API (no choices), retrying...")
                continue
            choice = response.choices[0]
            message = choice.message

            # Handle API errors (e.g. MALFORMED_FUNCTION_CALL from Gemini)
            if choice.finish_reason == "error":
                native = getattr(choice, "native_finish_reason", "") or ""
                log.warning("API error on turn %d: %s — retrying without tools", turn + 1, native)
                if malformed_retries < 2:
                    malformed_retries += 1
                    # Retry without tools to get a plain text response
                    fallback = self.client.chat.completions.create(
                        model=self.model,
                        messages=messages,
                        max_tokens=max_tokens,
                    )
                    if fallback.choices and fallback.choices[0].message.content:
                        fb_content = fallback.choices[0].message.content
                        if cost_tracker and fallback.usage:
                            cost_tracker.record_turn(
                                input_tokens=fallback.usage.prompt_tokens or 0,
                                output_tokens=fallback.usage.completion_tokens or 0,
                                tool_call_count=0,
                            )
                        if stream_callback:
                            stream_callback({"type": "text_chunk", "text": fb_content, "turn": turn + 1})
                        # Inject reminder if required tool not yet called
                        if required_tool and not required_tool_called:
                            messages.append({"role": "assistant", "content": fb_content})
                            messages.append({"role": "user", "content": f"Call save_deliverable now with the complete content."})
                            log.warning("Injecting save reminder after malformed call (turn %d)", turn + 1)
                            malformed_retries = 0
                            continue
                        if stream_callback:
                            stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                        return fb_content
                continue

            # Track cost
            if cost_tracker and response.usage:
                cost_tracker.record_turn(
                    input_tokens=response.usage.prompt_tokens or 0,
                    output_tokens=response.usage.completion_tokens or 0,
                    tool_call_count=len(message.tool_calls or []),
                )

            if required_tool and message.tool_calls:
                if any(tc.function.name == required_tool for tc in message.tool_calls):
                    required_tool_called = True

            # If no tool calls — inject reminder or stop
            if not message.tool_calls:
                if not required_tool_called:
                    if turn == 0:
                        reminder = "Do not narrate. Call the first tool now without any preamble."
                    else:
                        reminder = f"You have not called '{required_tool}' yet. Call save_deliverable now with the complete content."
                    messages.append({"role": "assistant", "content": message.content or ""})
                    messages.append({"role": "user", "content": reminder})
                    log.warning("Injecting tool reminder (turn %d)", turn + 1)
                    continue
                if message.content and stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return message.content or ""

            if message.content:
                log.info("LLM: %s", message.content[:200])
                if stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})

            if stream_callback:
                stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})

            # Add assistant message
            messages.append(message)

            # Parse tool call arguments
            parsed_calls = []
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except json.JSONDecodeError:
                    log.warning("Bad JSON from LLM for %s: %s", tc.function.name, tc.function.arguments[:200])
                    args = {}
                parsed_calls.append((tc, args))

            # Execute tool calls in parallel when multiple are requested
            if len(parsed_calls) > 1:
                from concurrent.futures import ThreadPoolExecutor
                if stream_callback:
                    for tc, args in parsed_calls:
                        stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                with ThreadPoolExecutor(max_workers=min(len(parsed_calls), 8)) as pool:
                    futures = {
                        pool.submit(self._execute_tool, tc.function.name, args, tool_map): tc
                        for tc, args in parsed_calls
                    }
                for tc, args in parsed_calls:
                    f = next(f for f, t in futures.items() if t is tc)
                    result = f.result()
                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": tc.function.name, "result": result[:500]})
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    })
            else:
                for tc, args in parsed_calls:
                    if stream_callback:
                        stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                    result = self._execute_tool(tc.function.name, args, tool_map)
                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": tc.function.name, "result": result[:500]})
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": result,
                    })

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
