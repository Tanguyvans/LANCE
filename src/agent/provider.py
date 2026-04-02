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
                timeout=120.0,
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
        tool_map = {t["name"]: t["function"] for t in tools}
        if self.provider == "anthropic":
            return self._anthropic_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool)
        else:
            return self._openai_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool)

    def _anthropic_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None):
        api_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
        messages = [{"role": "user", "content": user_message}]
        required_tool_called = False
        reminder_sent = False

        for turn in range(max_turns):
            log.info("Turn %d/%d (anthropic)", turn + 1, max_turns)
            response = self.client.messages.create(
                model=self.model, max_tokens=max_tokens, system=system_prompt, tools=api_tools, messages=messages
            )
            text_parts = []
            tool_calls = []
            for block in response.content:
                if block.type == "text": text_parts.append(block.text)
                elif block.type == "tool_use": tool_calls.append(block)

            if required_tool and any(tc.name == required_tool for tc in tool_calls):
                required_tool_called = True

            if text_parts and stream_callback:
                stream_callback({"type": "text_chunk", "text": "\n".join(text_parts), "turn": turn + 1})

            if cost_tracker and hasattr(response, "usage"):
                cost_tracker.record_turn(input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens, tool_call_count=len(tool_calls))

            if not tool_calls:
                if required_tool and not required_tool_called and not reminder_sent:
                    # Only send reminder if NO tool has been called yet AND it's not the first turn
                    if turn > 0:
                        reminder = f"IMPORTANT: Call '{required_tool}' before finishing."
                        messages.append({"role": "assistant", "content": response.content})
                        messages.append({"role": "user", "content": reminder})
                        reminder_sent = True
                        continue
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return "\n".join(text_parts)

            if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})
            messages.append({"role": "assistant", "content": response.content})

            # Execute tools (parallel)
            from concurrent.futures import ThreadPoolExecutor
            if stream_callback:
                for tc in tool_calls: stream_callback({"type": "tool_call", "name": tc.name, "args": tc.input})
            with ThreadPoolExecutor(max_workers=min(len(tool_calls), 8)) as pool:
                futures = {pool.submit(self._execute_tool, tc.name, tc.input, tool_map): tc for tc in tool_calls}
                tool_results = []
                for f, tc in futures.items():
                    res = f.result()
                    if stream_callback: stream_callback({"type": "tool_result", "name": tc.name, "result": res[:2000]})
                    tool_results.append({"type": "tool_result", "tool_use_id": tc.id, "content": res})
            messages.append({"role": "user", "content": tool_results})
        return "(max turns reached)"

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None):
        api_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        malformed_retries = 0
        required_tool_called = False
        reminder_sent = False

        for turn in range(max_turns):
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            response = self.client.chat.completions.create(model=self.model, messages=messages, tools=api_tools, max_tokens=max_tokens, parallel_tool_calls=False)
            if not response.choices: continue
            choice = response.choices[0]
            message = choice.message

            if choice.finish_reason == "error":
                if malformed_retries < 2:
                    malformed_retries += 1
                    fallback = self.client.chat.completions.create(model=self.model, messages=messages, max_tokens=max_tokens)
                    if fallback.choices:
                        fb_content = fallback.choices[0].message.content or ""
                        if stream_callback: stream_callback({"type": "text_chunk", "text": fb_content, "turn": turn + 1})
                        if required_tool and not required_tool_called and not reminder_sent:
                            messages.append({"role": "assistant", "content": fb_content})
                            messages.append({"role": "user", "content": f"Call {required_tool} now with the results."})
                            reminder_sent = True
                            continue
                        return fb_content
                continue

            if cost_tracker and response.usage:
                cost_tracker.record_turn(input_tokens=response.usage.prompt_tokens or 0, output_tokens=response.usage.completion_tokens or 0, tool_call_count=len(message.tool_calls or []))

            if required_tool and message.tool_calls:
                if any(tc.function.name == required_tool for tc in message.tool_calls):
                    required_tool_called = True

            if not message.tool_calls:
                if required_tool and not required_tool_called and not reminder_sent:
                    if turn > 0:
                        messages.append({"role": "assistant", "content": message.content or ""})
                        messages.append({"role": "user", "content": f"IMPORTANT: Call '{required_tool}' before finishing."})
                        reminder_sent = True
                        continue
                if message.content and stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return message.content or ""

            if message.content and stream_callback:
                stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
            if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})
            messages.append(message)

            for tc in message.tool_calls:
                try: args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except: args = {}
                if stream_callback: stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                res = self._execute_tool(tc.function.name, args, tool_map)
                if stream_callback: stream_callback({"type": "tool_result", "name": tc.function.name, "result": res[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res})
        return "(max turns reached)"

    @staticmethod
    def _execute_tool(name: str, args: dict, tool_map: dict) -> str:
        try:
            result = tool_map[name](**args)
            return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return f"Error executing {name}: {e}"
