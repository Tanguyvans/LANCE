"""LLM provider abstraction with tool-calling loop.

Supports Anthropic (native tool_use) and OpenRouter (OpenAI-compatible function_calling).
Tools are defined once and translated to each provider's format internally.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from src.config import API_TIMEOUT
import time
from collections.abc import Callable

log = logging.getLogger(__name__)

# Status codes that warrant a retry (transient server-side errors)
_RETRYABLE_CODES = {429, 500, 502, 503, 529}
_MAX_RETRIES = 5
_RETRY_BASE_DELAY = 5.0  # seconds

# Exception type names that indicate a network-level connection failure (no HTTP code)
_RETRYABLE_EXC_NAMES = {"APIConnectionError", "ConnectError", "ConnectionError", "ReadTimeout", "Timeout"}


def _is_network_error(exc: Exception) -> bool:
    """True for connection-level errors that have no HTTP status code."""
    return type(exc).__name__ in _RETRYABLE_EXC_NAMES or isinstance(exc, (ConnectionError, TimeoutError))


def _call_with_retry(fn, *args, **kwargs):
    """Call fn(*args, **kwargs), retrying on transient HTTP errors (429/5xx/529) and connection errors."""
    last_exc = None
    for attempt in range(_MAX_RETRIES + 1):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            code = getattr(exc, "status_code", None)
            if code is None:
                resp = getattr(exc, "response", None)
                if resp is not None:
                    code = getattr(resp, "status_code", None)
            retryable = (code in _RETRYABLE_CODES) or (code is None and _is_network_error(exc))
            if retryable and attempt < _MAX_RETRIES:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                log.warning("API error %s (attempt %d/%d) — retrying in %.0fs: %s", code or type(exc).__name__, attempt + 1, _MAX_RETRIES, delay, exc)
                time.sleep(delay)
                last_exc = exc
                continue
            raise
    raise last_exc

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
                timeout=API_TIMEOUT,
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
        terminate_after_tool: str | None = None,
    ) -> str:
        tool_map = {t["name"]: t["function"] for t in tools}
        if self.provider == "anthropic":
            return self._anthropic_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool, terminate_after_tool)
        else:
            return self._openai_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool, terminate_after_tool)

    def _anthropic_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None):
        api_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
        messages = [{"role": "user", "content": user_message}]
        required_tool_called = False
        reminder_sent = False
        recent_calls: list[tuple[str, str]] = []
        _REPEAT_THRESHOLD = 3

        for turn in range(max_turns):
            log.info("Turn %d/%d (anthropic)", turn + 1, max_turns)
            response = _call_with_retry(
                self.client.messages.create,
                model=self.model, max_tokens=max_tokens, system=system_prompt, tools=api_tools, messages=messages
            )
            text_parts = []
            tool_calls = []
            for block in response.content:
                if block.type == "text": text_parts.append(block.text)
                elif block.type == "tool_use": tool_calls.append(block)

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

            def _maybe_execute_anthropic(tc):
                call_sig = (tc.name, json.dumps(tc.input, sort_keys=True))
                if (len(recent_calls) >= _REPEAT_THRESHOLD
                        and all(c == call_sig for c in recent_calls[-_REPEAT_THRESHOLD:])):
                    return json.dumps({"warning": f"Tool '{tc.name}' called {_REPEAT_THRESHOLD}x with identical arguments. Change approach or call save_deliverable."})
                recent_calls.append(call_sig)
                return self._execute_tool(tc.name, tc.input, tool_map)

            if stream_callback:
                for tc in tool_calls: stream_callback({"type": "tool_call", "name": tc.name, "args": tc.input})
            terminate_now = False
            with ThreadPoolExecutor(max_workers=min(len(tool_calls), 8)) as pool:
                futures = {pool.submit(_maybe_execute_anthropic, tc): tc for tc in tool_calls}
                tool_results = []
                for f, tc in futures.items():
                    res = f.result()
                    # Only mark required_tool as called if it succeeded (no error)
                    if required_tool and tc.name == required_tool and not res.startswith("Error"):
                        required_tool_called = True
                    if terminate_after_tool and tc.name == terminate_after_tool and not res.startswith("Error"):
                        terminate_now = True
                    if stream_callback: stream_callback({"type": "tool_result", "name": tc.name, "result": res[:2000]})
                    tool_results.append({"type": "tool_result", "tool_use_id": tc.id, "content": res})
            messages.append({"role": "user", "content": tool_results})
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return "\n".join(text_parts) if text_parts else f"(terminated by {terminate_after_tool})"
        return "(max turns reached)"

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None):
        api_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        malformed_retries = 0
        required_tool_called = False
        reminder_sent = False
        last_nonempty_text = ""
        recent_calls: list[tuple[str, str]] = []
        _REPEAT_THRESHOLD = 3

        for turn in range(max_turns):
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            try:
                response = _call_with_retry(
                    self.client.chat.completions.create,
                    model=self.model, messages=messages, tools=api_tools, max_tokens=max_tokens, parallel_tool_calls=False
                )
            except Exception as exc:
                # MiniMax (and some OpenAI-compatible APIs) return 400 when the conversation
                # history contains a tool_call with malformed JSON arguments.
                # Recovery: remove the offending assistant+tool messages and ask the LLM to retry.
                err_str = str(exc)
                is_bad_tool_args = (
                    "400" in err_str and (
                        "invalid function arguments" in err_str.lower()
                        or "invalid params" in err_str.lower()
                    )
                )
                if is_bad_tool_args and malformed_retries < 3:
                    malformed_retries += 1
                    log.warning("400 invalid tool arguments (attempt %d/3) — removing malformed messages: %s", malformed_retries, exc)
                    # Strip tool results and the malformed assistant message from history
                    while messages and isinstance(messages[-1], dict) and messages[-1].get("role") == "tool":
                        messages.pop()
                    if messages and not isinstance(messages[-1], dict):
                        messages.pop()  # remove the OpenAI message object (assistant with tool_calls)
                    elif messages and isinstance(messages[-1], dict) and messages[-1].get("role") == "assistant":
                        messages.pop()
                    messages.append({"role": "user", "content": "Your previous tool call had invalid JSON arguments and was rejected. Please retry the tool call with properly formatted JSON."})
                    continue
                raise
            if not response.choices: continue
            choice = response.choices[0]
            message = choice.message

            if choice.finish_reason == "error":
                if malformed_retries < 2:
                    malformed_retries += 1
                    fallback = _call_with_retry(self.client.chat.completions.create, model=self.model, messages=messages, max_tokens=max_tokens)
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

            if message.content:
                last_nonempty_text = message.content

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
                return last_nonempty_text

            if message.content and stream_callback:
                stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
            if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})

            # Preemptive validation: check all tool call arguments for valid JSON BEFORE
            # appending to history. If malformed, MiniMax returns 400 on the next request.
            malformed_ids = []
            for tc in message.tool_calls:
                if tc.function.arguments:
                    try:
                        json.loads(tc.function.arguments)
                    except (json.JSONDecodeError, ValueError):
                        malformed_ids.append(tc.id)

            if malformed_ids:
                malformed_retries += 1
                log.warning("Tool call(s) with malformed JSON arguments detected (attempt %d/3): %s", malformed_retries, malformed_ids)
                if stream_callback:
                    stream_callback({"type": "tool_call", "name": "ERROR", "args": {"error": "invalid JSON", "tool_call_ids": malformed_ids}})
                if malformed_retries <= 3:
                    messages.append({"role": "user", "content": f"Your last tool call had invalid JSON arguments (IDs: {malformed_ids}). Please call the tool again with valid, properly escaped JSON."})
                    continue
                return last_nonempty_text or "(malformed tool call JSON — max retries)"

            messages.append(message)

            terminate_now = False
            for tc in message.tool_calls:
                try: args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except: args = {}
                if stream_callback: stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                call_sig = (tc.function.name, tc.function.arguments or "")
                recent_calls.append(call_sig)
                if (len(recent_calls) >= _REPEAT_THRESHOLD
                        and len(set(recent_calls[-_REPEAT_THRESHOLD:])) == 1):
                    res = json.dumps({"warning": f"Tool '{tc.function.name}' called {_REPEAT_THRESHOLD}x with identical arguments. Change approach or call save_deliverable."})
                    log.warning("Repeating tool detected: %s — injecting warning", tc.function.name)
                else:
                    res = self._execute_tool(tc.function.name, args, tool_map)
                # Only mark required_tool as called if it succeeded (no error)
                if required_tool and tc.function.name == required_tool and not res.startswith("Error"):
                    required_tool_called = True
                if terminate_after_tool and tc.function.name == terminate_after_tool and not res.startswith("Error"):
                    terminate_now = True
                if stream_callback: stream_callback({"type": "tool_result", "name": tc.function.name, "result": res[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res})
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return last_nonempty_text or f"(terminated by {terminate_after_tool})"
        return "(max turns reached)"

    @staticmethod
    def _execute_tool(name: str, args: dict, tool_map: dict) -> str:
        try:
            result = tool_map[name](**args)
            return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return f"Error executing {name}: {e}"
