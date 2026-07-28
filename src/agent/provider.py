"""LLM provider abstraction with tool-calling loop.

Supports Anthropic (native tool_use) and OpenRouter (OpenAI-compatible function_calling).
Tools are defined once and translated to each provider's format internally.
"""
from __future__ import annotations

import json
import logging
import os

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


def _resolve_provider_cfg(provider: str) -> dict | None:
    """Provider config (base_url, api_key_env, default_model), DB first.

    The SQLite ``providers`` table wins when present (lets you add/edit
    providers — e.g. a local OpenAI-compatible endpoint — without code
    changes); otherwise the hardcoded ``OPENAI_PROVIDERS`` dict is used. Any DB
    error is swallowed for full backward compatibility when the DB is absent.
    """
    try:
        from src.db.database import get_provider
        row = get_provider(provider)
        if row and row.get("base_url"):
            return row
    except Exception:
        pass
    return OPENAI_PROVIDERS.get(provider)


class LLMProvider:
    """Unified LLM interface with synchronous tool-calling loop."""

    def __init__(self, provider: str = "anthropic", model: str | None = None):
        self.provider = provider
        if provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic()
            self.model = model or "claude-sonnet-4-20250514"
        else:
            cfg = _resolve_provider_cfg(provider)
            if cfg is None:
                known = ", ".join(["anthropic", *OPENAI_PROVIDERS])
                raise ValueError(f"Unknown provider: {provider}. Available: {known}")
            import openai
            api_key_env = cfg.get("api_key_env") or ""
            self.client = openai.OpenAI(
                base_url=cfg["base_url"],
                api_key=os.environ.get(api_key_env) or "not-needed",
                timeout=API_TIMEOUT,
            )
            self.model = model or cfg.get("default_model") or ""


    @staticmethod
    def _tool_result_metadata(result: str) -> tuple[bool, bool]:
        """Return (failed, fallback_used) for legacy text and JSON tool results."""
        failed = result.startswith("Error")
        fallback_used = False
        try:
            payload = json.loads(result)
        except (TypeError, ValueError, json.JSONDecodeError):
            payload = None
        if isinstance(payload, dict):
            failed = failed or payload.get("ok") is False or bool(payload.get("error")) or payload.get("status") == "ERROR"
            fallback_used = bool(payload.get("fallback_used"))
        return failed, fallback_used

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
        repeat_guard: bool = True,
        terminate_on_unavailable_tools: set[str] | frozenset[str] | None = None,
    ) -> str:
        tool_map = {t["name"]: t["function"] for t in tools}
        terminal_unavailable_tools = frozenset(terminate_on_unavailable_tools or ())
        if self.provider == "anthropic":
            return self._anthropic_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool, terminate_after_tool, repeat_guard, terminal_unavailable_tools)
        else:
            return self._openai_loop(system_prompt, user_message, tools, tool_map, max_turns, cost_tracker, max_tokens, stream_callback, required_tool, terminate_after_tool, repeat_guard, terminal_unavailable_tools)

    def _anthropic_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None, repeat_guard=True, terminate_on_unavailable_tools=frozenset()):
        api_tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]} for t in tools]
        messages = [{"role": "user", "content": user_message}]
        required_tool_called = False
        reminder_sent = False
        call_counts: dict[tuple[str, str], int] = {}
        completion_only = False
        _REPEAT_THRESHOLD = 3

        terminal_api_tools = [tool for tool in api_tools if tool["name"] == required_tool]

        for turn in range(max_turns):
            log.info("Turn %d/%d (anthropic)", turn + 1, max_turns)
            if required_tool and not required_tool_called and turn >= max(1, max_turns - 2):
                completion_only = True
            active_api_tools = terminal_api_tools if completion_only and terminal_api_tools else api_tools
            request_kwargs = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": messages,
            }
            if active_api_tools:
                request_kwargs["tools"] = active_api_tools
            response = _call_with_retry(self.client.messages.create, **request_kwargs)
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
                if required_tool and not required_tool_called and (completion_only or not reminder_sent):
                    reminder = f"IMPORTANT: Call '{required_tool}' before finishing."
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({"role": "user", "content": reminder})
                    reminder_sent = True
                    continue
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return "\n".join(text_parts)

            terminal_unavailable = next(
                (
                    tc.name for tc in tool_calls
                    if tc.name in terminate_on_unavailable_tools and tc.name not in tool_map
                ),
                None,
            )
            if terminal_unavailable:
                log.info(
                    "Terminating after unavailable legacy tool call in memo mode: %s",
                    terminal_unavailable,
                )
                if stream_callback:
                    stream_callback({
                        "type": "turn_done", "turn": turn + 1, "final": True,
                        "terminated_by": terminal_unavailable,
                    })
                return "\n".join(text_parts) or f"(terminated by unavailable {terminal_unavailable})"

            if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": False})
            messages.append({"role": "assistant", "content": response.content})

            # Execute tools (parallel)
            from concurrent.futures import ThreadPoolExecutor

            completion_only_at_turn = completion_only
            repeated_tool_ids: set[str] = set()
            for tc in tool_calls:
                call_sig = (tc.name, json.dumps(tc.input, sort_keys=True))
                call_counts[call_sig] = call_counts.get(call_sig, 0) + 1
                if repeat_guard and call_counts[call_sig] >= _REPEAT_THRESHOLD:
                    repeated_tool_ids.add(tc.id)
                    if required_tool:
                        completion_only = True

            def _maybe_execute_anthropic(tc):
                if completion_only_at_turn and required_tool and tc.name != required_tool:
                    return json.dumps({"ok": False, "error": f"Tool cycle detected. No more data-gathering calls are allowed; call {required_tool} now using the results already collected.", "error_kind": "completion_required"})
                if tc.id in repeated_tool_ids:
                    return json.dumps({"ok": False, "error": f"Tool {tc.name} called {_REPEAT_THRESHOLD}x with identical arguments, including interleaved calls. Stop gathering data and call {required_tool or 'the completion tool'} now using the results already collected.", "error_kind": "repeated_call"})
                return self._execute_tool(tc.name, tc.input, tool_map)

            if stream_callback:
                for tc in tool_calls: stream_callback({"type": "tool_call", "name": tc.name, "args": tc.input})
            terminate_now = False
            with ThreadPoolExecutor(max_workers=min(len(tool_calls), 8)) as pool:
                futures = {pool.submit(_maybe_execute_anthropic, tc): tc for tc in tool_calls}
                tool_results = []
                for f, tc in futures.items():
                    res = f.result()
                    failed, fallback_used = self._tool_result_metadata(res)
                    if cost_tracker:
                        if failed:
                            cost_tracker.record_tool_error()
                        if tc.name == "save_deliverable":
                            cost_tracker.record_format_attempt(fallback_used=fallback_used)
                    # Only mark required_tool as called if it succeeded.
                    if required_tool and tc.name == required_tool and not failed:
                        required_tool_called = True
                    if terminate_after_tool and tc.name == terminate_after_tool and not failed:
                        terminate_now = True
                    if stream_callback: stream_callback({"type": "tool_result", "name": tc.name, "result": res[:2000]})
                    tool_results.append({"type": "tool_result", "tool_use_id": tc.id, "content": res})
            messages.append({"role": "user", "content": tool_results})
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return "\n".join(text_parts) if text_parts else f"(terminated by {terminate_after_tool})"
        return "(max turns reached)"

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None, repeat_guard=True, terminate_on_unavailable_tools=frozenset()):
        api_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        malformed_retries = 0
        required_tool_called = False
        reminder_sent = False
        last_nonempty_text = ""
        call_counts: dict[tuple[str, str], int] = {}
        completion_only = False
        _REPEAT_THRESHOLD = 3

        terminal_api_tools = [
            tool for tool in api_tools
            if tool["function"]["name"] == required_tool
        ]

        for turn in range(max_turns):
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            if required_tool and not required_tool_called and turn >= max(1, max_turns - 2):
                completion_only = True
            active_api_tools = terminal_api_tools if completion_only and terminal_api_tools else api_tools
            try:
                request_kwargs = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                }
                if active_api_tools:
                    request_kwargs["tools"] = active_api_tools
                    request_kwargs["parallel_tool_calls"] = False
                response = _call_with_retry(
                    self.client.chat.completions.create,
                    **request_kwargs,
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
                    if cost_tracker:
                        cost_tracker.record_tool_error()
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

            if cost_tracker and response.usage:
                cost_tracker.record_turn(input_tokens=response.usage.prompt_tokens or 0, output_tokens=response.usage.completion_tokens or 0, tool_call_count=len(message.tool_calls or []))

            if choice.finish_reason == "error":
                if malformed_retries < 2:
                    malformed_retries += 1
                    fallback = _call_with_retry(self.client.chat.completions.create, model=self.model, messages=messages, max_tokens=max_tokens)
                    if fallback.choices:
                        if cost_tracker and fallback.usage:
                            cost_tracker.record_turn(input_tokens=fallback.usage.prompt_tokens or 0, output_tokens=fallback.usage.completion_tokens or 0)
                        fb_content = fallback.choices[0].message.content or ""
                        if stream_callback: stream_callback({"type": "text_chunk", "text": fb_content, "turn": turn + 1})
                        if required_tool and not required_tool_called and not reminder_sent:
                            messages.append({"role": "assistant", "content": fb_content})
                            messages.append({"role": "user", "content": f"Call {required_tool} now with the results."})
                            reminder_sent = True
                            continue
                        return fb_content
                continue

            if message.content:
                last_nonempty_text = message.content

            if message.tool_calls and not tool_map:
                if stream_callback and message.content:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return last_nonempty_text or "(unexpected tool call without available tools)"

            if not message.tool_calls:
                if required_tool and not required_tool_called and (completion_only or not reminder_sent):
                    messages.append({"role": "assistant", "content": message.content or ""})
                    messages.append({"role": "user", "content": f"IMPORTANT: Call '{required_tool}' before finishing."})
                    reminder_sent = True
                    continue
                if message.content and stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return last_nonempty_text

            terminal_unavailable = next(
                (
                    tc.function.name for tc in message.tool_calls
                    if tc.function.name in terminate_on_unavailable_tools
                    and tc.function.name not in tool_map
                ),
                None,
            )
            if terminal_unavailable:
                log.info(
                    "Terminating after unavailable legacy tool call in memo mode: %s",
                    terminal_unavailable,
                )
                if message.content and stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                if stream_callback:
                    stream_callback({
                        "type": "turn_done", "turn": turn + 1, "final": True,
                        "terminated_by": terminal_unavailable,
                    })
                return last_nonempty_text or f"(terminated by unavailable {terminal_unavailable})"

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
                if cost_tracker:
                    for _ in malformed_ids:
                        cost_tracker.record_tool_error()
                log.warning("Tool call(s) with malformed JSON arguments detected (attempt %d/3): %s", malformed_retries, malformed_ids)
                if stream_callback:
                    stream_callback({"type": "tool_call", "name": "ERROR", "args": {"error": "invalid JSON", "tool_call_ids": malformed_ids}})
                if malformed_retries <= 3:
                    messages.append({"role": "user", "content": f"Your last tool call had invalid JSON arguments (IDs: {malformed_ids}). Please call the tool again with valid, properly escaped JSON."})
                    continue
                return last_nonempty_text or "(malformed tool call JSON — max retries)"

            messages.append(message)

            terminate_now = False
            completion_only_at_turn = completion_only
            for tc in message.tool_calls:
                try: args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except: args = {}
                if stream_callback: stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                canonical_args = json.dumps(
                    args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                call_sig = (tc.function.name, canonical_args)
                call_counts[call_sig] = call_counts.get(call_sig, 0) + 1
                if completion_only_at_turn and required_tool and tc.function.name != required_tool:
                    res = json.dumps({"ok": False, "error": f"Tool cycle detected. No more data-gathering calls are allowed; call {required_tool} now using the results already collected.", "error_kind": "completion_required"})
                elif repeat_guard and call_counts[call_sig] >= _REPEAT_THRESHOLD:
                    res = json.dumps({"ok": False, "error": f"Tool {tc.function.name} called {_REPEAT_THRESHOLD}x with identical arguments, including interleaved calls. Stop gathering data and call {required_tool or 'the completion tool'} now using the results already collected.", "error_kind": "repeated_call"})
                    log.warning("Repeating tool detected: %s — injecting warning", tc.function.name)
                    if required_tool:
                        completion_only = True
                else:
                    res = self._execute_tool(tc.function.name, args, tool_map)
                
                failed, fallback_used = self._tool_result_metadata(res)
                if cost_tracker:
                    if failed:
                        cost_tracker.record_tool_error()
                    if tc.function.name == "save_deliverable":
                        cost_tracker.record_format_attempt(fallback_used=fallback_used)

                # Only mark required_tool as called if it succeeded.
                if required_tool and tc.function.name == required_tool and not failed:
                    required_tool_called = True
                if terminate_after_tool and tc.function.name == terminate_after_tool and not failed:
                    terminate_now = True
                if stream_callback: stream_callback({"type": "tool_result", "name": tc.function.name, "result": res[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res})
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return last_nonempty_text or f"(terminated by {terminate_after_tool})"
        return "(max turns reached)"

    @staticmethod
    def _execute_tool(name: str, args: dict, tool_map: dict) -> str:
        if name not in tool_map:
            return json.dumps({
                "ok": False,
                "error_kind": "tool_not_available",
                "error": f"Tool '{name}' was not exposed for this request.",
                "tool": name,
                "available_tools": sorted(tool_map),
            }, ensure_ascii=False)
        try:
            result = tool_map[name](**args)
            return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            return f"Error executing {name}: {e}"
