"""LLM provider abstraction with tool-calling loops.

Supports OpenAI-compatible APIs and the user's local Codex
subscription session. Tools are defined once and translated internally.
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
_LOCAL_MOE_API_TIMEOUT = float(os.environ.get("LANCE_LOCAL_MOE_API_TIMEOUT", "90"))
_LOCAL_MOE_MAX_RETRIES = int(os.environ.get("LANCE_LOCAL_MOE_MAX_RETRIES", "2"))

# Exception type names that indicate a network-level connection failure (no HTTP code)
_RETRYABLE_EXC_NAMES = {"APIConnectionError", "ConnectError", "ConnectionError", "ReadTimeout", "Timeout"}


def _is_network_error(exc: Exception) -> bool:
    """True for connection-level errors that have no HTTP status code."""
    return type(exc).__name__ in _RETRYABLE_EXC_NAMES or isinstance(exc, (ConnectionError, TimeoutError))


def _deadline_remaining(deadline: float | None) -> float | None:
    """Return seconds remaining, or raise before a deadline-bounded call."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("LLM request deadline exceeded")
    return remaining


def _call_with_retry(fn, *args, max_retries=_MAX_RETRIES, deadline=None, **kwargs):
    """Call fn(*args, **kwargs), retrying on transient HTTP errors (429/5xx/529) and connection errors."""
    last_exc = None
    retry_limit = max(0, int(max_retries))
    for attempt in range(retry_limit + 1):
        _deadline_remaining(deadline)
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            code = getattr(exc, "status_code", None)
            if code is None:
                resp = getattr(exc, "response", None)
                if resp is not None:
                    code = getattr(resp, "status_code", None)
            retryable = (code in _RETRYABLE_CODES) or (code is None and _is_network_error(exc))
            if retryable and attempt < retry_limit:
                delay = _RETRY_BASE_DELAY * (2 ** attempt)
                if deadline is not None:
                    remaining = _deadline_remaining(deadline)
                    if delay >= remaining:
                        raise TimeoutError("LLM request deadline exceeded") from exc
                log.warning("API error %s (attempt %d/%d) — retrying in %.0fs: %s", code or type(exc).__name__, attempt + 1, retry_limit, delay, exc)
                time.sleep(delay)
                last_exc = exc
                continue
            raise
    raise last_exc

OPENAI_PROVIDERS = {
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": "OPENROUTER_API_KEY",
        "default_model": None,  # Legacy CLI provider: an explicit model is required.
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

    def __init__(self, provider: str, model: str | None = None):
        self.provider = provider
        self.last_usage = {"input_tokens": 0, "output_tokens": 0}
        if provider == "anthropic":
            raise ValueError("Anthropic is no longer supported; select another provider explicitly")
        if provider == "openrouter" and not model:
            raise ValueError("OpenRouter requires an explicit model")
        if provider == "codex":
            from src.agent.codex_app_server import get_codex_catalog

            catalog = get_codex_catalog()
            if not catalog.get("available"):
                raise ValueError(catalog.get("error") or "Aucun abonnement Codex disponible")
            available_models = [item["id"] for item in catalog.get("models", [])]
            if model and model not in available_models:
                raise ValueError(f"Modèle Codex indisponible pour ce compte : {model}")
            default = next(
                (item["id"] for item in catalog.get("models", []) if item.get("recommended")),
                available_models[0] if available_models else None,
            )
            if not default:
                raise ValueError("Aucun modèle Codex disponible pour ce compte")
            self.client = None
            self.model = model or default
        else:
            cfg = _resolve_provider_cfg(provider)
            if cfg is None:
                known = ", ".join(["codex", *OPENAI_PROVIDERS])
                raise ValueError(f"Unknown provider: {provider}. Available: {known}")
            import openai
            api_key_env = cfg.get("api_key_env") or ""
            request_timeout = (
                _LOCAL_MOE_API_TIMEOUT
                if provider == "local-moe"
                else API_TIMEOUT
            )
            self.client = openai.OpenAI(
                base_url=cfg["base_url"],
                api_key=os.environ.get(api_key_env) or "not-needed",
                timeout=request_timeout,
            )
            self._retry_limit = (
                _LOCAL_MOE_MAX_RETRIES
                if provider == "local-moe"
                else _MAX_RETRIES
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

    @staticmethod
    def _terminal_tool_succeeded(result: str) -> bool:
        """Require a non-empty, well-formed wrapper result for opt-in finalization."""
        if not isinstance(result, str) or not result.strip():
            return False
        try:
            payload = json.loads(result)
        except (TypeError, ValueError, json.JSONDecodeError):
            return False
        if not isinstance(payload, dict):
            return False
        failed, _ = LLMProvider._tool_result_metadata(result)
        status = payload.get("status")
        explicit_success = (
            payload.get("ok") is True
            or payload.get("success") is True
            or (isinstance(status, str) and status.lower() in {
                "saved",
                "success",
                "ok",
                "complete",
                "completed",
                "campaign_complete",
            })
        )
        return explicit_success and not failed

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
        strict_required_tool: bool = False,
        force_tool_on_stall: bool = False,
        reopen_intrusion_tools_on_contract_error: bool = False,
        force_completion_on_recon_ready: bool = False,
        recover_required_tool_on_stall: bool = False,
        stop_event=None,
        force_completion_on_phase4_conclusive: bool = False,
        max_data_tool_calls: int | None = None,
        deadline: float | None = None,
        finalize_required_tool_on_stall: bool = False,
    ) -> str:
        tool_map = {t["name"]: t["function"] for t in tools}
        terminal_unavailable_tools = frozenset(terminate_on_unavailable_tools or ())
        if self.provider == "codex":
            from src.agent.codex_app_server import run_codex_turn

            result, usage = run_codex_turn(
                model=self.model,
                system_prompt=system_prompt,
                user_message=user_message,
                tools=tools,
                execute_tool=self._execute_tool,
                max_turns=max_turns,
                max_tokens=max_tokens,
                cost_tracker=cost_tracker,
                stream_callback=stream_callback,
                required_tool=required_tool,
                terminate_after_tool=terminate_after_tool,
                repeat_guard=repeat_guard,
                strict_required_tool=strict_required_tool,
                stop_event=stop_event,
                max_data_tool_calls=max_data_tool_calls,
                force_completion_on_phase4_conclusive=force_completion_on_phase4_conclusive,
                force_completion_on_recon_ready=force_completion_on_recon_ready,
                reopen_intrusion_tools_on_contract_error=reopen_intrusion_tools_on_contract_error,
                deadline=deadline,
            )
            self.last_usage = usage
            return result
        return self._openai_loop(
            system_prompt, user_message, tools, tool_map, max_turns, cost_tracker,
            max_tokens, stream_callback, required_tool, terminate_after_tool,
            repeat_guard, terminal_unavailable_tools, strict_required_tool,
            force_tool_on_stall, force_completion_on_recon_ready,
            reopen_intrusion_tools_on_contract_error,
            recover_required_tool_on_stall,
            stop_event,
            max_data_tool_calls,
            force_completion_on_phase4_conclusive,
            deadline=deadline,
            finalize_required_tool_on_stall=finalize_required_tool_on_stall,
        )

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None, repeat_guard=True, terminate_on_unavailable_tools=frozenset(), strict_required_tool=False, force_tool_on_stall=False, force_completion_on_recon_ready=False, reopen_intrusion_tools_on_contract_error=False, recover_required_tool_on_stall=False, stop_event=None, max_data_tool_calls=None, force_completion_on_phase4_conclusive=False, deadline=None, finalize_required_tool_on_stall=False):
        api_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        malformed_retries = 0
        required_tool_called = False
        reminder_sent = False
        last_nonempty_text = ""
        call_counts: dict[tuple[str, str], int] = {}
        completion_only = False
        finalization_only = False
        finalization_requests = 0
        no_tool_stalls = 0
        data_tool_calls = 0
        force_any_tool_next_turn = False
        _REPEAT_THRESHOLD = 3
        _NO_TOOL_STALL_THRESHOLD = 3

        terminal_api_tools = [
            tool for tool in api_tools
            if tool["function"]["name"] == required_tool
        ]

        def finalization_unsatisfied(reason: str) -> str:
            return (
                "(required tool finalization unsatisfied: "
                f"{required_tool or 'required tool'} — {reason})"
            )

        def create_completion(**kwargs):
            if cost_tracker is not None:
                cost_tracker.check_budget()
            client = self.client
            remaining = _deadline_remaining(deadline)
            with_options = getattr(client, "with_options", None)
            if finalize_required_tool_on_stall and finalization_only and callable(with_options):
                options = {"max_retries": 0}
                if remaining is not None:
                    options["timeout"] = remaining
                client = with_options(**options)
            elif remaining is not None and callable(with_options):
                # Retry here, with a recomputed remaining deadline, rather
                # than letting SDK retries reuse the full request timeout.
                client = client.with_options(timeout=remaining, max_retries=0)
            return client.chat.completions.create(**kwargs)

        for turn in range(max_turns):
            if stop_event is not None and stop_event.is_set():
                if stream_callback:
                    stream_callback({"type": "turn_done", "turn": turn, "final": True, "terminated_by": "stop"})
                return "(stopped by user)"
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            if required_tool and not required_tool_called and turn >= max(1, max_turns - 2):
                completion_only = True
                if finalize_required_tool_on_stall:
                    finalization_only = True
            if (
                finalize_required_tool_on_stall
                and required_tool
                and not required_tool_called
                and completion_only
            ):
                finalization_only = True
            if finalization_only:
                if finalization_requests >= 3:
                    return finalization_unsatisfied("completion request budget exhausted")
                finalization_requests += 1
            active_api_tools = (
                terminal_api_tools
                if completion_only and (
                    terminal_api_tools
                    or (finalize_required_tool_on_stall and finalization_only)
                )
                else api_tools
            )
            try:
                request_kwargs = {
                    "model": self.model,
                    "messages": messages,
                    "max_tokens": max_tokens,
                }
                if active_api_tools:
                    request_kwargs["tools"] = active_api_tools
                    request_kwargs["parallel_tool_calls"] = False
                    if finalize_required_tool_on_stall and finalization_only:
                        request_kwargs["tool_choice"] = "required"
                    elif force_any_tool_next_turn:
                        request_kwargs["tool_choice"] = "required"
                        force_any_tool_next_turn = False
                response = _call_with_retry(
                    create_completion,
                    max_retries=(
                        0
                        if finalize_required_tool_on_stall and finalization_only
                        else getattr(self, "_retry_limit", _MAX_RETRIES)
                    ),
                    deadline=deadline,
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
            if not response.choices:
                if (
                    finalize_required_tool_on_stall
                    and cost_tracker is not None
                    and response.usage
                ):
                    cost_tracker.record_turn(
                        input_tokens=response.usage.prompt_tokens or 0,
                        output_tokens=response.usage.completion_tokens or 0,
                        tool_call_count=0,
                    )
                if finalize_required_tool_on_stall and required_tool and not required_tool_called:
                    completion_only = True
                    finalization_only = True
                    messages.append({
                        "role": "user",
                        "content": f"Call '{required_tool}' now using the results already collected.",
                    })
                continue
            choice = response.choices[0]
            message = choice.message

            if cost_tracker and response.usage:
                cost_tracker.record_turn(input_tokens=response.usage.prompt_tokens or 0, output_tokens=response.usage.completion_tokens or 0, tool_call_count=len(message.tool_calls or []))

            if choice.finish_reason == "error":
                if finalize_required_tool_on_stall and required_tool and not required_tool_called:
                    # Do not issue an unbounded/nested fallback request for
                    # opt-in finalization. Latch terminal mode immediately;
                    # the next ordinary iteration consumes the bounded budget.
                    completion_only = True
                    finalization_only = True
                    messages.append({
                        "role": "user",
                        "content": (
                            f"The previous completion attempt failed. Call '{required_tool}' now "
                            "using the results already collected."
                        ),
                    })
                    reminder_sent = True
                    continue
                if malformed_retries < 2:
                    malformed_retries += 1
                    fallback = _call_with_retry(
                        create_completion,
                        max_retries=getattr(self, "_retry_limit", _MAX_RETRIES),
                        deadline=deadline,
                        model=self.model,
                        messages=messages,
                        max_tokens=max_tokens,
                    )
                    if fallback.choices:
                        if cost_tracker and fallback.usage:
                            cost_tracker.record_turn(input_tokens=fallback.usage.prompt_tokens or 0, output_tokens=fallback.usage.completion_tokens or 0)
                        fb_content = fallback.choices[0].message.content or ""
                        if stream_callback: stream_callback({"type": "text_chunk", "text": fb_content, "turn": turn + 1})
                        if required_tool and not required_tool_called and (strict_required_tool or not reminder_sent):
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
                if required_tool and not required_tool_called and (
                    finalize_required_tool_on_stall
                    or strict_required_tool
                    or completion_only
                    or not reminder_sent
                ):
                    no_tool_stalls += 1
                    if finalize_required_tool_on_stall:
                        # A text-only response is the stall signal for the
                        # opt-in path. From the next request onward, only the
                        # required terminal tool remains exposed.
                        completion_only = True
                        finalization_only = True
                        if finalization_requests >= 3:
                            return finalization_unsatisfied("completion request budget exhausted")
                        messages.append({"role": "assistant", "content": message.content or ""})
                        messages.append({
                            "role": "user",
                            "content": (
                                f"You must call '{required_tool}' now using the results already collected. "
                                "Do not describe completion or call any other tool."
                            ),
                        })
                        reminder_sent = True
                        force_any_tool_next_turn = True
                        continue
                    if (
                        no_tool_stalls >= _NO_TOOL_STALL_THRESHOLD
                        and not recover_required_tool_on_stall
                    ):
                        log.warning(
                            "Required tool %s was not called after %d no-tool turns",
                            required_tool, no_tool_stalls,
                        )
                        if message.content and stream_callback:
                            stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                        if stream_callback:
                            stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                        return last_nonempty_text or f"(required tool {required_tool} not called after repeated reminders)"
                    messages.append({"role": "assistant", "content": message.content or ""})
                    if force_tool_on_stall and not completion_only:
                        messages.append({
                            "role": "user",
                            "content": (
                                "Do not wait or describe future work. Call one available action tool now. "
                                f"Call '{required_tool}' only when its progress contract is complete."
                            ),
                        })
                        force_any_tool_next_turn = True
                    else:
                        messages.append({"role": "user", "content": f"IMPORTANT: Call '{required_tool}' before finishing."})
                    reminder_sent = True
                    continue
                if message.content and stream_callback:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return last_nonempty_text

            no_tool_stalls = 0
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
                if finalize_required_tool_on_stall and any(
                    tc.function.name == required_tool for tc in message.tool_calls
                ):
                    completion_only = True
                    finalization_only = True
                if cost_tracker:
                    for _ in malformed_ids:
                        cost_tracker.record_tool_error()
                log.warning("Tool call(s) with malformed JSON arguments detected (attempt %d/3): %s", malformed_retries, malformed_ids)
                if stream_callback:
                    stream_callback({"type": "tool_call", "name": "ERROR", "args": {"error": "invalid JSON", "tool_call_ids": malformed_ids}})
                if malformed_retries <= 3:
                    messages.append({"role": "user", "content": f"Your last tool call had invalid JSON arguments (IDs: {malformed_ids}). Please call the tool again with valid, properly escaped JSON."})
                    continue
                if finalize_required_tool_on_stall and finalization_only:
                    return finalization_unsatisfied("malformed terminal tool arguments")
                return last_nonempty_text or "(malformed tool call JSON — max retries)"

            messages.append(message)

            terminate_now = False
            completion_only_at_turn = completion_only
            for tc in message.tool_calls:
                if stop_event is not None and stop_event.is_set():
                    if stream_callback:
                        stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": "stop"})
                    return "(stopped by user)"
                try: args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except: args = {}
                if stream_callback: stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                canonical_args = json.dumps(
                    args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                call_sig = (tc.function.name, canonical_args)
                call_counts[call_sig] = call_counts.get(call_sig, 0) + 1
                if (
                    max_data_tool_calls is not None
                    and tc.function.name != terminate_after_tool
                    and data_tool_calls >= max_data_tool_calls
                ):
                    completion_only = True
                    if finalize_required_tool_on_stall and required_tool:
                        finalization_only = True
                    res = json.dumps({
                        "ok": False,
                        "error_kind": "phase4_tool_budget_exhausted",
                        "error": (
                            f"Phase 4 data-tool budget exhausted after "
                            f"{max_data_tool_calls} calls. Save the deliverable now."
                        ),
                    })
                elif (
                    required_tool
                    and tc.function.name != required_tool
                    and (
                        completion_only_at_turn
                        or (finalize_required_tool_on_stall and finalization_only)
                    )
                ):
                    res = json.dumps({"ok": False, "error": f"Tool cycle detected. No more data-gathering calls are allowed; call {required_tool} now using the results already collected.", "error_kind": "completion_required"})
                elif repeat_guard and call_counts[call_sig] >= _REPEAT_THRESHOLD:
                    res = json.dumps({"ok": False, "error": f"Tool {tc.function.name} called {_REPEAT_THRESHOLD}x with identical arguments, including interleaved calls. Stop gathering data and call {required_tool or 'the completion tool'} now using the results already collected.", "error_kind": "repeated_call"})
                    log.warning("Repeating tool detected: %s — injecting warning", tc.function.name)
                    if required_tool:
                        completion_only = True
                        if finalize_required_tool_on_stall:
                            finalization_only = True
                else:
                    if tc.function.name != terminate_after_tool:
                        data_tool_calls += 1
                        if max_data_tool_calls is not None and data_tool_calls >= max_data_tool_calls:
                            completion_only = True
                            if finalize_required_tool_on_stall and required_tool:
                                finalization_only = True
                    res = self._execute_tool(tc.function.name, args, tool_map)
                
                failed, fallback_used = self._tool_result_metadata(res)
                try:
                    result_payload = json.loads(res)
                except (TypeError, ValueError, json.JSONDecodeError):
                    result_payload = {}
                recon_progress = (
                    result_payload.get("recon_progress", {})
                    if isinstance(result_payload, dict) else {}
                )
                if (
                    force_completion_on_phase4_conclusive
                    and required_tool == "save_deliverable"
                    and tc.function.name != required_tool
                    and isinstance(result_payload, dict)
                    and result_payload.get("phase4_conclusive") is True
                ):
                    completion_only = True
                    if finalize_required_tool_on_stall and required_tool:
                        finalization_only = True
                    force_any_tool_next_turn = True
                if (
                    force_completion_on_recon_ready
                    and required_tool == "save_deliverable"
                    and tc.function.name != required_tool
                    and isinstance(recon_progress, dict)
                    and recon_progress.get("ready_to_save") is True
                ):
                    # The Recon tool contract is authoritative. As soon as the
                    # final evidence call completes the baseline, expose and
                    # require only the terminal save tool on the next turn.
                    completion_only = True
                    if finalize_required_tool_on_stall and required_tool:
                        finalization_only = True
                    force_any_tool_next_turn = True
                if force_tool_on_stall and failed:
                    error_kind = (
                        result_payload.get("error_kind")
                        if isinstance(result_payload, dict) else None
                    )
                    if error_kind == "recon_completion_required":
                        completion_only = True
                        if finalize_required_tool_on_stall and required_tool:
                            finalization_only = True
                        force_any_tool_next_turn = True
                if (
                    reopen_intrusion_tools_on_contract_error
                    and required_tool == "complete_intrusion_campaign"
                    and tc.function.name == required_tool
                    and failed
                    and not (finalize_required_tool_on_stall and finalization_only)
                    and isinstance(result_payload, dict)
                    and result_payload.get("error_kind") in {
                        "intrusion_contract_incomplete",
                        "intrusion_contract_error",
                    }
                ):
                    # Compact Phase 5 may hit the generic repeat guard before
                    # discovering every target. Re-open action tools after a
                    # rejected completion so the contract can be repaired.
                    completion_only = False
                    force_any_tool_next_turn = True
                if cost_tracker:
                    if failed:
                        cost_tracker.record_tool_error()
                    if tc.function.name == "save_deliverable":
                        cost_tracker.record_format_attempt(fallback_used=fallback_used)

                # Only mark required_tool as called if it succeeded. Opt-in
                # finalization additionally requires an explicit success in
                # the wrapper result, so empty/malformed/rejected saves cannot
                # terminate and immediately latch save-only mode.
                terminal_success = not failed
                if (
                    finalize_required_tool_on_stall
                    and required_tool
                    and tc.function.name == required_tool
                ):
                    terminal_success = self._terminal_tool_succeeded(res)
                    if not terminal_success:
                        completion_only = True
                        finalization_only = True
                if required_tool and tc.function.name == required_tool and terminal_success:
                    required_tool_called = True
                if terminate_after_tool and tc.function.name == terminate_after_tool and terminal_success:
                    terminate_now = True
                if stream_callback: stream_callback({"type": "tool_result", "name": tc.function.name, "result": res[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res})
                if terminate_now:
                    break
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return last_nonempty_text or f"(terminated by {terminate_after_tool})"
        if finalize_required_tool_on_stall and required_tool and not required_tool_called:
            return finalization_unsatisfied("max turns exhausted")
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
