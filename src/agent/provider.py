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
from uuid import uuid4

from src.agent.core.completion_policy import CompletionPolicy

log = logging.getLogger(__name__)

# Status codes that warrant a retry (transient server-side errors)
_RETRYABLE_CODES = {429, 500, 502, 503, 529}
_MAX_RETRIES = 5
_RETRY_BASE_DELAY = 5.0  # seconds
_LOCAL_MOE_API_TIMEOUT = float(os.environ.get("LANCE_LOCAL_MOE_API_TIMEOUT", "90"))
_LOCAL_MOE_MAX_RETRIES = int(os.environ.get("LANCE_LOCAL_MOE_MAX_RETRIES", "2"))

# Exception type names that indicate a network-level connection failure (no HTTP code)
_RETRYABLE_EXC_NAMES = {"APIConnectionError", "ConnectError", "ConnectionError", "ReadTimeout", "Timeout"}


def _safe_provider_callback(callback: Callable[[dict], None] | None, event: dict) -> None:
    """Forward an observation without letting an event handler alter control flow."""
    if callback is None:
        return
    try:
        callback(event)
    except Exception:
        # Event delivery is observational. Do not log the exception: provider
        # messages and SDK exception text can contain credentials or payloads.
        log.warning("Provider event handler unavailable")


class _ProviderDiagnostics:
    """Per-chat invocation metadata emitter; persistence belongs to the runner."""

    def __init__(self, provider: str, model: str, callback: Callable[[dict], None] | None, tools: list[dict]):
        self.provider = provider
        self.model = model
        self.callback = callback
        self.invocation_id = uuid4().hex
        self.known_tools = {tool.get("name") for tool in tools if isinstance(tool.get("name"), str)}
        self.request_num = 0
        self.last_turn = 0
        self.terminal_emitted = False
        self.last_save_outcome: str | None = None
        self.last_sdk_exception: Exception | None = None

    def emit(self, event: str, **fields) -> None:
        payload = {
            "type": "provider_diagnostic",
            "event": event,
            "provider": self.provider,
            "model": self.model,
            "invocation_id": self.invocation_id,
            "_known_tools": sorted(self.known_tools),
        }
        payload.update(fields)
        _safe_provider_callback(self.callback, payload)

    def request(self, *, turn: int, attempt: int) -> int:
        self.request_num += 1
        self.last_turn = turn
        self.emit("request", request_num=self.request_num, attempt=attempt, turn=turn)
        return self.request_num

    def response(self, *, response_type: str, turn: int, finish_reason=None, usage_present=False, request_num=None, error_kind=None, status_code=None) -> None:
        self.emit(
            "response",
            response_type=response_type,
            finish_reason=finish_reason,
            usage_present=bool(usage_present),
            request_num=request_num,
            turn=turn,
            error_kind=error_kind,
            status_code=status_code,
        )

    def provider_error(self, exc: Exception | None = None, *, turn: int, request_num: int | None) -> None:
        """Observe SDK-boundary error metadata without retaining its message."""
        error_kind = "unknown"
        status_code = None
        if exc is not None:
            status_code = getattr(exc, "status_code", None)
            if status_code is None:
                response = getattr(exc, "response", None)
                status_code = getattr(response, "status_code", None) if response is not None else None
            try:
                status_code = int(status_code) if status_code is not None else None
            except (TypeError, ValueError, OverflowError):
                status_code = None
            lowered = str(exc).lower()
            if _is_missing_user_query_error(exc):
                error_kind = "no_user_query"
            elif "invalid function arguments" in lowered or "invalid params" in lowered:
                error_kind = "invalid_tool_arguments"
            elif status_code == 400:
                error_kind = "invalid_request"
            elif status_code in _RETRYABLE_CODES:
                error_kind = "transient"
            elif _is_network_error(exc):
                error_kind = "timeout" if isinstance(exc, TimeoutError) or type(exc).__name__ in {"ReadTimeout", "Timeout"} else "network"
        self.last_sdk_exception = exc
        self.response(
            response_type="providererror",
            turn=turn,
            usage_present=False,
            request_num=request_num,
            error_kind=error_kind,
            status_code=status_code,
        )

    def terminal(self, cause: str, *, turn: int | None = None, **fields) -> None:
        if self.terminal_emitted:
            return
        self.terminal_emitted = True
        self.emit("terminal", cause=cause, turn=turn, **fields)

    def tool(self, event: str, name: str, *, turn: int, request_num: int | None = None, **fields) -> None:
        self.emit(
            event,
            tool_name=name if name in self.known_tools else "unknown",
            request_num=request_num,
            turn=turn,
            **fields,
        )

    def save(self, accepted: bool, *, turn: int, request_num: int | None, attempt_ref=None) -> None:
        self.last_save_outcome = "accepted" if accepted else "rejected"
        self.emit(
            "save_outcome",
            accepted=bool(accepted),
            attempt_ref=attempt_ref,
            request_num=request_num,
            turn=turn,
        )

    def finalization(self, reason: str, *, turn: int, no_tool_stalls: int, finalization_requests: int, data_tool_calls: int) -> None:
        self.emit(
            "finalization_entered",
            reason=reason,
            turn=turn,
            no_tool_stalls=no_tool_stalls,
            finalization_requests=finalization_requests,
            data_tool_calls=data_tool_calls,
        )

    def continuation_requested(
        self,
        reason: str,
        *,
        response_category: str,
        count: int,
        turn: int,
    ) -> None:
        self.emit(
            "continuation_requested",
            reason=reason,
            response_category=response_category,
            count=count,
            turn=turn,
        )


def _is_network_error(exc: Exception) -> bool:
    """True for connection-level errors that have no HTTP status code."""
    return type(exc).__name__ in _RETRYABLE_EXC_NAMES or isinstance(exc, (ConnectionError, TimeoutError))


def _is_missing_user_query_error(exc: Exception) -> bool:
    """A rejected conversation is not a transient server failure."""
    return (
        getattr(exc, "status_code", None) in {400, 500}
        and "no user query found in messages" in str(exc).lower()
    )


def _deadline_remaining(deadline: float | None) -> float | None:
    """Return seconds remaining, or raise before a deadline-bounded call."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("LLM request deadline exceeded")
    return remaining


def _call_with_retry(fn, *args, max_retries=_MAX_RETRIES, deadline=None, on_attempt=None, on_error=None, **kwargs):
    """Call fn(*args, **kwargs), retrying on transient HTTP errors (429/5xx/529) and connection errors."""
    last_exc = None
    retry_limit = max(0, int(max_retries))
    for attempt in range(retry_limit + 1):
        _deadline_remaining(deadline)
        if on_attempt is not None:
            try:
                on_attempt(attempt)
            except Exception:
                log.warning("Provider request observer unavailable")
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if on_error is not None:
                try:
                    on_error(exc)
                except Exception:
                    log.warning("Provider error observer unavailable")
            if _is_missing_user_query_error(exc):
                raise
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
                log.warning("API error %s (attempt %d/%d) — retrying in %.0fs", code or type(exc).__name__, attempt + 1, retry_limit, delay)
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
        completion_metadata: dict | None = None,
    ) -> str:
        # Caller-owned metadata avoids cross-talk between parallel workers.
        if completion_metadata is not None:
            completion_metadata.clear()
        event_callback = (
            (lambda event: _safe_provider_callback(stream_callback, event))
            if stream_callback is not None
            and getattr(stream_callback, "_provider_diagnostics", False)
            else None
        )
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
        diagnostics = _ProviderDiagnostics(self.provider, self.model, event_callback, tools)
        diagnostics.emit("invocation_started")
        try:
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
                completion_metadata=completion_metadata,
                diagnostics=diagnostics,
            )
        except Exception as exc:
            # SDK-boundary failures have already been observed once by the
            # retry owner. Exceptions after that boundary (tool/callback/
            # bookkeeping) must not receive a fictitious provider response.
            if exc is diagnostics.last_sdk_exception:
                cause = "providererror"
            elif type(exc).__name__ == "BudgetExceeded":
                cause = "budget"
            elif isinstance(exc, TimeoutError):
                cause = "deadline"
            else:
                cause = "internal"
            diagnostics.terminal(
                cause,
                turn=getattr(diagnostics, "last_turn", 0) or 1,
            )
            raise

    def _openai_loop(self, system_prompt, user_message, tools, tool_map, max_turns, cost_tracker=None, max_tokens=4096, stream_callback=None, required_tool=None, terminate_after_tool=None, repeat_guard=True, terminate_on_unavailable_tools=frozenset(), strict_required_tool=False, force_tool_on_stall=False, force_completion_on_recon_ready=False, reopen_intrusion_tools_on_contract_error=False, recover_required_tool_on_stall=False, stop_event=None, max_data_tool_calls=None, force_completion_on_phase4_conclusive=False, deadline=None, finalize_required_tool_on_stall=False, completion_metadata=None, diagnostics=None):
        if not isinstance(user_message, str) or not user_message.strip():
            raise ValueError("A non-empty user message is required")
        if diagnostics is None:
            diagnostics = _ProviderDiagnostics(self.provider, self.model, stream_callback, tools)
            diagnostics.emit("invocation_started")
        api_tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["input_schema"]}} for t in tools]
        messages = [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_message}]
        malformed_retries = 0
        user_query_recovered = False
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
        request_context = {"turn": 0, "attempt": 0, "request_started": False}
        completion_policy = (
            CompletionPolicy() if finalize_required_tool_on_stall else None
        )

        terminal_api_tools = [
            tool for tool in api_tools
            if tool["function"]["name"] == required_tool
        ]

        def finalization_unsatisfied(reason: str) -> str:
            return (
                "(required tool finalization unsatisfied: "
                f"{required_tool or 'required tool'} — {reason})"
            )

        finalization_observed = False

        def enter_finalization(reason: str, current_turn: int) -> None:
            nonlocal finalization_observed
            if completion_policy is not None:
                completion_policy.enter_finalization()
            if finalization_observed:
                return
            finalization_observed = True
            diagnostics.finalization(
                reason,
                turn=current_turn,
                no_tool_stalls=no_tool_stalls,
                finalization_requests=finalization_requests,
                data_tool_calls=data_tool_calls,
            )

        def finish(value: str, cause: str, *, current_turn: int | None = None, **fields) -> str:
            diagnostics.terminal(cause, turn=current_turn, **fields)
            return value

        def handle_interruption(
            response_category: str,
            current_turn: int,
            *,
            assistant_content: str | None = None,
        ) -> bool:
            """Schedule a bounded action-capable continuation or latch closing."""
            nonlocal completion_only, finalization_only, reminder_sent
            nonlocal force_any_tool_next_turn
            if completion_policy is None:
                return False
            continued = completion_policy.request_continuation(
                budget_reserved=completion_only or finalization_only
            )
            if assistant_content is not None:
                messages.append({"role": "assistant", "content": assistant_content})
            if continued:
                diagnostics.continuation_requested(
                    response_category,
                    response_category=response_category,
                    count=completion_policy.continuation_count,
                    turn=current_turn,
                )
                messages.append({
                    "role": "user",
                    "content": (
                        "Continue with one available action tool, or call "
                        f"'{required_tool}' if you are finished."
                    ),
                })
                reminder_sent = True
                force_any_tool_next_turn = True
                return True
            completion_only = True
            finalization_only = True
            enter_finalization(response_category, current_turn)
            messages.append({
                "role": "user",
                "content": (
                    f"Call '{required_tool}' now using the results already collected. "
                    "Do not call any other tool."
                ),
            })
            reminder_sent = True
            force_any_tool_next_turn = True
            return False

        def create_completion(**kwargs):
            if cost_tracker is not None:
                cost_tracker.check_budget()
            client = self.client
            remaining = _deadline_remaining(deadline)
            with_options = getattr(client, "with_options", None)
            if callable(with_options):
                # One retry owner: SDK retries would otherwise resend a rejected
                # conversation before our compatibility guard can inspect it.
                options = {"max_retries": 0}
                if remaining is not None:
                    options["timeout"] = remaining
                client = with_options(**options)
            # This is intentionally after budget/deadline/options checks and
            # immediately before the SDK call: it counts HTTP attempts, not
            # loop turns, and cannot invent a request rejected locally.
            diagnostics.request(
                turn=request_context["turn"],
                attempt=request_context["attempt"],
            )
            request_context["request_started"] = True
            return client.chat.completions.create(**kwargs)

        def note_attempt(attempt: int) -> None:
            request_context["attempt"] = attempt
            request_context["request_started"] = False

        def observe_request_error(exc: Exception) -> None:
            if request_context["request_started"]:
                diagnostics.provider_error(
                    exc,
                    turn=request_context["turn"],
                    request_num=diagnostics.request_num or None,
                )

        for turn in range(max_turns):
            if stop_event is not None and stop_event.is_set():
                if stream_callback:
                    stream_callback({"type": "turn_done", "turn": turn, "final": True, "terminated_by": "stop"})
                return finish("(stopped by user)", "stop", current_turn=turn + 1)
            log.info("Turn %d/%d (openrouter)", turn + 1, max_turns)
            if required_tool and not required_tool_called and turn >= max(1, max_turns - 2):
                completion_only = True
                if finalize_required_tool_on_stall:
                    finalization_only = True
                    completion_policy.enter_finalization()
            if (
                finalize_required_tool_on_stall
                and required_tool
                and not required_tool_called
                and completion_only
            ):
                finalization_only = True
            if finalization_only:
                if finalization_requests >= 3:
                    return finish(
                        finalization_unsatisfied("completion request budget exhausted"),
                        "terminalretryexhausted",
                        current_turn=turn + 1,
                        last_save_outcome=diagnostics.last_save_outcome,
                    )
                finalization_requests += 1
                enter_finalization("turn_budget", turn + 1)
            active_api_tools = (
                terminal_api_tools
                if completion_only and (
                    terminal_api_tools
                    or (finalize_required_tool_on_stall and finalization_only)
                )
                else api_tools
            )
            try:
                request_context["turn"] = turn + 1
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
                    on_attempt=note_attempt,
                    on_error=observe_request_error,
                    **request_kwargs,
                )
            except Exception as exc:
                if (
                    _is_missing_user_query_error(exc)
                    and not user_query_recovered
                    and turn + 1 < max_turns
                    and isinstance(messages[-1], dict)
                    and messages[-1].get("role") == "tool"
                    and not (finalization_only and finalization_requests >= 3)
                ):
                    # Some compatible endpoints reject a tool-ended history.
                    # Preserve the original request and every tool call/result;
                    # the next ordinary turn consumes the existing request budget.
                    user_query_recovered = True
                    messages.append({
                        "role": "user",
                        "content": (
                            "Continue the original user request using the tool results "
                            "already present above. Do not repeat completed actions merely "
                            "because the previous model request was rejected. All original "
                            "constraints and evidence requirements still apply."
                        ),
                    })
                    log.warning("Provider rejected tool-ended history; trying one bounded continuation")
                    if stream_callback:
                        stream_callback({"type": "provider_recovery", "reason": "missing_user_query", "turn": turn + 1})
                    continue
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
                    log.warning("400 invalid tool arguments (attempt %d/3) — removing malformed messages", malformed_retries)
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
            diagnostics.last_turn = turn + 1
            if not response.choices:
                diagnostics.response(
                    response_type="emptychoices",
                    turn=turn + 1,
                    usage_present=bool(response.usage),
                    request_num=diagnostics.request_num,
                )
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
                    handle_interruption("emptychoices", turn + 1)
                continue
            choice = response.choices[0]
            message = choice.message
            finish_reason = getattr(choice, "finish_reason", None)
            if finish_reason == "error":
                response_type = "finish_reasonerror"
            elif finish_reason == "length":
                response_type = "length"
            elif getattr(message, "tool_calls", None):
                response_type = "tool_calls"
            elif getattr(message, "content", None):
                response_type = "textonly"
            else:
                response_type = "emptymessage"
            diagnostics.response(
                response_type=response_type,
                finish_reason=finish_reason,
                usage_present=bool(response.usage),
                request_num=diagnostics.request_num,
                turn=turn + 1,
            )
            if completion_metadata is not None:
                reason = finish_reason
                completion_metadata["finish_reason"] = reason if isinstance(reason, str) else None

            for tc in message.tool_calls or []:
                diagnostics.tool(
                    "tool_proposed", tc.function.name,
                    turn=turn + 1, request_num=diagnostics.request_num,
                )

            if cost_tracker and response.usage:
                cost_tracker.record_turn(input_tokens=response.usage.prompt_tokens or 0, output_tokens=response.usage.completion_tokens or 0, tool_call_count=len(message.tool_calls or []))

            if choice.finish_reason == "error":
                if finalize_required_tool_on_stall and required_tool and not required_tool_called:
                    handle_interruption(
                        "finish_reasonerror",
                        turn + 1,
                        assistant_content=message.content or "",
                    )
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
                        on_attempt=note_attempt,
                        on_error=observe_request_error,
                    )
                    if fallback.choices:
                        fallback_choice = fallback.choices[0]
                        diagnostics.response(
                            response_type=(
                                "finish_reasonerror" if getattr(fallback_choice, "finish_reason", None) == "error"
                                else "length" if getattr(fallback_choice, "finish_reason", None) == "length"
                                else "tool_calls" if getattr(fallback_choice.message, "tool_calls", None)
                                else "textonly" if fallback_choice.message.content else "emptymessage"
                            ),
                            finish_reason=getattr(fallback_choice, "finish_reason", None),
                            usage_present=bool(fallback.usage),
                            request_num=diagnostics.request_num,
                            turn=turn + 1,
                        )
                        if completion_metadata is not None:
                            reason = getattr(fallback_choice, "finish_reason", None)
                            completion_metadata["finish_reason"] = reason if isinstance(reason, str) else None
                        if cost_tracker and fallback.usage:
                            cost_tracker.record_turn(input_tokens=fallback.usage.prompt_tokens or 0, output_tokens=fallback.usage.completion_tokens or 0)
                        fb_content = fallback_choice.message.content or ""
                        if stream_callback: stream_callback({"type": "text_chunk", "text": fb_content, "turn": turn + 1})
                        if required_tool and not required_tool_called and (strict_required_tool or not reminder_sent):
                            messages.append({"role": "assistant", "content": fb_content})
                            messages.append({"role": "user", "content": f"Call {required_tool} now with the results."})
                            reminder_sent = True
                            continue
                        return finish(fb_content, "finish_reasonerror", current_turn=turn + 1)
                    diagnostics.response(
                        response_type="emptychoices",
                        turn=turn + 1,
                        usage_present=bool(fallback.usage),
                        request_num=diagnostics.request_num,
                    )
                continue

            if message.content:
                last_nonempty_text = message.content

            if message.tool_calls and not tool_map:
                for tc in message.tool_calls:
                    diagnostics.tool(
                        "tool_refused", tc.function.name, turn=turn + 1,
                        request_num=diagnostics.request_num, reason="unavailable",
                    )
                if stream_callback and message.content:
                    stream_callback({"type": "text_chunk", "text": message.content, "turn": turn + 1})
                    stream_callback({"type": "turn_done", "turn": turn + 1, "final": True})
                return finish(
                    last_nonempty_text or "(unexpected tool call without available tools)",
                    "unknown_tool",
                    current_turn=turn + 1,
                )

            if not message.tool_calls:
                if required_tool and not required_tool_called and (
                    finalize_required_tool_on_stall
                    or strict_required_tool
                    or completion_only
                    or not reminder_sent
                ):
                    no_tool_stalls += 1
                    if finalize_required_tool_on_stall:
                        handle_interruption(
                            response_type,
                            turn + 1,
                            assistant_content=message.content or "",
                        )
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
                        return finish(
                            last_nonempty_text or f"(required tool {required_tool} not called after repeated reminders)",
                            "textonly",
                            current_turn=turn + 1,
                        )
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
                return finish(
                    last_nonempty_text,
                    response_type,
                    current_turn=turn + 1,
                )

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
                for tc in message.tool_calls:
                    diagnostics.tool(
                        "tool_refused", tc.function.name,
                        turn=turn + 1,
                        request_num=diagnostics.request_num,
                        reason="unavailable",
                    )
                return finish(
                    last_nonempty_text or f"(terminated by unavailable {terminal_unavailable})",
                    "unknown_tool",
                    current_turn=turn + 1,
                )

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
                # The existing parser rejects the whole batch, including any
                # well-formed sibling. Do not imply that an action executed.
                for tc in message.tool_calls:
                    diagnostics.tool(
                        "tool_refused", tc.function.name, turn=turn + 1,
                        request_num=diagnostics.request_num, reason="malformed_args",
                    )
                malformed_retries += 1
                if finalize_required_tool_on_stall and any(
                    tc.function.name == required_tool for tc in message.tool_calls
                ):
                    completion_only = True
                    finalization_only = True
                    enter_finalization("malformedargs", turn + 1)
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
                    return finish(
                        finalization_unsatisfied("malformed terminal tool arguments"),
                        "malformedargs",
                        current_turn=turn + 1,
                    )
                return finish(
                    last_nonempty_text or "(malformed tool call JSON — max retries)",
                    "malformedargs",
                    current_turn=turn + 1,
                )

            messages.append(message)

            terminate_now = False
            completion_only_at_turn = completion_only
            for tc in message.tool_calls:
                if stop_event is not None and stop_event.is_set():
                    if stream_callback:
                        stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": "stop"})
                    diagnostics.tool(
                        "tool_refused", tc.function.name,
                        turn=turn + 1,
                        request_num=diagnostics.request_num,
                        reason="stop",
                    )
                    return finish("(stopped by user)", "stop", current_turn=turn + 1)
                try: args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                except: args = {}
                if stream_callback: stream_callback({"type": "tool_call", "name": tc.function.name, "args": args})
                canonical_args = json.dumps(
                    args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                )
                call_sig = (tc.function.name, canonical_args)
                call_counts[call_sig] = call_counts.get(call_sig, 0) + 1
                refusal_reason = None
                tool_was_executed = False
                if (
                    max_data_tool_calls is not None
                    and tc.function.name != terminate_after_tool
                    and data_tool_calls >= max_data_tool_calls
                ):
                    completion_only = True
                    if finalize_required_tool_on_stall and required_tool:
                        finalization_only = True
                        enter_finalization("data_tool_budget", turn + 1)
                    refusal_reason = "tool_budget"
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
                    refusal_reason = "completion_required"
                elif repeat_guard and call_counts[call_sig] >= _REPEAT_THRESHOLD:
                    res = json.dumps({"ok": False, "error": f"Tool {tc.function.name} called {_REPEAT_THRESHOLD}x with identical arguments, including interleaved calls. Stop gathering data and call {required_tool or 'the completion tool'} now using the results already collected.", "error_kind": "repeated_call"})
                    log.warning("Repeating tool detected: %s — injecting warning", tc.function.name)
                    if required_tool:
                        completion_only = True
                        if finalize_required_tool_on_stall:
                            finalization_only = True
                            enter_finalization("repeat_guard", turn + 1)
                    refusal_reason = "repeated_call"
                else:
                    if tc.function.name != terminate_after_tool:
                        data_tool_calls += 1
                        if max_data_tool_calls is not None and data_tool_calls >= max_data_tool_calls:
                            completion_only = True
                            if finalize_required_tool_on_stall and required_tool:
                                finalization_only = True
                                enter_finalization("data_tool_budget", turn + 1)
                    res = self._execute_tool(tc.function.name, args, tool_map)
                    tool_was_executed = tc.function.name in tool_map
                    if not tool_was_executed:
                        refusal_reason = "unavailable"

                if refusal_reason is not None:
                    diagnostics.tool(
                        "tool_refused", tc.function.name,
                        turn=turn + 1,
                        request_num=diagnostics.request_num,
                        reason=refusal_reason,
                    )
                elif tool_was_executed:
                    diagnostics.tool(
                        "tool_executed", tc.function.name,
                        turn=turn + 1,
                        request_num=diagnostics.request_num,
                        outcome="returned",
                    )
                
                failed, fallback_used = self._tool_result_metadata(res)
                if completion_policy is not None and tool_was_executed:
                    completion_policy.action_executed(
                        tc.function.name,
                        terminate_after_tool,
                        result=res,
                    )
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
                        enter_finalization("phase4_conclusive", turn + 1)
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
                        enter_finalization("recon_ready", turn + 1)
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
                            enter_finalization("recon_completion_required", turn + 1)
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
                        enter_finalization("rejected_save", turn + 1)
                if required_tool and tc.function.name == required_tool and terminal_success:
                    required_tool_called = True
                if tc.function.name in {"save_deliverable", required_tool}:
                    diagnostics.save(
                        terminal_success,
                        turn=turn + 1,
                        request_num=diagnostics.request_num,
                        attempt_ref=(
                            result_payload.get("attempt_ref")
                            if isinstance(result_payload, dict) else None
                        ),
                    )
                if terminate_after_tool and tc.function.name == terminate_after_tool and terminal_success:
                    terminate_now = True
                if stream_callback: stream_callback({"type": "tool_result", "name": tc.function.name, "result": res[:2000]})
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": res})
                if terminate_now:
                    break
            if terminate_now:
                if stream_callback: stream_callback({"type": "turn_done", "turn": turn + 1, "final": True, "terminated_by": terminate_after_tool})
                return finish(
                    last_nonempty_text or f"(terminated by {terminate_after_tool})",
                    "accepted_save" if required_tool == terminate_after_tool else "tool_terminated",
                    current_turn=turn + 1,
                )
        if finalize_required_tool_on_stall and required_tool and not required_tool_called:
            return finish(
                finalization_unsatisfied("max turns exhausted"),
                "max_turns_exhausted",
                current_turn=max_turns,
                last_save_outcome=diagnostics.last_save_outcome,
            )
        return finish("(max turns reached)", "max_turns_exhausted", current_turn=max_turns)

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
