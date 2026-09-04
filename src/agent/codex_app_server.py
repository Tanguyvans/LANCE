"""Codex subscription integration through the local Codex app-server.

The app-server reuses the user's existing ``codex login`` session.  LANCE never
reads, stores, or forwards OAuth tokens itself.  It also exposes the current
Codex model catalog and can bridge LANCE's Python tools as app-server dynamic
tools for a normal pipeline phase.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable
import json
import logging
import os
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

_CATALOG_TTL_SECONDS = 5 * 60
_catalog_cache: tuple[float, dict[str, Any]] | None = None
_catalog_lock = threading.Lock()


def _resolve_codex_command() -> str | None:
    """Locate Codex for both interactive shells and restricted web services."""
    configured = os.environ.get("LANCE_CODEX_CLI_PATH")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        return None

    discovered = shutil.which("codex")
    if discovered:
        return discovered

    # GUI launchers and user services often omit ~/.local/bin from PATH even
    # though that is where the official installer and npm user installs live.
    for candidate in (
        Path.home() / ".local" / "bin" / "codex",
        Path("/opt/homebrew/bin/codex"),
        Path("/usr/local/bin/codex"),
    ):
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _codex_missing_message() -> str:
    if os.environ.get("LANCE_CODEX_CLI_PATH"):
        return (
            "LANCE_CODEX_CLI_PATH ne pointe pas vers un exécutable Codex valide. "
            "Corrigez ce chemin puis relancez le service."
        )
    return "Codex CLI n'est pas installé. Installez-le puis lancez `codex login`."


class CodexAppServerError(RuntimeError):
    """Raised when the local Codex app-server cannot satisfy a request."""


class _CodexProcess:
    """Small synchronous JSON-RPC client for ``codex app-server --stdio``."""

    def __init__(self) -> None:
        command = _resolve_codex_command()
        if command is None:
            raise CodexAppServerError(_codex_missing_message())
        try:
            self._process = subprocess.Popen(
                [command, "app-server", "--stdio"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            raise CodexAppServerError(f"Impossible de démarrer Codex : {exc}") from exc

        self._events: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._backlog: deque[dict[str, Any]] = deque()
        self._stderr: deque[str] = deque(maxlen=20)
        self._write_lock = threading.Lock()
        self._next_id = 1
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        self._initialize()

    def _read_stdout(self) -> None:
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                try:
                    self._events.put(json.loads(line))
                except json.JSONDecodeError:
                    log.debug("Ignoring invalid Codex app-server output: %r", line[:500])
        finally:
            self._events.put(None)

    def _read_stderr(self) -> None:
        assert self._process.stderr is not None
        for line in self._process.stderr:
            self._stderr.append(line.rstrip())

    def _error_context(self) -> str:
        detail = "\n".join(self._stderr).strip()
        return detail or f"processus terminé avec le code {self._process.poll()}"

    def send(self, method: str, params: dict[str, Any] | None = None, *, request: bool = True) -> int | None:
        message: dict[str, Any] = {"method": method}
        if params is not None:
            message["params"] = params
        if request:
            message["id"] = self._next_id
            self._next_id += 1
        payload = json.dumps(message, ensure_ascii=False) + "\n"
        try:
            with self._write_lock:
                if self._process.stdin is None:
                    raise BrokenPipeError
                self._process.stdin.write(payload)
                self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise CodexAppServerError(self._error_context()) from exc
        return message.get("id")

    def respond(self, request_id: int | str, result: dict[str, Any]) -> None:
        payload = json.dumps({"id": request_id, "result": result}, ensure_ascii=False) + "\n"
        try:
            with self._write_lock:
                if self._process.stdin is None:
                    raise BrokenPipeError
                self._process.stdin.write(payload)
                self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise CodexAppServerError(self._error_context()) from exc

    def next_event(self, timeout: float) -> dict[str, Any]:
        if self._backlog:
            return self._backlog.popleft()
        try:
            event = self._events.get(timeout=max(0.01, timeout))
        except queue.Empty as exc:
            raise TimeoutError("Délai d'attente du serveur Codex dépassé") from exc
        if event is None:
            raise CodexAppServerError(self._error_context())
        return event

    def request(self, method: str, params: dict[str, Any] | None = None, *, timeout: float = 15) -> dict[str, Any]:
        request_id = self.send(method, params)
        deadline = time.monotonic() + timeout
        pending: list[dict[str, Any]] = []
        try:
            while True:
                event = self.next_event(deadline - time.monotonic())
                if event.get("id") != request_id:
                    pending.append(event)
                    continue
                if "error" in event:
                    error = event["error"]
                    message = error.get("message") if isinstance(error, dict) else str(error)
                    raise CodexAppServerError(message or f"Échec de {method}")
                result = event.get("result")
                return result if isinstance(result, dict) else {}
        finally:
            self._backlog.extendleft(reversed(pending))

    def _initialize(self) -> None:
        self.request(
            "initialize",
            {
                "clientInfo": {"name": "lance", "title": "LANCE", "version": "1.0"},
                "capabilities": {"experimentalApi": True},
            },
        )
        self.send("initialized", request=False)

    def interrupt(self, thread_id: str, turn_id: str) -> None:
        try:
            self.send("turn/interrupt", {"threadId": thread_id, "turnId": turn_id})
        except CodexAppServerError:
            pass

    def close(self) -> None:
        if self._process.poll() is not None:
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)

    def __enter__(self) -> "_CodexProcess":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _unavailable_catalog(message: str) -> dict[str, Any]:
    return {
        "available": False,
        "account_type": None,
        "plan_type": None,
        "models": [],
        "error": message,
        "auth_command": "codex login",
    }


def _read_codex_catalog() -> dict[str, Any]:
    if _resolve_codex_command() is None:
        return _unavailable_catalog(_codex_missing_message())
    try:
        with _CodexProcess() as session:
            account_result = session.request(
                "account/read", {"refreshToken": False}, timeout=10
            )
            account = account_result.get("account") or {}
            account_type = account.get("type")
            plan_type = account.get("planType")
            subscription = account_type == "chatgpt"
            available = subscription

            models: list[dict[str, Any]] = []
            cursor: str | None = None
            while True:
                result = session.request(
                    "model/list",
                    {"includeHidden": False, "limit": 100, "cursor": cursor},
                    timeout=15,
                )
                for item in result.get("data", []):
                    if item.get("hidden") or not item.get("id"):
                        continue
                    models.append({
                        "id": item["id"],
                        "label": item.get("displayName") or item["id"],
                        "description": item.get("description") or "",
                        "recommended": bool(item.get("isDefault")),
                        "reasoning_efforts": [
                            effort.get("reasoningEffort")
                            for effort in item.get("supportedReasoningEfforts", [])
                            if effort.get("reasoningEffort")
                        ],
                        "default_reasoning_effort": item.get("defaultReasoningEffort"),
                        "service_tiers": item.get("serviceTiers", []),
                        "upgrade": item.get("upgrade"),
                    })
                cursor = result.get("nextCursor")
                if not cursor:
                    break

            error = None
            if not account:
                error = "Aucune session Codex. Lancez `codex login`."
            elif not subscription:
                error = (
                    "Codex est connecté avec une clé API. Reconnectez-vous avec ChatGPT "
                    "pour utiliser votre abonnement."
                )
            elif not models:
                error = "Aucun modèle Codex n'est disponible pour ce compte."
                available = False
            return {
                "available": available,
                "account_type": account_type,
                "plan_type": plan_type,
                "models": models,
                "error": error,
                "auth_command": "codex login",
            }
    except (CodexAppServerError, OSError, TimeoutError) as exc:
        return _unavailable_catalog(str(exc))


def get_codex_catalog(*, force_refresh: bool = False) -> dict[str, Any]:
    """Return the current account-safe Codex catalog (email and tokens omitted)."""
    global _catalog_cache
    now = time.monotonic()
    with _catalog_lock:
        if (
            not force_refresh
            and _catalog_cache is not None
            and now - _catalog_cache[0] < _CATALOG_TTL_SECONDS
        ):
            return _catalog_cache[1]
        catalog = _read_codex_catalog()
        _catalog_cache = (now, catalog)
        return catalog


def is_codex_model(model: str) -> bool:
    """Best-effort provider resolution for phase-specific model IDs."""
    if _catalog_cache is not None:
        if any(item.get("id") == model for item in _catalog_cache[1].get("models", [])):
            return True
    lowered = (model or "").lower()
    return lowered.startswith(("gpt-", "o3", "o4"))


def _dynamic_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "name": tool["name"],
            "description": tool.get("description") or "",
            "inputSchema": tool.get("input_schema") or {"type": "object", "properties": {}},
        }
        for tool in tools
    ]


def _usage_from_event(event: dict[str, Any]) -> tuple[int, int]:
    usage = event.get("params", {}).get("tokenUsage", {}).get("last", {})
    return int(usage.get("inputTokens") or 0), int(usage.get("outputTokens") or 0)


def run_codex_turn(
    *,
    model: str,
    system_prompt: str,
    user_message: str,
    tools: list[dict[str, Any]],
    execute_tool: Callable[[str, dict[str, Any], dict[str, Callable[..., Any]]], str],
    max_turns: int,
    max_tokens: int,
    cost_tracker: Any = None,
    stream_callback: Callable[[dict[str, Any]], None] | None = None,
    required_tool: str | None = None,
    terminate_after_tool: str | None = None,
    repeat_guard: bool = True,
    strict_required_tool: bool = False,
    stop_event: Any = None,
    max_data_tool_calls: int | None = None,
    force_completion_on_phase4_conclusive: bool = False,
    force_completion_on_recon_ready: bool = False,
    reopen_intrusion_tools_on_contract_error: bool = False,
    deadline: float | None = None,
) -> tuple[str, dict[str, int]]:
    """Run one LANCE prompt with Codex and bridge all dynamic tool calls."""
    tool_map = {tool["name"]: tool["function"] for tool in tools}
    tool_specs = _dynamic_tools(tools)
    call_counts: dict[tuple[str, str], int] = {}
    required_tool_called = False
    completion_only = False
    data_tool_calls = 0
    total_tool_calls = 0
    total_input_tokens = 0
    total_output_tokens = 0
    last_text = ""
    terminated_by: str | None = None

    guard = (
        "\n\nLANCE RUNTIME RULES:\n"
        "- Use only the dynamic tools supplied by LANCE for actions and evidence.\n"
        "- Do not use shell, file-editing, web, browser, app, MCP, skill, or sub-agent tools.\n"
        f"- Keep the final response below approximately {max_tokens} tokens.\n"
        f"- At most {max_turns} dynamic tool calls are allowed."
    )
    if required_tool:
        guard += f"\n- You MUST successfully call `{required_tool}` before finishing."
    if terminate_after_tool:
        guard += f"\n- Stop immediately after `{terminate_after_tool}` succeeds."

    with _CodexProcess() as session:
        thread_result = session.request(
            "thread/start",
            {
                "model": model,
                "cwd": str(Path.cwd().resolve()),
                "approvalPolicy": "never",
                "sandbox": "read-only",
                "ephemeral": True,
                "baseInstructions": system_prompt,
                "developerInstructions": guard,
                "dynamicTools": tool_specs,
                "config": {
                    "features": {
                        "shell_tool": False,
                        "apps": False,
                        "browser_use": False,
                        "multi_agent": False,
                    }
                },
            },
            timeout=20,
        )
        thread = thread_result.get("thread") or {}
        thread_id = thread.get("id")
        if not thread_id:
            raise CodexAppServerError("Codex n'a pas retourné d'identifiant de session")

        next_message = user_message
        # A Codex turn already contains its own model/tool loop. Extra turns are
        # used only to recover a missing required completion tool.
        for reminder_attempt in range(3):
            turn_request_id = session.send(
                "turn/start",
                {"threadId": thread_id, "input": [{"type": "text", "text": next_message}]},
            )
            turn_id: str | None = None
            turn_tool_calls = 0
            turn_input_tokens = 0
            turn_output_tokens = 0
            turn_finished = False

            while not turn_finished:
                if stop_event is not None and stop_event.is_set():
                    if turn_id:
                        session.interrupt(thread_id, turn_id)
                    terminated_by = "stop"
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    if turn_id:
                        session.interrupt(thread_id, turn_id)
                    raise TimeoutError("LLM request deadline exceeded")
                wait_for = min(0.25, max(0.01, (deadline - time.monotonic()) if deadline else 0.25))
                try:
                    event = session.next_event(wait_for)
                except TimeoutError:
                    continue

                if event.get("id") == turn_request_id:
                    if "error" in event:
                        error = event["error"]
                        message = error.get("message") if isinstance(error, dict) else str(error)
                        raise CodexAppServerError(message or "Impossible de lancer le tour Codex")
                    turn_id = (event.get("result", {}).get("turn") or {}).get("id")
                    continue

                method = event.get("method")
                params = event.get("params") or {}
                if method == "thread/tokenUsage/updated":
                    turn_input_tokens, turn_output_tokens = _usage_from_event(event)
                    continue

                if method == "item/completed":
                    item = params.get("item") or {}
                    if item.get("type") == "agentMessage" and item.get("text"):
                        last_text = item["text"]
                        if stream_callback:
                            stream_callback({
                                "type": "text_chunk",
                                "text": last_text,
                                "turn": reminder_attempt + 1,
                            })
                    continue

                if method == "item/tool/call":
                    name = params.get("tool") or ""
                    args = params.get("arguments")
                    args = args if isinstance(args, dict) else {}
                    turn_id = params.get("turnId") or turn_id
                    total_tool_calls += 1
                    turn_tool_calls += 1
                    if stream_callback:
                        stream_callback({"type": "tool_call", "name": name, "args": args})

                    canonical_args = json.dumps(
                        args, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                    )
                    signature = (name, canonical_args)
                    call_counts[signature] = call_counts.get(signature, 0) + 1
                    if total_tool_calls > max_turns:
                        completion_only = True
                        result = json.dumps({
                            "ok": False,
                            "error_kind": "tool_budget_exhausted",
                            "error": f"Tool budget exhausted. Call {required_tool or 'no more tools'} now.",
                        })
                    elif completion_only and required_tool and name != required_tool:
                        result = json.dumps({
                            "ok": False,
                            "error_kind": "completion_required",
                            "error": f"No more data calls are allowed. Call {required_tool} now.",
                        })
                    elif repeat_guard and call_counts[signature] >= 3:
                        completion_only = bool(required_tool)
                        result = json.dumps({
                            "ok": False,
                            "error_kind": "repeated_call",
                            "error": f"Repeated identical call. Call {required_tool or 'finish'} now.",
                        })
                    elif (
                        max_data_tool_calls is not None
                        and name != terminate_after_tool
                        and data_tool_calls >= max_data_tool_calls
                    ):
                        completion_only = True
                        result = json.dumps({
                            "ok": False,
                            "error_kind": "phase4_tool_budget_exhausted",
                            "error": f"Data-tool budget exhausted. Call {required_tool or 'finish'} now.",
                        })
                    else:
                        result = execute_tool(name, args, tool_map)
                        if name != terminate_after_tool:
                            data_tool_calls += 1

                    failed, fallback_used = _tool_result_metadata(result)
                    try:
                        result_payload = json.loads(result)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        result_payload = {}
                    if (
                        force_completion_on_phase4_conclusive
                        and isinstance(result_payload, dict)
                        and result_payload.get("phase4_conclusive") is True
                    ):
                        completion_only = True
                    recon_progress = (
                        result_payload.get("recon_progress", {})
                        if isinstance(result_payload, dict) else {}
                    )
                    if (
                        force_completion_on_recon_ready
                        and isinstance(recon_progress, dict)
                        and recon_progress.get("ready_to_save") is True
                    ):
                        completion_only = True
                    if (
                        reopen_intrusion_tools_on_contract_error
                        and required_tool == "complete_intrusion_campaign"
                        and name == required_tool
                        and failed
                        and isinstance(result_payload, dict)
                        and result_payload.get("error_kind") in {
                            "intrusion_contract_incomplete",
                            "intrusion_contract_error",
                        }
                    ):
                        completion_only = False

                    if cost_tracker:
                        if failed:
                            cost_tracker.record_tool_error()
                        if name == "save_deliverable":
                            cost_tracker.record_format_attempt(fallback_used=fallback_used)
                    if required_tool and name == required_tool and not failed:
                        required_tool_called = True
                    if terminate_after_tool and name == terminate_after_tool and not failed:
                        terminated_by = terminate_after_tool

                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": name, "result": result[:2000]})
                    session.respond(
                        event["id"],
                        {
                            "contentItems": [{"type": "inputText", "text": result}],
                            "success": not failed,
                        },
                    )
                    if terminated_by and turn_id:
                        session.interrupt(thread_id, turn_id)
                    continue

                if method == "turn/completed" and params.get("threadId") == thread_id:
                    turn = params.get("turn") or {}
                    turn_id = turn.get("id") or turn_id
                    status = turn.get("status")
                    if status == "failed":
                        raise CodexAppServerError(
                            str(turn.get("error") or "Le tour Codex a échoué")
                        )
                    turn_finished = True

            total_input_tokens += turn_input_tokens
            total_output_tokens += turn_output_tokens
            if cost_tracker:
                cost_tracker.record_turn(
                    input_tokens=turn_input_tokens,
                    output_tokens=turn_output_tokens,
                    tool_call_count=turn_tool_calls,
                )
            if stream_callback:
                stream_callback({
                    "type": "turn_done",
                    "turn": reminder_attempt + 1,
                    "final": bool(
                        terminated_by or not required_tool or required_tool_called
                        or reminder_attempt == 2
                    ),
                    **({"terminated_by": terminated_by} if terminated_by else {}),
                })

            if terminated_by == "stop":
                return "(stopped by user)", {
                    "input_tokens": total_input_tokens,
                    "output_tokens": total_output_tokens,
                }
            if terminated_by or not required_tool or required_tool_called:
                break
            next_message = (
                f"IMPORTANT: your previous response did not successfully call `{required_tool}`. "
                f"Call `{required_tool}` now using the evidence already collected."
            )

    if required_tool and strict_required_tool and not required_tool_called:
        last_text = last_text or f"(required tool {required_tool} was not called)"
    return last_text, {
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
    }


def _tool_result_metadata(result: str) -> tuple[bool, bool]:
    failed = result.startswith("Error")
    fallback_used = False
    try:
        payload = json.loads(result)
    except (TypeError, ValueError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, dict):
        failed = (
            failed
            or payload.get("ok") is False
            or bool(payload.get("error"))
            or payload.get("status") == "ERROR"
        )
        fallback_used = bool(payload.get("fallback_used"))
    return failed, fallback_used
