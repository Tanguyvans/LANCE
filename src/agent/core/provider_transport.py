"""Network retries and deadlines for calls to an LLM provider.

This layer retries the same request; it never edits the conversation, executes
tools, decides phase completion, or validates evidence. Model continuations
belong to completion_policy and remain distinct from these transport retries.

The caller owns the SDK client and disables its implicit retries. Timeouts allow
at most one retry. Other transient errors allow at most six calls, with delays
of 5, 10, 20, 40 and 80 seconds. A deadline
can shorten that sequence. Diagnostic callbacks must not alter its outcome.
"""
from __future__ import annotations

import json
import logging
import time


log = logging.getLogger(__name__)

RETRYABLE_CODES = {429, 500, 502, 503, 529}
MAX_RETRIES = 5
RETRY_BASE_DELAY = 5.0
RETRYABLE_EXC_NAMES = {
    "APIConnectionError", "APITimeoutError", "ConnectError", "ConnectionError", "ReadTimeout", "Timeout",
}
_MISSING_USER_QUERY_TEXT = "no user query found in messages"


def is_network_error(exc: Exception) -> bool:
    """True for connection-level errors that have no HTTP status code."""
    return type(exc).__name__ in RETRYABLE_EXC_NAMES or isinstance(
        exc, (ConnectionError, TimeoutError)
    )


def _status_code_for_exception(exc: Exception) -> int | None:
    """Read a status code from SDK and response-only HTTP error shapes."""
    try:
        status_code = getattr(exc, "status_code", None)
    except Exception:
        status_code = None
    if status_code is None:
        try:
            response = getattr(exc, "response", None)
            status_code = getattr(response, "status_code", None) if response is not None else None
        except Exception:
            status_code = None
    try:
        status_code = int(status_code) if status_code is not None else None
    except (TypeError, ValueError, OverflowError):
        return None
    return status_code


def _exception_text_fragments(exc: Exception):
    """Yield error text without logging or persisting provider payloads."""
    yield str(exc)

    try:
        body = getattr(exc, "body", None)
    except Exception:
        body = None
    if body is not None:
        try:
            yield json.dumps(body, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            try:
                yield str(body)
            except Exception:
                pass

    try:
        response = getattr(exc, "response", None)
    except Exception:
        response = None
    if response is None:
        return
    try:
        response_json = response.json()
    except Exception:
        response_json = None
    if response_json is not None:
        try:
            yield json.dumps(response_json, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            try:
                yield str(response_json)
            except Exception:
                pass
    try:
        response_text = response.text
    except Exception:
        response_text = None
    if response_text:
        yield response_text


def _exception_has_text(exc: Exception, text: str) -> bool:
    """Match a known provider diagnostic across SDK/body representations."""
    needle = " ".join(str(text).lower().split())
    return any(
        needle in " ".join(fragment.lower().split())
        for fragment in _exception_text_fragments(exc)
        if isinstance(fragment, str)
    )


def is_missing_user_query_error(exc: Exception) -> bool:
    """A rejected conversation is not a transient server failure."""
    return (
        _status_code_for_exception(exc) in {400, 500}
        and _exception_has_text(exc, _MISSING_USER_QUERY_TEXT)
    )


def deadline_remaining(deadline: float | None) -> float | None:
    """Return seconds remaining, or raise before a deadline-bounded call."""
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("LLM request deadline exceeded")
    return remaining


def call_with_retry(
    fn, *args, max_retries=MAX_RETRIES, deadline=None,
    on_attempt=None, on_error=None, **kwargs,
):
    """Retry transient HTTP/connection errors without changing request arguments."""
    last_exc = None
    timeout_retries = 0
    retry_limit = max(0, int(max_retries))
    for attempt in range(retry_limit + 1):
        deadline_remaining(deadline)
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
            if is_missing_user_query_error(exc):
                raise
            code = _status_code_for_exception(exc)
            retryable = (code in RETRYABLE_CODES) or (
                code is None and is_network_error(exc)
            )
            is_timeout = isinstance(exc, TimeoutError) or type(exc).__name__ in {
                "APITimeoutError", "ReadTimeout", "Timeout",
            }
            if is_timeout:
                if timeout_retries >= 1:
                    raise
                timeout_retries += 1
            if retryable and attempt < retry_limit:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                if deadline is not None:
                    remaining = deadline_remaining(deadline)
                    if delay >= remaining:
                        raise TimeoutError("LLM request deadline exceeded") from exc
                log.warning(
                    "API error %s (attempt %d/%d) — retrying in %.0fs",
                    code or type(exc).__name__, attempt + 1, retry_limit, delay,
                )
                time.sleep(delay)
                last_exc = exc
                continue
            raise
    raise last_exc
