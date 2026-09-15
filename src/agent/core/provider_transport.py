"""Network retries and deadlines for calls to an LLM provider.

This layer retries the same request; it never edits the conversation, executes
tools, decides phase completion, or validates evidence. Model continuations
belong to completion_policy and remain distinct from these transport retries.

The caller owns the SDK client and disables its implicit retries. Five retries
mean at most six calls, with delays of 5, 10, 20, 40 and 80 seconds. A deadline
can shorten that sequence. Diagnostic callbacks must not alter its outcome.
"""
from __future__ import annotations

import logging
import time


log = logging.getLogger(__name__)

RETRYABLE_CODES = {429, 500, 502, 503, 529}
MAX_RETRIES = 5
RETRY_BASE_DELAY = 5.0
RETRYABLE_EXC_NAMES = {
    "APIConnectionError", "ConnectError", "ConnectionError", "ReadTimeout", "Timeout",
}


def is_network_error(exc: Exception) -> bool:
    """True for connection-level errors that have no HTTP status code."""
    return type(exc).__name__ in RETRYABLE_EXC_NAMES or isinstance(
        exc, (ConnectionError, TimeoutError)
    )


def is_missing_user_query_error(exc: Exception) -> bool:
    """A rejected conversation is not a transient server failure."""
    return (
        getattr(exc, "status_code", None) in {400, 500}
        and "no user query found in messages" in str(exc).lower()
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
            code = getattr(exc, "status_code", None)
            if code is None:
                resp = getattr(exc, "response", None)
                if resp is not None:
                    code = getattr(resp, "status_code", None)
            retryable = (code in RETRYABLE_CODES) or (
                code is None and is_network_error(exc)
            )
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
