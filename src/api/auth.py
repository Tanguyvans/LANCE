"""Small, reusable authentication dependency for administrative API actions.

API mutations are deliberately fail-closed: a deployment without an
``LANCE_ADMIN_TOKEN`` cannot execute them. This module does not log or return
the configured token.
"""
from __future__ import annotations

import hmac
import os
import hashlib
import secrets
import time
from threading import Lock

from fastapi import HTTPException, Request

SESSION_COOKIE = "lance_admin_session"
SESSION_TTL = 8 * 60 * 60
_sessions = {}
_sessions_lock = Lock()


def _session_valid(request: Request, expected: str) -> bool:
    session_id = request.cookies.get(SESSION_COOKIE, "")
    now = time.time()
    with _sessions_lock:
        for key in list(_sessions):
            if _sessions[key][0] <= now:
                del _sessions[key]
        record = _sessions.get(session_id)
    return bool(record and hmac.compare_digest(record[1], hashlib.sha256(expected.encode()).digest()))


def require_session_origin(request: Request) -> None:
    # Non-simple header + no permissive CORS prevents cross-origin form/fetch CSRF.
    origin = request.headers.get("origin")
    expected = f"{request.url.scheme}://{request.url.netloc}"
    if request.headers.get("x-lance-admin-session") != "1" or (origin and origin != expected):
        raise HTTPException(status_code=403, detail="Origine de session administrateur invalide.")


def create_session(expected: str) -> str:
    session_id = secrets.token_urlsafe(32)
    with _sessions_lock:
        now = time.time()
        for key in list(_sessions):
            if _sessions[key][0] <= now:
                del _sessions[key]
        if len(_sessions) >= 256:
            del _sessions[min(_sessions, key=lambda key: _sessions[key][0])]
        _sessions[session_id] = (now + SESSION_TTL, hashlib.sha256(expected.encode()).digest())
    return session_id


def revoke_session(request: Request) -> None:
    with _sessions_lock:
        _sessions.pop(request.cookies.get(SESSION_COOKIE, ""), None)


def _unauthorized() -> None:
    """Raise the one response used for missing, malformed, or bad credentials."""
    raise HTTPException(
        status_code=401,
        detail="Authentification administrateur requise ou invalide.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _server_token() -> str | None:
    """Return the configured token, or ``None`` for an unusable setting."""
    token = os.environ.get("LANCE_ADMIN_TOKEN")
    if token is None or not token.strip():
        return None
    return token


def require_admin_auth(request: Request) -> None:
    """Authorize with Bearer or a revocable session (CSRF-checked on writes).

    The configuration check happens before parsing the request header so a
    missing server key always returns 503 and, importantly, the route handler
    (and therefore any database write) is never reached.  Token comparison is
    constant-time once the Bearer syntax has been validated.
    """
    expected = _server_token()
    if expected is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "admin_auth_not_configured",
                "message": "Authentification administrateur non configurée côté serveur.",
            },
        )

    authorization_values = request.headers.getlist("authorization")
    if not authorization_values and _session_valid(request, expected):
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            require_session_origin(request)
        return
    if len(authorization_values) != 1:
        _unauthorized()
    authorization = authorization_values[0]

    scheme, separator, supplied = authorization.partition(" ")
    # A token is an opaque value without whitespace in an HTTP Bearer field.
    # Reject extra fields and surrounding whitespace as malformed credentials.
    if (
        scheme.lower() != "bearer"
        or not separator
        or not supplied
        or supplied != supplied.strip()
        or any(char.isspace() for char in supplied)
    ):
        _unauthorized()

    if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
        _unauthorized()


def require_mutation_auth(request: Request) -> None:
    """All API mutations are administrative; reads remain unchanged."""
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        require_admin_auth(request)
