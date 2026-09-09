"""Small, reusable authentication dependency for administrative API actions.

The provider registry is deliberately fail-closed: a deployment without an
``LANCE_ADMIN_TOKEN`` cannot mutate it.  This module does not log or return
the configured token.
"""
from __future__ import annotations

import hmac
import os

from fastapi import HTTPException, Request


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
    """Authorize an administrative request with ``Authorization: Bearer``.

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
