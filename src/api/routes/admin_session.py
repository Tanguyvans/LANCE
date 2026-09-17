"""Opaque, revocable browser sessions. Never return or persist the admin key."""
from fastapi import APIRouter, Request, Response
from src.api import auth

router = APIRouter()


@router.post("")
def login(request: Request, response: Response):
    # Login always requires the key, not an existing cookie (no silent renewal).
    if not request.headers.get("authorization"):
        auth._unauthorized()
    auth.require_admin_auth(request)
    auth.require_session_origin(request)
    session_id = auth.create_session(auth._server_token())
    auth.revoke_session(request)
    response.set_cookie(auth.SESSION_COOKIE, session_id, max_age=auth.SESSION_TTL,
                        httponly=True, secure=request.url.scheme == "https",
                        samesite="strict", path="/api")
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "expires_in": auth.SESSION_TTL}


@router.get("")
def status(request: Request, response: Response):
    response.headers["Cache-Control"] = "no-store"
    expected = auth._server_token()
    return {"authenticated": bool(expected and auth._session_valid(request, expected))}


@router.delete("")
def logout(request: Request, response: Response):
    auth.require_admin_auth(request)
    auth.revoke_session(request)
    response.delete_cookie(auth.SESSION_COOKIE, path="/api", httponly=True,
                           secure=request.url.scheme == "https", samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": False}
