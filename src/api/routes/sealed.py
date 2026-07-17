"""Aggregate-only proxy for controller-managed sealed suite evaluations.

This module intentionally has no run state, event stream, artifact endpoint or
filesystem access.  Every operation is a stateless authenticated pass-through
to the private controller, which owns worker execution and data deletion.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Annotated, Any, Iterator
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised only by minimal deployments
    class InvalidSignature(Exception):
        pass

    serialization = None  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]

from src.benchmark.controller import ControllerError, SealedControllerClient
from src.benchmark.catalog import load_catalog


router = APIRouter()

_GENERIC_DISABLED = "Sealed evaluation is unavailable"
_GENERIC_CONTROLLER_ERROR = "Sealed evaluation controller is unavailable"
_GENERIC_AUTH_ERROR = "Invalid sealed evaluation credentials"
_GENERIC_PROVIDER_ERROR = "Provider is not approved for sealed evaluation"
_NO_STORE = "no-store, max-age=0"


class SealedSuiteLaunchRequest(BaseModel):
    """Non-secret runner identity; provider credentials stay controller-side."""

    model_config = ConfigDict(extra="forbid")

    model: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=64)

    @field_validator("model", "provider")
    @classmethod
    def _safe_trimmed_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("must be trimmed text without control characters")
        return value


@dataclass(frozen=True, slots=True)
class _SealedConfiguration:
    controller_url: str
    controller_token: str
    approved_providers: frozenset[str]
    benchmark_version: str
    runner_commit: str
    runner_image_digest: str
    controller_public_key: Any


def _disabled() -> HTTPException:
    return HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=_GENERIC_DISABLED)


def _load_ed25519_public_key(encoded: str) -> Any:
    """Accept an Ed25519 SubjectPublicKeyInfo PEM or base64 raw/DER key."""

    if Ed25519PublicKey is None or serialization is None:
        raise _disabled()
    candidate = encoded.strip()
    try:
        if candidate.startswith("-----BEGIN PUBLIC KEY-----"):
            # Systemd/Docker env files commonly encode PEM newlines as ``\\n``.
            pem = candidate.replace("\\n", "\n").encode("ascii")
            key = serialization.load_pem_public_key(pem)
        else:
            decoded = base64.b64decode(candidate, validate=True)
            if len(decoded) == 32:
                key = Ed25519PublicKey.from_public_bytes(decoded)
            else:
                key = serialization.load_der_public_key(decoded)
    except (ValueError, TypeError, UnicodeEncodeError, binascii.Error) as exc:
        raise _disabled() from exc
    if not isinstance(key, Ed25519PublicKey):
        raise _disabled()
    return key


def _load_configuration(
    launch_token: Annotated[
        str | None,
        Header(alias="X-Sealed-Launch-Token", include_in_schema=True),
    ] = None,
) -> _SealedConfiguration:
    """Load all security settings per request and fail closed if incomplete."""

    controller_url = os.environ.get("SEALED_CONTROLLER_URL", "")
    controller_token = os.environ.get("SEALED_CONTROLLER_TOKEN", "")
    expected_launch_token = os.environ.get("SEALED_LAUNCH_TOKEN", "")
    raw_providers = os.environ.get("SEALED_ZERO_RETENTION_PROVIDERS", "")
    runner_commit = os.environ.get("SEALED_RUNNER_COMMIT", "")
    runner_image_digest = os.environ.get("SEALED_RUNNER_IMAGE_DIGEST", "")
    encoded_public_key = os.environ.get("SEALED_CONTROLLER_PUBLIC_KEY", "")
    if not all(
        value and value == value.strip()
        for value in (
            controller_url,
            controller_token,
            expected_launch_token,
            raw_providers,
            runner_commit,
            runner_image_digest,
        )
    ):
        raise _disabled()
    if not encoded_public_key:
        raise _disabled()
    if len(runner_commit) not in {40, 64} or any(
        char not in "0123456789abcdef" for char in runner_commit
    ):
        raise _disabled()
    if (
        len(runner_image_digest) != 71
        or not runner_image_digest.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in runner_image_digest[7:])
    ):
        raise _disabled()

    approved_providers = frozenset(
        item.strip().casefold() for item in raw_providers.split(",") if item.strip()
    )
    if not approved_providers or "*" in approved_providers:
        raise _disabled()
    if launch_token is None or not secrets.compare_digest(launch_token, expected_launch_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_GENERIC_AUTH_ERROR,
        )
    try:
        benchmark_version = load_catalog().benchmark_version
    except (FileNotFoundError, KeyError, TypeError, ValueError) as exc:
        raise _disabled() from exc
    return _SealedConfiguration(
        controller_url=controller_url,
        controller_token=controller_token,
        approved_providers=approved_providers,
        benchmark_version=benchmark_version,
        runner_commit=runner_commit,
        runner_image_digest=runner_image_digest,
        controller_public_key=_load_ed25519_public_key(encoded_public_key),
    )


@contextmanager
def _controller(configuration: _SealedConfiguration) -> Iterator[SealedControllerClient]:
    try:
        client = SealedControllerClient(
            configuration.controller_url,
            configuration.controller_token,
        )
    except ControllerError as exc:
        raise _disabled() from exc
    try:
        yield client
    finally:
        client.close()


def _canonical_suite_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid suite identifier") from exc
    canonical = str(parsed)
    if value.lower() != canonical:
        raise HTTPException(status_code=400, detail="Invalid suite identifier")
    return canonical


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = _NO_STORE
    response.headers["Pragma"] = "no-cache"


def _verify_terminal_summary(configuration: _SealedConfiguration, summary: Any) -> None:
    """Fail closed unless every terminal result has a valid signature."""

    if summary.status not in {"complete", "failed", "cancelled", "expired"}:
        return
    try:
        signature = base64.b64decode(summary.signature, validate=True)
        if len(signature) != 64:
            raise ValueError("invalid Ed25519 signature length")
        configuration.controller_public_key.verify(signature, summary.signature_payload())
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ControllerError("invalid sealed suite attestation") from exc
    except InvalidSignature as exc:
        raise ControllerError("invalid sealed suite attestation") from exc


def _validate_summary_identity(configuration: _SealedConfiguration, summary: Any) -> None:
    """Reject replay/misrouting from another benchmark or runner build."""

    if (
        summary.benchmark_version != configuration.benchmark_version
        or summary.runner.git_commit != configuration.runner_commit
        or summary.runner.runner_image_digest != configuration.runner_image_digest
        or summary.runner.provider.casefold() not in configuration.approved_providers
    ):
        raise ControllerError("mismatched sealed suite identity")


@router.post("/suites", status_code=status.HTTP_201_CREATED)
def launch_sealed_suite(
    request: SealedSuiteLaunchRequest,
    response: Response,
    configuration: Annotated[_SealedConfiguration, Depends(_load_configuration)],
) -> dict[str, object]:
    """Launch the complete S20-S25 suite inside the private controller."""

    _no_store(response)
    provider = request.provider.casefold()
    if provider not in configuration.approved_providers:
        raise HTTPException(status_code=400, detail=_GENERIC_PROVIDER_ERROR)
    try:
        with _controller(configuration) as client:
            summary = client.create_suite(
                model=request.model,
                provider=provider,
                git_commit=configuration.runner_commit,
                runner_image_digest=configuration.runner_image_digest,
            )
            _validate_summary_identity(configuration, summary)
            _verify_terminal_summary(configuration, summary)
    except HTTPException:
        raise
    except ControllerError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_GENERIC_CONTROLLER_ERROR,
        ) from exc
    return summary.to_dict()


@router.get("/suites/{suite_id}")
def get_sealed_suite(
    suite_id: str,
    response: Response,
    configuration: Annotated[_SealedConfiguration, Depends(_load_configuration)],
) -> dict[str, object]:
    """Return global state or the signed suite aggregate; never run details."""

    _no_store(response)
    canonical_id = _canonical_suite_id(suite_id)
    try:
        with _controller(configuration) as client:
            summary = client.get_suite(canonical_id)
            _validate_summary_identity(configuration, summary)
            _verify_terminal_summary(configuration, summary)
    except HTTPException:
        raise
    except ControllerError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_GENERIC_CONTROLLER_ERROR,
        ) from exc
    return summary.to_dict()


@router.delete("/suites/{suite_id}", status_code=status.HTTP_202_ACCEPTED)
def cancel_sealed_suite(
    suite_id: str,
    response: Response,
    configuration: Annotated[_SealedConfiguration, Depends(_load_configuration)],
) -> dict[str, str]:
    """Request controller-owned cancellation and ephemeral workspace deletion."""

    _no_store(response)
    canonical_id = _canonical_suite_id(suite_id)
    try:
        with _controller(configuration) as client:
            client.cancel_suite(canonical_id)
    except HTTPException:
        raise
    except ControllerError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=_GENERIC_CONTROLLER_ERROR,
        ) from exc
    return {"status": "cancellation-requested"}
