"""Minimal authenticated client for the sealed evaluation control plane.

The client belongs in the trusted CLI/API process.  Its bearer token must never
be copied into the agent worker environment or challenge contract.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping
from urllib.parse import urljoin, urlparse
from uuid import UUID

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from src.benchmark.artifacts import manifest_sha256
from src.benchmark.catalog import EVAL_SEALED, BenchmarkCatalog, get_scenario, load_catalog
from src.benchmark.contracts import (
    ChallengeContract,
    ContractError,
    EvaluationSummary,
    SubmissionManifest,
    SubmissionReceipt,
    SuiteEvaluationSummary,
)


DEFAULT_TIMEOUT_SECONDS = 30.0


class ControllerError(RuntimeError):
    """Controller transport, authentication or response validation failed."""


@dataclass(frozen=True, slots=True)
class SessionStatus:
    session_id: str
    status: Literal["preparing", "ready", "running", "failed", "expired"]


def _canonical_uuid(value: str, where: str) -> str:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as exc:
        raise ControllerError(f"{where} must be a UUID") from exc
    canonical = str(parsed)
    if value.lower() != canonical:
        raise ControllerError(f"{where} must use canonical UUID form")
    return canonical


def _safe_optional_text(value: str | None, where: str, *, max_length: int = 256) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > max_length:
        raise ControllerError(f"{where} must be a non-empty trimmed string of at most {max_length} characters")
    return value


def _exact_mapping(raw: object, *, keys: frozenset[str], where: str) -> Mapping[str, object]:
    if not isinstance(raw, Mapping) or not all(isinstance(key, str) for key in raw):
        raise ControllerError(f"{where} must be a JSON object")
    actual = frozenset(raw)
    if actual != keys:
        raise ControllerError(
            f"{where} has an invalid response schema (missing={sorted(keys - actual)}, unknown={sorted(actual - keys)})"
        )
    return raw


def _load_signature_public_key(
    value: Ed25519PublicKey | bytes | str | Path | None,
) -> Ed25519PublicKey | None:
    if value is None:
        return None
    if isinstance(value, Ed25519PublicKey):
        return value
    if isinstance(value, (str, Path)):
        path = Path(value)
        if not path.is_file() or path.is_symlink():
            raise ControllerError(f"sealed signature public key is not a regular file: {path}")
        encoded = path.read_bytes()
    elif isinstance(value, bytes):
        encoded = value
    else:
        raise ControllerError("sealed signature public key must be PEM bytes or a file path")
    try:
        public_key = serialization.load_pem_public_key(encoded)
    except (TypeError, ValueError) as exc:
        raise ControllerError("sealed signature public key is not valid PEM") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise ControllerError("sealed signature public key must be Ed25519")
    return public_key


class SealedControllerClient:
    """Fail-closed HTTP client for creating and scoring sealed sessions."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        verify_tls: bool | str = True,
        allow_insecure: bool = False,
        session: requests.Session | None = None,
        catalog: BenchmarkCatalog | None = None,
        signature_public_key: Ed25519PublicKey | bytes | str | Path | None = None,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ControllerError("controller URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ControllerError("controller URL must not contain credentials, query parameters or fragments")
        if parsed.scheme != "https" and not allow_insecure:
            raise ControllerError("sealed controller requires HTTPS (set allow_insecure only in isolated tests)")
        if not isinstance(token, str) or not token.strip():
            raise ControllerError("sealed controller token is required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ControllerError("controller timeout must be positive")

        self.base_url = base_url.rstrip("/") + "/"
        self._token = token.strip()
        self.timeout = float(timeout)
        self.verify_tls = verify_tls
        self._session = session or requests.Session()
        if hasattr(self._session, "trust_env"):
            self._session.trust_env = False
        self._catalog = catalog or load_catalog()
        self._signature_public_key = _load_signature_public_key(signature_public_key)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r}, token=<redacted>)"

    @classmethod
    def from_env(
        cls,
        *,
        url_env: str = "SEALED_CONTROLLER_URL",
        token_env: str = "SEALED_CONTROLLER_TOKEN",
        public_key_env: str = "SEALED_CONTROLLER_PUBLIC_KEY",
        **kwargs,
    ) -> "SealedControllerClient":
        url = os.environ.get(url_env)
        token = os.environ.get(token_env)
        if not url or not token:
            raise ControllerError(f"{url_env} and {token_env} must be configured in the trusted control plane")
        if "signature_public_key" not in kwargs:
            kwargs["signature_public_key"] = os.environ.get(public_key_env)
        return cls(url, token, **kwargs)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "SealedControllerClient":
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _url(self, path: str) -> str:
        if not path.startswith("v1/") or ".." in path:
            raise ControllerError(f"unsafe controller API path: {path!r}")
        return urljoin(self.base_url, path)

    def _request(
        self,
        method: str,
        path: str,
        *,
        expected_status: frozenset[int],
        **kwargs,
    ) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}))
        headers.update({
            "Accept": "application/json",
            "Authorization": f"Bearer {self._token}",
            "Cache-Control": "no-store",
        })
        kwargs["allow_redirects"] = False
        try:
            response = self._session.request(
                method,
                self._url(path),
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
                **kwargs,
            )
        except requests.RequestException as exc:
            raise ControllerError(f"sealed controller request failed: {method} {path}") from exc
        if response.status_code not in expected_status:
            request_id = response.headers.get("X-Request-ID")
            suffix = f" (request_id={request_id})" if request_id else ""
            # Do not echo a controller body: deployment errors may contain oracle data.
            raise ControllerError(f"sealed controller returned HTTP {response.status_code}{suffix}")
        return response

    @staticmethod
    def _json(response: requests.Response, where: str) -> object:
        try:
            return response.json()
        except (requests.JSONDecodeError, ValueError) as exc:
            raise ControllerError(f"{where} did not return valid JSON") from exc

    def create_session(
        self,
        scenario_id: int | str,
        *,
        benchmark_version: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        git_commit: str | None = None,
        suite_id: str | None = None,
    ) -> ChallengeContract:
        descriptor = get_scenario(scenario_id, catalog=self._catalog)
        if descriptor.split != EVAL_SEALED:
            raise ControllerError(f"scenario S{descriptor.id} is not part of eval-sealed")
        version = benchmark_version or self._catalog.benchmark_version
        payload: dict[str, object] = {
            "scenario_id": descriptor.id,
            "benchmark_version": version,
        }
        runner = {
            key: value
            for key, value in {
                "model": _safe_optional_text(model, "model"),
                "provider": _safe_optional_text(provider, "provider"),
                "git_commit": _safe_optional_text(git_commit, "git_commit", max_length=64),
            }.items()
            if value is not None
        }
        if runner:
            payload["runner"] = runner
        if suite_id is not None:
            payload["suite_id"] = _canonical_uuid(suite_id, "suite_id")

        response = self._request(
            "POST",
            "v1/sessions",
            expected_status=frozenset({201}),
            json=payload,
        )
        envelope = _exact_mapping(self._json(response, "session creation"), keys=frozenset({"contract"}), where="session creation")
        try:
            contract = ChallengeContract.from_dict(envelope["contract"])
        except ContractError as exc:
            raise ControllerError("controller returned an invalid challenge contract") from exc
        if contract.scenario_id != descriptor.id or contract.benchmark_version != version:
            raise ControllerError("controller contract does not match the requested scenario/version")
        return contract

    def get_session_status(self, session_id: str) -> SessionStatus:
        canonical_id = _canonical_uuid(session_id, "session_id")
        response = self._request(
            "GET",
            f"v1/sessions/{canonical_id}",
            expected_status=frozenset({200}),
        )
        data = _exact_mapping(
            self._json(response, "session status"),
            keys=frozenset({"session_id", "status"}),
            where="session status",
        )
        returned_id = _canonical_uuid(str(data["session_id"]), "session_id")
        status = data["status"]
        if returned_id != canonical_id or status not in {"preparing", "ready", "running", "failed", "expired"}:
            raise ControllerError("controller returned an invalid session status")
        return SessionStatus(session_id=returned_id, status=status)  # type: ignore[arg-type]

    def submit(
        self,
        bundle_path: str | Path,
        manifest: SubmissionManifest,
    ) -> SubmissionReceipt:
        bundle = Path(bundle_path)
        if not bundle.is_file() or bundle.is_symlink():
            raise ControllerError(f"submission bundle must be a regular file: {bundle}")
        with bundle.open("rb") as handle:
            response = self._request(
                "POST",
                f"v1/sessions/{manifest.session_id}/submissions",
                expected_status=frozenset({202}),
                data={
                    "manifest": manifest.to_json(),
                    "manifest_sha256": manifest_sha256(manifest),
                },
                files={"bundle": (bundle.name, handle, "application/zip")},
            )
        try:
            return SubmissionReceipt.from_dict(self._json(response, "submission receipt"))
        except ContractError as exc:
            raise ControllerError("controller returned an invalid submission receipt") from exc

    def get_evaluation(self, submission_id: str) -> EvaluationSummary:
        canonical_id = _canonical_uuid(submission_id, "submission_id")
        response = self._request(
            "GET",
            f"v1/submissions/{canonical_id}",
            expected_status=frozenset({200}),
        )
        try:
            summary = EvaluationSummary.from_dict(self._json(response, "evaluation summary"))
        except ContractError as exc:
            raise ControllerError("controller returned an invalid evaluation summary") from exc
        if summary.submission_id != canonical_id:
            raise ControllerError("evaluation summary submission_id mismatch")
        return summary

    def get_suite_evaluation(self, suite_id: str) -> SuiteEvaluationSummary:
        """Fetch the official aggregate-only result after suite finalization."""
        canonical_id = _canonical_uuid(suite_id, "suite_id")
        response = self._request(
            "GET",
            f"v1/suites/{canonical_id}",
            expected_status=frozenset({200}),
        )
        try:
            summary = SuiteEvaluationSummary.from_dict(
                self._json(response, "suite evaluation summary")
            )
        except ContractError as exc:
            raise ControllerError("controller returned an invalid suite evaluation summary") from exc
        if summary.suite_id != canonical_id:
            raise ControllerError("suite evaluation summary suite_id mismatch")
        if summary.benchmark_version != self._catalog.benchmark_version:
            raise ControllerError("suite evaluation summary benchmark version mismatch")
        if summary.status == "complete":
            if self._signature_public_key is None:
                raise ControllerError(
                    "a trusted Ed25519 public key is required for complete suite results"
                )
            assert summary.signature is not None
            prefix = "ed25519:"
            if not summary.signature.startswith(prefix):
                raise ControllerError("suite evaluation signature has an unsupported format")
            encoded_signature = summary.signature.removeprefix(prefix)
            if not encoded_signature or "=" in encoded_signature:
                raise ControllerError("suite evaluation signature is not canonical base64url")
            try:
                padding = "=" * (-len(encoded_signature) % 4)
                signature = base64.b64decode(
                    encoded_signature + padding,
                    altchars=b"-_",
                    validate=True,
                )
            except (binascii.Error, ValueError) as exc:
                raise ControllerError("suite evaluation signature is not valid base64url") from exc
            if len(signature) != 64:
                raise ControllerError("suite evaluation Ed25519 signature must be 64 bytes")
            try:
                self._signature_public_key.verify(signature, summary.signature_payload())
            except InvalidSignature as exc:
                raise ControllerError("suite evaluation signature verification failed") from exc
        return summary

    def teardown(self, session_id: str) -> None:
        canonical_id = _canonical_uuid(session_id, "session_id")
        self._request(
            "DELETE",
            f"v1/sessions/{canonical_id}",
            expected_status=frozenset({202, 204}),
        )
