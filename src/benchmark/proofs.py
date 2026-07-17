"""Trusted proof primitives for strict benchmark evaluation.

The worker controls every artifact in its submission bundle.  A finding's
``evidence`` text and ``evidence_level`` are therefore useful diagnostics, but
they are not trustworthy enough to decide the official score.

``TrustedProofLedger`` is produced inside the evaluator/controller trust zone
after checking per-run canaries or another deterministic verifier.  It is bound
to the exact normalized finding list and ground-truth file by SHA-256 digests,
so it cannot be replayed after either input changes.

The canary helpers deliberately expose only an opaque challenge UUID.  The
private controller keeps the mapping from that UUID to a vulnerability or path
hop; seeing a token in a target must not disclose ground-truth semantics.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Mapping, Sequence
from uuid import UUID, uuid4


PROOF_SCHEMA_VERSION = "1"
CANARY_TOKEN_PREFIX = "icb1"
LEDGER_SIGNATURE_DOMAIN = b"iotchainbench:proof-ledger:v1:"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}$")
_CANARY_RE = re.compile(
    rf"^{CANARY_TOKEN_PREFIX}\.([0-9a-f]{{32}})\.([0-9a-f]{{64}})$"
)


class ProofError(ValueError):
    """Raised when evaluator-owned proof material is absent or invalid."""


def _mapping(raw: object, where: str) -> Mapping[str, object]:
    if not isinstance(raw, Mapping) or not all(isinstance(key, str) for key in raw):
        raise ProofError(f"{where} must be a JSON object")
    return raw


def _exact_keys(
    data: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str] | None = None,
    where: str,
) -> None:
    required_keys = required if required is not None else allowed
    missing = required_keys - set(data)
    extra = set(data) - allowed
    if missing or extra:
        raise ProofError(
            f"{where} has invalid keys (missing={sorted(missing)}, extra={sorted(extra)})"
        )


def _safe_id(value: object, where: str) -> str:
    if not isinstance(value, str) or not _SAFE_ID_RE.fullmatch(value):
        raise ProofError(f"{where} must be a non-empty safe identifier")
    return value


def _sha256(value: object, where: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ProofError(f"{where} must be a lowercase SHA-256 digest")
    return value


def _uuid(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise ProofError(f"{where} must be a UUID")
    try:
        canonical = str(UUID(value))
    except ValueError as exc:
        raise ProofError(f"{where} must be a UUID") from exc
    if value != canonical:
        raise ProofError(f"{where} must use canonical UUID formatting")
    return canonical


def _proof_secret(secret: object) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ProofError("proof secret must contain at least 32 bytes")
    return secret


def canonical_findings_sha256(findings: Sequence[Mapping[str, object]]) -> str:
    """Hash the normalized finding list used by the evaluator.

    List order is significant because verdicts bind to ``finding_index``.
    Mapping keys are sorted so controller and evaluator implementations can
    reproduce the digest independently.
    """

    payload = json.dumps(
        list(findings),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def ground_truth_sha256(path: str | Path) -> str:
    """Hash the exact ground-truth bytes used for evaluation."""

    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ProofError(f"ground truth must be a regular non-symlink file: {source}")
    return hashlib.sha256(source.read_bytes()).hexdigest()


def proof_receipt_sha256(receipt: str | bytes) -> str:
    """Return a non-reversible commitment to an evaluator-private receipt."""

    payload = receipt.encode("utf-8") if isinstance(receipt, str) else receipt
    return hashlib.sha256(payload).hexdigest()


def _ledger_signature(
    secret: bytes,
    unsigned_ledger: Mapping[str, object],
) -> str:
    payload = json.dumps(
        unsigned_ledger,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(
        secret,
        LEDGER_SIGNATURE_DOMAIN + payload,
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingVerdict:
    """Trusted disposition for exactly one normalized worker finding."""

    finding_index: int
    disposition: Literal["verified_gt", "verified_extra", "rejected"]
    gt_id: str | None
    evidence_level: int
    verifier_id: str
    proof_digest: str

    def __post_init__(self) -> None:
        if (
            isinstance(self.finding_index, bool)
            or not isinstance(self.finding_index, int)
            or self.finding_index < 0
        ):
            raise ProofError("finding verdict finding_index must be a non-negative integer")
        if self.disposition not in {"verified_gt", "verified_extra", "rejected"}:
            raise ProofError(
                f"unsupported finding verdict disposition: {self.disposition!r}"
            )
        if self.gt_id is not None:
            _safe_id(self.gt_id, "finding verdict gt_id")
        if self.disposition == "verified_gt" and self.gt_id is None:
            raise ProofError("verified_gt finding verdict requires gt_id")
        if self.disposition != "verified_gt" and self.gt_id is not None:
            raise ProofError(f"{self.disposition} finding verdict must not declare gt_id")
        if (
            isinstance(self.evidence_level, bool)
            or not isinstance(self.evidence_level, int)
            or self.evidence_level not in {0, 1, 2, 3}
        ):
            raise ProofError("finding verdict evidence_level must be an integer in [0, 3]")
        if self.disposition in {"verified_gt", "verified_extra"} and self.evidence_level < 1:
            raise ProofError(f"{self.disposition} finding verdict requires evidence_level >= 1")
        if self.disposition == "rejected" and self.evidence_level != 0:
            raise ProofError("rejected finding verdict must use evidence_level 0")
        _safe_id(self.verifier_id, "finding verdict verifier_id")
        _sha256(self.proof_digest, "finding verdict proof_digest")

    @classmethod
    def from_dict(cls, raw: object) -> "FindingVerdict":
        data = _mapping(raw, "finding verdict")
        _exact_keys(
            data,
            allowed=frozenset(
                {
                    "finding_index",
                    "disposition",
                    "gt_id",
                    "evidence_level",
                    "verifier_id",
                    "proof_digest",
                }
            ),
            where="finding verdict",
        )
        finding_index = data["finding_index"]
        if isinstance(finding_index, bool) or not isinstance(finding_index, int) or finding_index < 0:
            raise ProofError("finding verdict finding_index must be a non-negative integer")
        disposition = data["disposition"]
        if disposition not in {"verified_gt", "verified_extra", "rejected"}:
            raise ProofError(f"unsupported finding verdict disposition: {disposition!r}")
        gt_id_raw = data["gt_id"]
        gt_id = None if gt_id_raw is None else _safe_id(gt_id_raw, "finding verdict gt_id")
        evidence_level = data["evidence_level"]
        if (
            isinstance(evidence_level, bool)
            or not isinstance(evidence_level, int)
            or evidence_level not in {0, 1, 2, 3}
        ):
            raise ProofError("finding verdict evidence_level must be an integer in [0, 3]")
        if disposition == "verified_gt" and gt_id is None:
            raise ProofError("verified_gt finding verdict requires gt_id")
        if disposition != "verified_gt" and gt_id is not None:
            raise ProofError(f"{disposition} finding verdict must not declare gt_id")
        if disposition in {"verified_gt", "verified_extra"} and evidence_level < 1:
            raise ProofError(f"{disposition} finding verdict requires evidence_level >= 1")
        if disposition == "rejected" and evidence_level != 0:
            raise ProofError("rejected finding verdict must use evidence_level 0")
        return cls(
            finding_index=finding_index,
            disposition=disposition,  # type: ignore[arg-type]
            gt_id=gt_id,
            evidence_level=evidence_level,
            verifier_id=_safe_id(data["verifier_id"], "finding verdict verifier_id"),
            proof_digest=_sha256(data["proof_digest"], "finding verdict proof_digest"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_index": self.finding_index,
            "disposition": self.disposition,
            "gt_id": self.gt_id,
            "evidence_level": self.evidence_level,
            "verifier_id": self.verifier_id,
            "proof_digest": self.proof_digest,
        }


@dataclass(frozen=True, slots=True)
class PathVerdict:
    """Trusted proof of sequential progress along one expected attack path."""

    path_id: str
    verified: bool
    deepest_verified_hop: int
    verifier_id: str
    proof_digest: str

    def __post_init__(self) -> None:
        _safe_id(self.path_id, "path verdict path_id")
        if not isinstance(self.verified, bool):
            raise ProofError("path verdict verified must be boolean")
        if (
            isinstance(self.deepest_verified_hop, bool)
            or not isinstance(self.deepest_verified_hop, int)
            or self.deepest_verified_hop < 0
        ):
            raise ProofError(
                "path verdict deepest_verified_hop must be a non-negative integer"
            )
        if self.verified is False and self.deepest_verified_hop != 0:
            raise ProofError("an unverified path verdict must use deepest_verified_hop 0")
        _safe_id(self.verifier_id, "path verdict verifier_id")
        _sha256(self.proof_digest, "path verdict proof_digest")

    @classmethod
    def from_dict(cls, raw: object) -> "PathVerdict":
        data = _mapping(raw, "path verdict")
        _exact_keys(
            data,
            allowed=frozenset(
                {
                    "path_id",
                    "verified",
                    "deepest_verified_hop",
                    "verifier_id",
                    "proof_digest",
                }
            ),
            where="path verdict",
        )
        if not isinstance(data["verified"], bool):
            raise ProofError("path verdict verified must be boolean")
        deepest = data["deepest_verified_hop"]
        if isinstance(deepest, bool) or not isinstance(deepest, int) or deepest < 0:
            raise ProofError("path verdict deepest_verified_hop must be a non-negative integer")
        if data["verified"] is False and deepest != 0:
            raise ProofError("an unverified path verdict must use deepest_verified_hop 0")
        return cls(
            path_id=_safe_id(data["path_id"], "path verdict path_id"),
            verified=data["verified"],
            deepest_verified_hop=deepest,
            verifier_id=_safe_id(data["verifier_id"], "path verdict verifier_id"),
            proof_digest=_sha256(data["proof_digest"], "path verdict proof_digest"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "path_id": self.path_id,
            "verified": self.verified,
            "deepest_verified_hop": self.deepest_verified_hop,
            "verifier_id": self.verifier_id,
            "proof_digest": self.proof_digest,
        }


@dataclass(frozen=True, slots=True)
class TrustedProofLedger:
    """Evaluator-owned proof decisions bound to one immutable evaluation input."""

    session_id: str
    scenario_id: str
    findings_sha256: str
    ground_truth_sha256: str
    finding_verdicts: tuple[FindingVerdict, ...]
    signature: str
    path_verdicts: tuple[PathVerdict, ...] = ()
    schema_version: str = PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PROOF_SCHEMA_VERSION:
            raise ProofError(
                f"unsupported trusted proof schema_version: {self.schema_version!r}"
            )
        _uuid(self.session_id, "trusted proof ledger session_id")
        _safe_id(self.scenario_id, "trusted proof ledger scenario_id")
        _sha256(self.findings_sha256, "trusted proof ledger findings_sha256")
        _sha256(
            self.ground_truth_sha256,
            "trusted proof ledger ground_truth_sha256",
        )
        if not isinstance(self.finding_verdicts, tuple) or not all(
            isinstance(item, FindingVerdict) for item in self.finding_verdicts
        ):
            raise ProofError("trusted proof ledger finding_verdicts must be a tuple")
        if not isinstance(self.path_verdicts, tuple) or not all(
            isinstance(item, PathVerdict) for item in self.path_verdicts
        ):
            raise ProofError("trusted proof ledger path_verdicts must be a tuple")
        finding_indices = [item.finding_index for item in self.finding_verdicts]
        if len(finding_indices) != len(set(finding_indices)):
            raise ProofError("trusted proof ledger contains duplicate finding_index verdicts")
        path_ids = [item.path_id for item in self.path_verdicts]
        if len(path_ids) != len(set(path_ids)):
            raise ProofError("trusted proof ledger contains duplicate path_id verdicts")
        _sha256(self.signature, "trusted proof ledger signature")

    @classmethod
    def from_dict(cls, raw: object) -> "TrustedProofLedger":
        data = _mapping(raw, "trusted proof ledger")
        _exact_keys(
            data,
            allowed=frozenset(
                {
                    "schema_version",
                    "session_id",
                    "scenario_id",
                    "findings_sha256",
                    "ground_truth_sha256",
                    "finding_verdicts",
                    "path_verdicts",
                    "signature",
                }
            ),
            where="trusted proof ledger",
        )
        if data["schema_version"] != PROOF_SCHEMA_VERSION:
            raise ProofError(
                f"unsupported trusted proof schema_version: {data['schema_version']!r}"
            )
        raw_finding_verdicts = data["finding_verdicts"]
        raw_path_verdicts = data["path_verdicts"]
        if not isinstance(raw_finding_verdicts, list):
            raise ProofError("trusted proof ledger finding_verdicts must be a list")
        if not isinstance(raw_path_verdicts, list):
            raise ProofError("trusted proof ledger path_verdicts must be a list")
        finding_verdicts = tuple(
            FindingVerdict.from_dict(item) for item in raw_finding_verdicts
        )
        path_verdicts = tuple(PathVerdict.from_dict(item) for item in raw_path_verdicts)
        finding_indices = [item.finding_index for item in finding_verdicts]
        if len(finding_indices) != len(set(finding_indices)):
            raise ProofError("trusted proof ledger contains duplicate finding_index verdicts")
        path_ids = [item.path_id for item in path_verdicts]
        if len(path_ids) != len(set(path_ids)):
            raise ProofError("trusted proof ledger contains duplicate path_id verdicts")
        return cls(
            session_id=_uuid(
                data["session_id"],
                "trusted proof ledger session_id",
            ),
            scenario_id=_safe_id(data["scenario_id"], "trusted proof ledger scenario_id"),
            findings_sha256=_sha256(
                data["findings_sha256"], "trusted proof ledger findings_sha256"
            ),
            ground_truth_sha256=_sha256(
                data["ground_truth_sha256"],
                "trusted proof ledger ground_truth_sha256",
            ),
            finding_verdicts=finding_verdicts,
            path_verdicts=path_verdicts,
            signature=_sha256(
                data["signature"],
                "trusted proof ledger signature",
            ),
        )

    @classmethod
    def issue(
        cls,
        *,
        secret: bytes,
        session_id: str,
        scenario_id: str,
        findings_sha256: str,
        ground_truth_sha256: str,
        finding_verdicts: tuple[FindingVerdict, ...],
        path_verdicts: tuple[PathVerdict, ...] = (),
    ) -> "TrustedProofLedger":
        """Create a controller-authenticated ledger for one evaluation session."""

        unsigned = {
            "schema_version": PROOF_SCHEMA_VERSION,
            "session_id": _uuid(session_id, "trusted proof ledger session_id"),
            "scenario_id": _safe_id(
                scenario_id,
                "trusted proof ledger scenario_id",
            ),
            "findings_sha256": _sha256(
                findings_sha256,
                "trusted proof ledger findings_sha256",
            ),
            "ground_truth_sha256": _sha256(
                ground_truth_sha256,
                "trusted proof ledger ground_truth_sha256",
            ),
            "finding_verdicts": [item.to_dict() for item in finding_verdicts],
            "path_verdicts": [item.to_dict() for item in path_verdicts],
        }
        signature = _ledger_signature(_proof_secret(secret), unsigned)
        return cls(
            session_id=unsigned["session_id"],
            scenario_id=unsigned["scenario_id"],
            findings_sha256=unsigned["findings_sha256"],
            ground_truth_sha256=unsigned["ground_truth_sha256"],
            finding_verdicts=finding_verdicts,
            path_verdicts=path_verdicts,
            signature=signature,
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> "TrustedProofLedger":
        try:
            raw = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ProofError("trusted proof ledger must be valid JSON") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_file(cls, path: str | Path) -> "TrustedProofLedger":
        source = Path(path)
        if not source.is_file() or source.is_symlink():
            raise ProofError(f"trusted proof ledger must be a regular non-symlink file: {source}")
        return cls.from_json(source.read_text(encoding="utf-8"))

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "findings_sha256": self.findings_sha256,
            "ground_truth_sha256": self.ground_truth_sha256,
            "finding_verdicts": [item.to_dict() for item in self.finding_verdicts],
            "path_verdicts": [item.to_dict() for item in self.path_verdicts],
            "signature": self.signature,
        }

    def unsigned_dict(self) -> dict[str, object]:
        data = self.to_dict()
        del data["signature"]
        return data

    def verify_signature(self, secret: bytes) -> None:
        expected = _ledger_signature(_proof_secret(secret), self.unsigned_dict())
        if not hmac.compare_digest(self.signature, expected):
            raise ProofError("trusted proof ledger signature mismatch")

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def validate_bindings(
        self,
        *,
        session_id: str,
        scenario_id: str,
        findings: Sequence[Mapping[str, object]],
        ground_truth_file: str | Path,
        ground_truth_ids: set[str],
        path_ids: set[str],
    ) -> None:
        if self.session_id != _uuid(session_id, "evaluation session_id"):
            raise ProofError("trusted proof ledger session_id mismatch")
        if self.scenario_id != scenario_id:
            raise ProofError("trusted proof ledger scenario_id mismatch")
        if self.findings_sha256 != canonical_findings_sha256(findings):
            raise ProofError("trusted proof ledger findings digest mismatch")
        if self.ground_truth_sha256 != ground_truth_sha256(ground_truth_file):
            raise ProofError("trusted proof ledger ground-truth digest mismatch")
        for verdict in self.finding_verdicts:
            if verdict.finding_index >= len(findings):
                raise ProofError(
                    f"trusted proof verdict finding_index {verdict.finding_index} is out of range"
                )
            if (
                verdict.disposition == "verified_gt"
                and verdict.gt_id not in ground_truth_ids
            ):
                raise ProofError(
                    f"trusted proof verdict references unknown gt_id {verdict.gt_id!r}"
                )
        for verdict in self.path_verdicts:
            if verdict.path_id not in path_ids:
                raise ProofError(
                    f"trusted path verdict references unknown path_id {verdict.path_id!r}"
                )

    def finding_verdict_map(self) -> dict[int, FindingVerdict]:
        return {item.finding_index: item for item in self.finding_verdicts}

    def path_verdict_map(self) -> dict[str, PathVerdict]:
        return {item.path_id: item for item in self.path_verdicts}


def issue_canary(
    secret: bytes,
    *,
    session_id: str,
    challenge_id: str | None = None,
) -> str:
    """Issue an opaque, session-bound proof token for target injection."""

    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ProofError("canary secret must contain at least 32 bytes")
    try:
        canonical_session = str(UUID(session_id))
    except (TypeError, ValueError) as exc:
        raise ProofError("canary session_id must be a UUID") from exc
    if challenge_id is None:
        challenge_hex = uuid4().hex
    else:
        try:
            challenge_hex = UUID(challenge_id).hex
        except (TypeError, ValueError) as exc:
            raise ProofError("canary challenge_id must be a UUID") from exc
    message = f"{CANARY_TOKEN_PREFIX}:{canonical_session}:{challenge_hex}".encode("ascii")
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"{CANARY_TOKEN_PREFIX}.{challenge_hex}.{signature}"


def verify_canary(secret: bytes, *, session_id: str, token: str) -> str | None:
    """Verify a canary and return its opaque canonical challenge UUID."""

    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ProofError("canary secret must contain at least 32 bytes")
    try:
        canonical_session = str(UUID(session_id))
    except (TypeError, ValueError) as exc:
        raise ProofError("canary session_id must be a UUID") from exc
    match = _CANARY_RE.fullmatch(token)
    if match is None:
        return None
    challenge_hex, supplied = match.groups()
    message = f"{CANARY_TOKEN_PREFIX}:{canonical_session}:{challenge_hex}".encode("ascii")
    expected = hmac.new(secret, message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        return None
    return str(UUID(hex=challenge_hex))


def new_canary_secret() -> bytes:
    """Return a controller-private canary secret with 256 bits of entropy."""

    return secrets.token_bytes(32)


__all__ = [
    "CANARY_TOKEN_PREFIX",
    "FindingVerdict",
    "PROOF_SCHEMA_VERSION",
    "PathVerdict",
    "ProofError",
    "TrustedProofLedger",
    "canonical_findings_sha256",
    "ground_truth_sha256",
    "issue_canary",
    "new_canary_secret",
    "proof_receipt_sha256",
    "verify_canary",
]
