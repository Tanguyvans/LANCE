"""Fail-closed wire contracts for sealed benchmark execution.

Only explicitly declared fields are accepted.  This is intentional: silently
ignoring an unexpected controller field could forward topology, seed, ground
truth or other oracle data into the agent worker.
"""

from __future__ import annotations

import base64
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_network
from typing import Literal, Mapping
from uuid import UUID


CONTRACT_SCHEMA_VERSION = "1"
ARTIFACT_SCHEMA_VERSION = "1"
SEALED_SPLIT = "eval-sealed"
SUITE_SCORE_VISIBILITY = "suite-aggregate"
SEALED_SIGNATURE_DOMAIN = "iotchainbench.sealed-suite.ed25519.v1"

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ENTRYPOINT_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,512}$")
_SEALED_PRIVATE_V4 = tuple(
    ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SEALED_PRIVATE_V6 = (ip_network("fc00::/7"),)


class ContractError(ValueError):
    """Raised when a controller or submission payload violates its schema."""


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ContractError(f"{where} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ContractError(f"{where} contains a non-string key")
    return value


def _exact_keys(
    data: Mapping[str, object],
    *,
    allowed: frozenset[str],
    required: frozenset[str] | None = None,
    where: str,
) -> None:
    required = allowed if required is None else required
    keys = frozenset(data)
    unknown = keys - allowed
    missing = required - keys
    if unknown:
        raise ContractError(f"{where} contains forbidden/unknown keys: {sorted(unknown)}")
    if missing:
        raise ContractError(f"{where} is missing required keys: {sorted(missing)}")


def _string(value: object, where: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContractError(f"{where} must be a non-empty, trimmed string")
    if len(value) > max_length:
        raise ContractError(f"{where} exceeds {max_length} characters")
    return value


def _version(value: object, where: str) -> str:
    result = _string(value, where, max_length=64)
    if not _VERSION_RE.fullmatch(result):
        raise ContractError(f"{where} is not a valid version identifier")
    return result


def _uuid(value: object, where: str) -> str:
    raw = _string(value, where, max_length=64)
    try:
        parsed = UUID(raw)
    except (ValueError, AttributeError) as exc:
        raise ContractError(f"{where} must be a UUID") from exc
    canonical = str(parsed)
    if raw.lower() != canonical:
        raise ContractError(f"{where} must use canonical UUID form")
    return canonical


def _sealed_scenario_id(value: object, where: str = "scenario_id") -> str:
    raw = _string(value, where, max_length=2)
    if not raw.isdigit() or not 20 <= int(raw) <= 25:
        raise ContractError(f"{where} must identify a sealed scenario S20-S25")
    return raw


def _positive_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ContractError(f"{where} must be a positive integer")
    return value


def _nonnegative_int(value: object, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{where} must be a non-negative integer")
    return value


def _positive_number(value: object, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{where} must be a positive number")
    result = float(value)
    if not 0 < result < float("inf"):
        raise ContractError(f"{where} must be finite and greater than zero")
    return result


@dataclass(frozen=True, slots=True)
class ChallengeScope:
    ingress_cidrs: tuple[str, ...]
    entrypoints: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: object) -> "ChallengeScope":
        data = _mapping(raw, "scope")
        _exact_keys(
            data,
            allowed=frozenset({"ingress_cidrs", "entrypoints"}),
            required=frozenset({"ingress_cidrs"}),
            where="scope",
        )
        raw_cidrs = data["ingress_cidrs"]
        raw_entrypoints = data.get("entrypoints", [])
        if not isinstance(raw_cidrs, list) or not isinstance(raw_entrypoints, list):
            raise ContractError("scope.ingress_cidrs and scope.entrypoints must be arrays")

        # The pipeline derives its discovery target from this network scope.
        # Entrypoints are optional, non-authoritative hints and can therefore
        # never replace an explicit CIDR authorization boundary.
        if not raw_cidrs:
            raise ContractError("scope.ingress_cidrs must contain at least one CIDR")

        cidrs: list[str] = []
        for index, value in enumerate(raw_cidrs):
            cidr = _string(value, f"scope.ingress_cidrs[{index}]", max_length=64)
            try:
                parsed = ip_network(cidr, strict=True)
            except ValueError as exc:
                raise ContractError(f"scope.ingress_cidrs[{index}] is not a canonical CIDR") from exc
            canonical = parsed.with_prefixlen
            if cidr != canonical:
                raise ContractError(f"scope.ingress_cidrs[{index}] must use canonical form {canonical}")
            allowed_parents = (
                _SEALED_PRIVATE_V4 if parsed.version == 4 else _SEALED_PRIVATE_V6
            )
            minimum_prefix = 16 if parsed.version == 4 else 48
            if (
                parsed.prefixlen < minimum_prefix
                or not any(parsed.subnet_of(parent) for parent in allowed_parents)
            ):
                raise ContractError(
                    f"scope.ingress_cidrs[{index}] must be a bounded RFC1918 "
                    "or IPv6 ULA challenge network"
                )
            cidrs.append(canonical)

        entrypoints: list[str] = []
        for index, value in enumerate(raw_entrypoints):
            endpoint = _string(value, f"scope.entrypoints[{index}]")
            if not _SAFE_ENTRYPOINT_RE.fullmatch(endpoint):
                raise ContractError(f"scope.entrypoints[{index}] contains unsafe characters")
            entrypoints.append(endpoint)

        if len(set(cidrs)) != len(cidrs) or len(set(entrypoints)) != len(entrypoints):
            raise ContractError("scope contains duplicate CIDRs or entrypoints")
        return cls(ingress_cidrs=tuple(cidrs), entrypoints=tuple(entrypoints))

    def to_dict(self) -> dict[str, object]:
        return {"ingress_cidrs": list(self.ingress_cidrs), "entrypoints": list(self.entrypoints)}


@dataclass(frozen=True, slots=True)
class RunLimits:
    expires_at: str
    max_cost_usd: float
    max_tool_calls: int

    @classmethod
    def from_dict(cls, raw: object) -> "RunLimits":
        data = _mapping(raw, "limits")
        _exact_keys(
            data,
            allowed=frozenset({"expires_at", "max_cost_usd", "max_tool_calls"}),
            where="limits",
        )
        expires_at = _string(data["expires_at"], "limits.expires_at", max_length=64)
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ContractError("limits.expires_at must be an ISO-8601 timestamp") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ContractError("limits.expires_at must include a timezone")
        return cls(
            expires_at=expires_at,
            max_cost_usd=_positive_number(data["max_cost_usd"], "limits.max_cost_usd"),
            max_tool_calls=_positive_int(data["max_tool_calls"], "limits.max_tool_calls"),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "expires_at": self.expires_at,
            "max_cost_usd": self.max_cost_usd,
            "max_tool_calls": self.max_tool_calls,
        }


@dataclass(frozen=True, slots=True)
class ChallengeContract:
    session_id: str
    scenario_id: str
    benchmark_version: str
    scope: ChallengeScope
    limits: RunLimits
    schema_version: str = CONTRACT_SCHEMA_VERSION
    split: Literal["eval-sealed"] = SEALED_SPLIT
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, raw: object) -> "ChallengeContract":
        data = _mapping(raw, "challenge contract")
        keys = frozenset(
            {
                "schema_version",
                "session_id",
                "scenario_id",
                "split",
                "benchmark_version",
                "scope",
                "limits",
                "artifact_schema_version",
            }
        )
        _exact_keys(data, allowed=keys, where="challenge contract")
        schema_version = _version(data["schema_version"], "schema_version")
        split = _string(data["split"], "split", max_length=32)
        artifact_schema_version = _version(data["artifact_schema_version"], "artifact_schema_version")
        if schema_version != CONTRACT_SCHEMA_VERSION:
            raise ContractError(f"unsupported contract schema_version: {schema_version}")
        if split != SEALED_SPLIT:
            raise ContractError("sealed challenge split must be eval-sealed")
        if artifact_schema_version != ARTIFACT_SCHEMA_VERSION:
            raise ContractError(f"unsupported artifact_schema_version: {artifact_schema_version}")
        return cls(
            session_id=_uuid(data["session_id"], "session_id"),
            scenario_id=_sealed_scenario_id(data["scenario_id"]),
            benchmark_version=_version(data["benchmark_version"], "benchmark_version"),
            scope=ChallengeScope.from_dict(data["scope"]),
            limits=RunLimits.from_dict(data["limits"]),
        )

    @classmethod
    def from_json(cls, payload: str | bytes) -> "ChallengeContract":
        try:
            raw = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise ContractError("challenge contract is not valid JSON") from exc
        return cls.from_dict(raw)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "split": self.split,
            "benchmark_version": self.benchmark_version,
            "scope": self.scope.to_dict(),
            "limits": self.limits.to_dict(),
            "artifact_schema_version": self.artifact_schema_version,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class ArtifactDigest:
    path: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_dict(cls, raw: object) -> "ArtifactDigest":
        data = _mapping(raw, "artifact")
        _exact_keys(
            data,
            allowed=frozenset({"path", "sha256", "size_bytes"}),
            where="artifact",
        )
        path = _string(data["path"], "artifact.path", max_length=512)
        digest = _string(data["sha256"], "artifact.sha256", max_length=64)
        if not _SHA256_RE.fullmatch(digest):
            raise ContractError("artifact.sha256 must be a lowercase SHA-256 digest")
        return cls(path=path, sha256=digest, size_bytes=_nonnegative_int(data["size_bytes"], "artifact.size_bytes"))

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "size_bytes": self.size_bytes}


@dataclass(frozen=True, slots=True)
class SubmissionManifest:
    session_id: str
    scenario_id: str
    run_id: str
    benchmark_version: str
    artifacts: tuple[ArtifactDigest, ...]
    schema_version: str = CONTRACT_SCHEMA_VERSION
    artifact_schema_version: str = ARTIFACT_SCHEMA_VERSION

    @classmethod
    def from_dict(cls, raw: object) -> "SubmissionManifest":
        data = _mapping(raw, "submission manifest")
        keys = frozenset(
            {
                "schema_version",
                "session_id",
                "scenario_id",
                "run_id",
                "benchmark_version",
                "artifact_schema_version",
                "artifacts",
            }
        )
        _exact_keys(data, allowed=keys, where="submission manifest")
        if _version(data["schema_version"], "schema_version") != CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported submission schema_version")
        if _version(data["artifact_schema_version"], "artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
            raise ContractError("unsupported artifact_schema_version")
        run_id = _string(data["run_id"], "run_id", max_length=128)
        if not _RUN_ID_RE.fullmatch(run_id):
            raise ContractError("run_id contains unsafe characters")
        raw_artifacts = data["artifacts"]
        if not isinstance(raw_artifacts, list) or not raw_artifacts:
            raise ContractError("submission manifest must contain at least one artifact")
        artifacts = tuple(ArtifactDigest.from_dict(item) for item in raw_artifacts)
        paths = [artifact.path for artifact in artifacts]
        if len(set(paths)) != len(paths):
            raise ContractError("submission manifest contains duplicate artifact paths")
        if paths != sorted(paths):
            raise ContractError("submission artifacts must be sorted by path")
        return cls(
            session_id=_uuid(data["session_id"], "session_id"),
            scenario_id=_sealed_scenario_id(data["scenario_id"]),
            run_id=run_id,
            benchmark_version=_version(data["benchmark_version"], "benchmark_version"),
            artifacts=artifacts,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "scenario_id": self.scenario_id,
            "run_id": self.run_id,
            "benchmark_version": self.benchmark_version,
            "artifact_schema_version": self.artifact_schema_version,
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class SubmissionReceipt:
    submission_id: str
    status: Literal["accepted", "evaluating"]

    @classmethod
    def from_dict(cls, raw: object) -> "SubmissionReceipt":
        data = _mapping(raw, "submission receipt")
        _exact_keys(data, allowed=frozenset({"submission_id", "status"}), where="submission receipt")
        status = _string(data["status"], "submission receipt.status", max_length=16)
        if status not in {"accepted", "evaluating"}:
            raise ContractError(f"unsupported submission status: {status}")
        return cls(
            submission_id=_uuid(data["submission_id"], "submission_id"),
            status=status,  # type: ignore[arg-type]
        )


_AGGREGATE_METRICS = frozenset(
    {
        "overall_score",
        "precision",
        "recall",
        "f1",
        "exploitation_coverage",
        "path_coverage",
        "cost_usd",
    }
)
_RATIO_AGGREGATE_METRICS = _AGGREGATE_METRICS - {"cost_usd"}


@dataclass(frozen=True, slots=True)
class EvaluationSummary:
    submission_id: str
    scenario_id: str
    benchmark_version: str
    status: Literal["pending", "complete", "failed"]
    metrics: Mapping[str, float] | None
    signature: str | None
    schema_version: str = CONTRACT_SCHEMA_VERSION
    score_visibility: Literal["aggregate"] = "aggregate"

    @classmethod
    def from_dict(cls, raw: object) -> "EvaluationSummary":
        data = _mapping(raw, "evaluation summary")
        keys = frozenset(
            {
                "schema_version",
                "submission_id",
                "scenario_id",
                "benchmark_version",
                "status",
                "score_visibility",
                "metrics",
                "signature",
            }
        )
        _exact_keys(data, allowed=keys, where="evaluation summary")
        if _version(data["schema_version"], "schema_version") != CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported evaluation schema_version")
        status = _string(data["status"], "evaluation status", max_length=16)
        if status not in {"pending", "complete", "failed"}:
            raise ContractError(f"unsupported evaluation status: {status}")
        if data["score_visibility"] != "aggregate":
            raise ContractError("sealed evaluation may expose aggregate scores only")

        metrics: dict[str, float] | None = None
        signature: str | None = None
        if status == "complete":
            raw_metrics = _mapping(data["metrics"], "evaluation metrics")
            _exact_keys(
                raw_metrics,
                allowed=_AGGREGATE_METRICS,
                required=frozenset({"overall_score"}),
                where="evaluation metrics",
            )
            metrics = {}
            for key, value in raw_metrics.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ContractError(f"evaluation metric {key} must be numeric")
                numeric = float(value)
                if not -float("inf") < numeric < float("inf"):
                    raise ContractError(f"evaluation metric {key} must be finite")
                if key in _RATIO_AGGREGATE_METRICS and not 0.0 <= numeric <= 1.0:
                    raise ContractError(
                        f"evaluation metric {key} must be a normalized ratio in [0, 1]"
                    )
                if key == "cost_usd" and numeric < 0.0:
                    raise ContractError("evaluation metric cost_usd must be non-negative USD")
                metrics[key] = numeric
            signature = _string(data["signature"], "evaluation signature", max_length=4096)
        elif data["metrics"] is not None or data["signature"] is not None:
            raise ContractError("pending/failed evaluations must not expose metrics or signatures")

        return cls(
            submission_id=_uuid(data["submission_id"], "submission_id"),
            scenario_id=_sealed_scenario_id(data["scenario_id"]),
            benchmark_version=_version(data["benchmark_version"], "benchmark_version"),
            status=status,  # type: ignore[arg-type]
            metrics=metrics,
            signature=signature,
        )


_SUITE_STATUSES = frozenset(
    {"queued", "running", "complete", "failed", "cancelled", "expired"}
)
_TERMINAL_SUITE_STATUSES = frozenset({"complete", "failed", "cancelled", "expired"})
_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_MODEL_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUNNER_IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class SealedDataPolicy:
    """Exact permitted lifecycle for data produced by a sealed evaluation.

    ``inference_retention`` forbids the model provider from retaining prompts,
    responses or tool traffic. ``improvement_use`` forbids using any evaluation
    data or logs to train, tune, select or otherwise improve the harness or a
    model. ``raw_artifact_retention`` permits controller-private raw artifacts
    only while scoring is active; successful scoring or an abort must end in a
    signed deletion attestation. ``feedback_visibility`` limits the public
    result to a suite aggregate, never per-scenario feedback or logs.

    These are fixed protocol values rather than advisory free-form strings. A
    different lifecycle therefore requires a new schema version.
    """

    inference_retention: Literal["zero-data-retention"] = "zero-data-retention"
    improvement_use: Literal["prohibited"] = "prohibited"
    raw_artifact_retention: Literal["delete-after-scoring"] = "delete-after-scoring"
    feedback_visibility: Literal["suite-aggregate-only"] = "suite-aggregate-only"

    @classmethod
    def from_dict(cls, raw: object) -> "SealedDataPolicy":
        data = _mapping(raw, "sealed data policy")
        keys = frozenset(
            {
                "inference_retention",
                "improvement_use",
                "raw_artifact_retention",
                "feedback_visibility",
            }
        )
        _exact_keys(data, allowed=keys, where="sealed data policy")
        expected = cls().to_dict()
        for key, value in expected.items():
            if data[key] != value:
                raise ContractError(f"sealed data policy {key} must be {value!r}")
        return cls()

    def to_dict(self) -> dict[str, str]:
        return {
            "inference_retention": self.inference_retention,
            "improvement_use": self.improvement_use,
            "raw_artifact_retention": self.raw_artifact_retention,
            "feedback_visibility": self.feedback_visibility,
        }


@dataclass(frozen=True, slots=True)
class SealedDeletionAttestation:
    """Signed assertion that controller-private evaluation data was erased.

    ``status=deleted`` means deletion completed before the result was signed.
    ``evidence_digest`` is the SHA-256 commitment to a controller-private
    deletion receipt. The receipt and raw evidence stay private, so this field
    proves what the controller signed without publishing logs or oracle data.
    """

    status: Literal["deleted"]
    evidence_digest: str

    @classmethod
    def from_dict(cls, raw: object) -> "SealedDeletionAttestation":
        data = _mapping(raw, "sealed deletion attestation")
        _exact_keys(
            data,
            allowed=frozenset({"status", "evidence_digest"}),
            where="sealed deletion attestation",
        )
        if data["status"] != "deleted":
            raise ContractError("sealed deletion attestation status must be 'deleted'")
        evidence_digest = _string(
            data["evidence_digest"],
            "sealed deletion attestation evidence_digest",
            max_length=71,
        )
        if not _EVIDENCE_DIGEST_RE.fullmatch(evidence_digest):
            raise ContractError(
                "sealed deletion attestation evidence_digest must be a sha256 digest"
            )
        return cls(status="deleted", evidence_digest=evidence_digest)

    def to_dict(self) -> dict[str, str]:
        return {"status": self.status, "evidence_digest": self.evidence_digest}


@dataclass(frozen=True, slots=True)
class SealedRunnerIdentity:
    """Signed identity of the exact harness/model evaluated by a suite.

    The source commit identifies the code, while ``runner_image_digest`` binds
    the immutable OCI image that actually executed it. ``model_digest`` binds
    the resolved model artifact independently of its human-readable name.
    """

    model: str
    provider: str
    git_commit: str
    model_digest: str
    runner_image_digest: str

    @classmethod
    def from_dict(cls, raw: object) -> "SealedRunnerIdentity":
        data = _mapping(raw, "sealed runner identity")
        _exact_keys(
            data,
            allowed=frozenset(
                {
                    "model",
                    "provider",
                    "git_commit",
                    "model_digest",
                    "runner_image_digest",
                }
            ),
            where="sealed runner identity",
        )
        model = _string(data["model"], "sealed runner model", max_length=256)
        provider = _string(data["provider"], "sealed runner provider", max_length=64)
        git_commit = _string(data["git_commit"], "sealed runner git_commit", max_length=64)
        model_digest = _string(data["model_digest"], "sealed runner model_digest", max_length=71)
        runner_image_digest = _string(
            data["runner_image_digest"],
            "sealed runner runner_image_digest",
            max_length=71,
        )
        if not _COMMIT_RE.fullmatch(git_commit):
            raise ContractError("sealed runner git_commit must be a 40/64-character lowercase hex digest")
        if not _MODEL_DIGEST_RE.fullmatch(model_digest):
            raise ContractError("sealed runner model_digest must be a sha256 digest")
        if not _RUNNER_IMAGE_DIGEST_RE.fullmatch(runner_image_digest):
            raise ContractError(
                "sealed runner runner_image_digest must be an OCI sha256 digest"
            )
        return cls(
            model=model,
            provider=provider,
            git_commit=git_commit,
            model_digest=model_digest,
            runner_image_digest=runner_image_digest,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "model": self.model,
            "provider": self.provider,
            "git_commit": self.git_commit,
            "model_digest": self.model_digest,
            "runner_image_digest": self.runner_image_digest,
        }


@dataclass(frozen=True, slots=True)
class SealedSuiteSummary:
    """Controller-owned, suite-level result safe for the public control plane.

    The exact-key contract deliberately has no scenario identifier, progress,
    event, error-detail or log field.  A controller that accidentally returns
    any of those fields is rejected before its response reaches the dashboard.
    """

    suite_id: str
    benchmark_version: str
    runner: SealedRunnerIdentity
    status: Literal["queued", "running", "complete", "failed", "cancelled", "expired"]
    data_policy: SealedDataPolicy
    deletion_attestation: SealedDeletionAttestation | None
    metrics: Mapping[str, float] | None
    signature: str | None
    schema_version: str = CONTRACT_SCHEMA_VERSION
    score_visibility: Literal["suite-aggregate"] = SUITE_SCORE_VISIBILITY

    @classmethod
    def from_dict(cls, raw: object) -> "SealedSuiteSummary":
        data = _mapping(raw, "sealed suite summary")
        keys = frozenset(
            {
                "schema_version",
                "suite_id",
                "benchmark_version",
                "runner",
                "status",
                "score_visibility",
                "data_policy",
                "deletion_attestation",
                "metrics",
                "signature",
            }
        )
        _exact_keys(data, allowed=keys, where="sealed suite summary")
        if _version(data["schema_version"], "schema_version") != CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported sealed suite schema_version")
        status = _string(data["status"], "sealed suite status", max_length=16)
        if status not in _SUITE_STATUSES:
            raise ContractError(f"unsupported sealed suite status: {status}")
        if data["score_visibility"] != SUITE_SCORE_VISIBILITY:
            raise ContractError("sealed suite may expose suite-aggregate scores only")
        data_policy = SealedDataPolicy.from_dict(data["data_policy"])

        metrics: dict[str, float] | None = None
        if status == "complete":
            raw_metrics = _mapping(data["metrics"], "sealed suite metrics")
            _exact_keys(
                raw_metrics,
                allowed=_AGGREGATE_METRICS,
                required=frozenset({"overall_score"}),
                where="sealed suite metrics",
            )
            metrics = {}
            for key, value in raw_metrics.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ContractError(f"sealed suite metric {key} must be numeric")
                numeric = float(value)
                if not -float("inf") < numeric < float("inf"):
                    raise ContractError(f"sealed suite metric {key} must be finite")
                if key in _RATIO_AGGREGATE_METRICS and not 0.0 <= numeric <= 1.0:
                    raise ContractError(
                        f"sealed suite metric {key} must be a normalized ratio in [0, 1]"
                    )
                if key == "cost_usd" and numeric < 0.0:
                    raise ContractError("sealed suite metric cost_usd must be non-negative USD")
                metrics[key] = numeric
        elif data["metrics"] is not None:
            raise ContractError("only complete sealed suites may expose metrics")

        signature: str | None = None
        deletion_attestation: SealedDeletionAttestation | None = None
        if status in _TERMINAL_SUITE_STATUSES:
            deletion_attestation = SealedDeletionAttestation.from_dict(
                data["deletion_attestation"]
            )
            signature = _string(data["signature"], "sealed suite signature", max_length=4096)
        elif data["signature"] is not None or data["deletion_attestation"] is not None:
            raise ContractError(
                "queued/running sealed suites must not expose signatures or deletion attestations"
            )

        return cls(
            suite_id=_uuid(data["suite_id"], "suite_id"),
            benchmark_version=_version(data["benchmark_version"], "benchmark_version"),
            runner=SealedRunnerIdentity.from_dict(data["runner"]),
            status=status,  # type: ignore[arg-type]
            data_policy=data_policy,
            deletion_attestation=deletion_attestation,
            metrics=metrics,
            signature=signature,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "suite_id": self.suite_id,
            "benchmark_version": self.benchmark_version,
            "runner": self.runner.to_dict(),
            "status": self.status,
            "score_visibility": self.score_visibility,
            "data_policy": self.data_policy.to_dict(),
            "deletion_attestation": (
                self.deletion_attestation.to_dict()
                if self.deletion_attestation is not None
                else None
            ),
            "metrics": dict(self.metrics) if self.metrics is not None else None,
            "signature": self.signature,
        }

    def signature_payload(self) -> bytes:
        """Return the interoperable canonical Ed25519 message.

        The message is a compact UTF-8 JSON array whose positions are fixed by
        protocol version ``iotchainbench.sealed-suite.ed25519.v1``::

            [domain, schema_version, suite_id, benchmark_version,
             model_utf8_base64url, provider_utf8_base64url, git_commit,
             model_digest, runner_image_digest, status, score_visibility,
             [inference_retention, improvement_use,
              raw_artifact_retention, feedback_visibility],
             [deletion_status, deletion_evidence_digest],
             [[metric_name, ieee754_binary64_big_endian_hex], ...]]

        Metric pairs are sorted by their ASCII metric name and are an empty
        array for failed, cancelled and expired suites. ``-0.0`` is
        canonicalized to positive zero. Model and provider text is unpadded
        base64url of its exact UTF-8 bytes, avoiding JSON Unicode-escaping
        differences across languages. The signature is intentionally absent,
        so a controller can construct this message *before* signing it.
        """

        if self.status not in _TERMINAL_SUITE_STATUSES or self.deletion_attestation is None:
            raise ContractError(
                "only a terminal sealed suite with deletion attestation has a signature payload"
            )
        if self.status == "complete" and self.metrics is None:
            raise ContractError("a complete sealed suite signature payload requires metrics")
        if self.status != "complete" and self.metrics is not None:
            raise ContractError("only complete sealed suite signature payloads may contain metrics")

        def utf8_base64url(value: str) -> str:
            return base64.urlsafe_b64encode(value.encode("utf-8")).rstrip(b"=").decode("ascii")

        def binary64_hex(value: float) -> str:
            numeric = float(value)
            if not -float("inf") < numeric < float("inf"):
                raise ContractError("sealed suite signature metrics must be finite")
            if numeric == 0.0:
                numeric = 0.0
            return struct.pack(">d", numeric).hex()

        policy = self.data_policy
        deletion = self.deletion_attestation
        metric_pairs = (
            [[name, binary64_hex(value)] for name, value in sorted(self.metrics.items())]
            if self.metrics is not None
            else []
        )
        payload = [
            SEALED_SIGNATURE_DOMAIN,
            self.schema_version,
            self.suite_id,
            self.benchmark_version,
            utf8_base64url(self.runner.model),
            utf8_base64url(self.runner.provider),
            self.runner.git_commit,
            self.runner.model_digest,
            self.runner.runner_image_digest,
            self.status,
            self.score_visibility,
            [
                policy.inference_retention,
                policy.improvement_use,
                policy.raw_artifact_retention,
                policy.feedback_visibility,
            ],
            [deletion.status, deletion.evidence_digest],
            metric_pairs,
        ]
        return json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
