"""Fail-closed wire contracts for sealed benchmark execution.

Only explicitly declared fields are accepted.  This is intentional: silently
ignoring an unexpected controller field could forward topology, seed, ground
truth or other oracle data into the agent worker.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_network
from typing import Literal, Mapping
from uuid import UUID


CONTRACT_SCHEMA_VERSION = "1"
ARTIFACT_SCHEMA_VERSION = "1"
SEALED_SPLIT = "eval-sealed"
SEALED_SCENARIO_MIN = 24
SEALED_SCENARIO_MAX = 29

_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ENTRYPOINT_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,512}$")


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
    if not raw.isdigit() or not SEALED_SCENARIO_MIN <= int(raw) <= SEALED_SCENARIO_MAX:
        raise ContractError(f"{where} must identify a sealed scenario S24-S29")
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


@dataclass(frozen=True, slots=True)
class SuiteEvaluationSummary:
    """Aggregate-only official result for a complete sealed suite."""

    suite_id: str
    benchmark_version: str
    status: Literal["pending", "complete", "failed"]
    metrics: Mapping[str, float] | None
    signature: str | None
    schema_version: str = CONTRACT_SCHEMA_VERSION
    score_visibility: Literal["aggregate"] = "aggregate"

    @classmethod
    def from_dict(cls, raw: object) -> "SuiteEvaluationSummary":
        data = _mapping(raw, "suite evaluation summary")
        keys = frozenset({
            "schema_version",
            "suite_id",
            "benchmark_version",
            "status",
            "score_visibility",
            "metrics",
            "signature",
        })
        _exact_keys(data, allowed=keys, where="suite evaluation summary")
        if _version(data["schema_version"], "schema_version") != CONTRACT_SCHEMA_VERSION:
            raise ContractError("unsupported suite evaluation schema_version")
        status = _string(data["status"], "suite evaluation status", max_length=16)
        if status not in {"pending", "complete", "failed"}:
            raise ContractError(f"unsupported suite evaluation status: {status}")
        if data["score_visibility"] != "aggregate":
            raise ContractError("sealed suite evaluation may expose aggregate scores only")

        metrics: dict[str, float] | None = None
        signature: str | None = None
        if status == "complete":
            raw_metrics = _mapping(data["metrics"], "suite evaluation metrics")
            _exact_keys(
                raw_metrics,
                allowed=_AGGREGATE_METRICS,
                required=frozenset({"overall_score"}),
                where="suite evaluation metrics",
            )
            metrics = {}
            for key, value in raw_metrics.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise ContractError(f"suite evaluation metric {key} must be numeric")
                numeric = float(value)
                if not -float("inf") < numeric < float("inf"):
                    raise ContractError(f"suite evaluation metric {key} must be finite")
                if key in _RATIO_AGGREGATE_METRICS and not 0.0 <= numeric <= 1.0:
                    raise ContractError(
                        f"suite evaluation metric {key} must be a normalized ratio in [0, 1]"
                    )
                if key == "cost_usd" and numeric < 0.0:
                    raise ContractError("suite evaluation metric cost_usd must be non-negative USD")
                metrics[key] = numeric
            signature = _string(data["signature"], "suite evaluation signature", max_length=4096)
        elif data["metrics"] is not None or data["signature"] is not None:
            raise ContractError(
                "pending/failed suite evaluations must not expose metrics or signatures"
            )

        return cls(
            suite_id=_uuid(data["suite_id"], "suite_id"),
            benchmark_version=_version(data["benchmark_version"], "benchmark_version"),
            status=status,  # type: ignore[arg-type]
            metrics=metrics,
            signature=signature,
        )
