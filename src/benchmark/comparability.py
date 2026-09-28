"""Configuration identity used to decide whether run scores may be averaged."""
from __future__ import annotations

import json
import math
from typing import Any, Mapping

from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION, METRIC_CONTRACT_VERSION


# These are execution/scoring settings, not campaign or scenario identifiers.
# Keep the list explicit so a newly introduced setting cannot silently become
# comparable merely because older metadata omitted it.
COMPARABILITY_FIELDS = (
    "provider",
    "model",
    "execution_profile",
    "execution_profile_policy",
    "blind",
    "max_cost_usd",
    "max_tool_calls",
    "effective_phases",
    "phase_models",
    "execution_profile_config",
    "prompt_manifest_sha256",
    "tool_manifest_sha256",
    "scoring_policy",
    "metric_contract_version",
    "evidence_contract_version",
)

POLICY_FIELDS = (
    "policy_schema_version", "decision_policy", "experiment_scope", "rules_version",
    "resource_manifest_sha256", "max_duration_s", "workers", "execution_ledger_version", "analysis_limits",
)


def _canonical(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(
            not isinstance(key, (str, int)) or isinstance(key, bool)
            for key in value
        ):
            raise TypeError("unsupported metadata mapping key")
        names = [str(key) for key in value]
        if len(names) != len(set(names)):
            raise ValueError("ambiguous metadata mapping keys")
        return {str(key): _canonical(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("non-finite number")
    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value
    raise TypeError(f"unsupported metadata type: {type(value).__name__}")


def configuration_identity(
    metadata: Mapping[str, Any] | None,
    *,
    scoring_policy: str | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Return a canonical complete identity, or an explicit reason it is absent."""
    if not isinstance(metadata, Mapping):
        return None, "configuration metadata is missing"
    values = dict(metadata)
    policy_fields = ()
    if "policy_schema_version" in values:
        policy_fields = POLICY_FIELDS
        missing = [key for key in policy_fields if key not in values]
        if missing:
            return None, "policy metadata missing: " + ", ".join(missing)
        if type(values["policy_schema_version"]) is not int or values["policy_schema_version"] != 1:
            return None, "unsupported policy schema"
        if values["decision_policy"] not in {"rules", "llm"}:
            return None, "unsupported decision policy"
        if values["experiment_scope"] != "analysis-verification" or values.get("effective_phases") != [3, 4]:
            return None, "unsupported experiment scope"
        if values.get("execution_profile") != "full" or values.get("execution_profile_policy") != "full" or values.get("phase_models") != {}:
            return None, "experiment profile must be explicitly full with no overrides"
        if type(values["workers"]) is not int or values["workers"] != 1 or type(values["execution_ledger_version"]) is not int or values["execution_ledger_version"] != 2:
            return None, "unsupported experiment execution settings"
        for key in ("max_duration_s", "max_tool_calls"):
            value = values.get(key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                return None, f"experiment {key} must be positive and finite"
        for key in ("rules_version", "resource_manifest_sha256"):
            if not isinstance(values[key], str) or not values[key].strip():
                return None, f"{key} is missing or empty"
        if not isinstance(values["analysis_limits"], Mapping) or not values["analysis_limits"]:
            return None, "analysis_limits is missing or invalid"
        if values["decision_policy"] == "rules" and (values.get("model") is not None or values.get("provider") is not None):
            return None, "rules policy must have null provider and model"
    elif "decision_policy" in values or "experiment_scope" in values:
        return None, "policy schema version is missing"
    if scoring_policy is not None:
        values["scoring_policy"] = scoring_policy
    missing = [key for key in COMPARABILITY_FIELDS if key not in values]
    if missing:
        return None, "configuration metadata missing: " + ", ".join(missing)
    if not isinstance(values["blind"], bool):
        return None, "blind must be an explicit boolean"
    if values["max_cost_usd"] is not None and (
        isinstance(values["max_cost_usd"], bool)
        or not isinstance(values["max_cost_usd"], (int, float))
        or values["max_cost_usd"] < 0
    ):
        return None, "max_cost_usd is invalid"
    if values["max_tool_calls"] is not None and (
        isinstance(values["max_tool_calls"], bool)
        or not isinstance(values["max_tool_calls"], int)
        or values["max_tool_calls"] < 0
    ):
        return None, "max_tool_calls is invalid"
    if not isinstance(values["effective_phases"], (list, tuple)):
        return None, "effective_phases is invalid"
    if not values["effective_phases"] or any(
        isinstance(phase, bool) or not isinstance(phase, int) or phase < 1
        for phase in values["effective_phases"]
    ):
        return None, "effective_phases is invalid"
    if not isinstance(values["phase_models"], Mapping):
        return None, "phase_models is invalid"
    if any(
        not str(phase).strip() or not isinstance(model, str) or not model.strip()
        for phase, model in values["phase_models"].items()
    ):
        return None, "phase_models is invalid"
    if not isinstance(values["execution_profile_config"], Mapping) or not values["execution_profile_config"]:
        return None, "execution_profile_config is invalid"
    for key in (
        "provider", "model", "execution_profile", "execution_profile_policy",
        "prompt_manifest_sha256", "tool_manifest_sha256", "scoring_policy",
        "metric_contract_version", "evidence_contract_version",
    ):
        if key in {"provider", "model"} and policy_fields and values["decision_policy"] == "rules":
            continue
        if not isinstance(values[key], str) or not values[key].strip():
            return None, f"{key} is missing or empty"
    if values["metric_contract_version"] != METRIC_CONTRACT_VERSION:
        return None, "metric contract is legacy or incompatible"
    if values["evidence_contract_version"] != EVIDENCE_CONTRACT_VERSION:
        return None, "evidence contract is legacy or incompatible"
    try:
        identity = {key: _canonical(values[key]) for key in (*COMPARABILITY_FIELDS, *policy_fields)}
        # Preserve historical identities, but never merge changed instrumentation
        # into the old model-turn-based accounting population.
        for key in ("execution_ledger_version", "max_duration_s"):
            if key in values:
                identity[key] = _canonical(values[key])
    except (TypeError, ValueError) as exc:
        return None, f"configuration metadata is invalid: {exc}"
    return identity, None


def identity_key(identity: Mapping[str, Any] | None) -> str | None:
    if not isinstance(identity, Mapping):
        return None
    try:
        return json.dumps(_canonical(identity), sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError):
        return None


__all__ = ["COMPARABILITY_FIELDS", "configuration_identity", "identity_key"]
