"""Batch runner — runs multiple benchmark scenarios sequentially and aggregates metrics."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from src.benchmark.scenario_exports import default_export_store, resolve_ground_truth_path

ROOT = Path(__file__).resolve().parents[2]
GT_DIR = ROOT / "benchmarks" / "ground_truth"
OUTPUT_DIR = ROOT / "output" / "agent"


class SealedScenarioError(ValueError):
    """Raised when a local runner is asked to execute a sealed scenario."""


def _available_scenarios() -> list[str]:
    """Return deployable public scenarios, including legacy hardened variants."""
    from src.benchmark.catalog import list_scenarios

    ids = [item.id for item in list_scenarios() if not item.sealed]
    variants = [
        path.stem.removeprefix("scenario_")
        for path in GT_DIR.glob("scenario_*.yaml")
        if not path.stem.removeprefix("scenario_").isdigit()
    ]
    variants.extend(item["id"] for item in default_export_store().list())

    def sort_key(value: str) -> tuple[int, str]:
        number = "".join(ch for ch in value if ch.isdigit())
        suffix = value[len(number):]
        return (int(number), suffix) if number else (10**9, value)

    return sorted(set(ids + variants), key=sort_key)


def _public_scenario_split(scenario_id: int | str) -> str:
    """Return the trusted split for one locally deployable scenario.

    Historical variants and Scenario Lab exports remain development material;
    numeric catalogue scenarios retain their explicit dev/test-public split.
    """
    normalized = str(scenario_id).strip().removeprefix("S").removeprefix("s")
    if normalized.isdigit():
        from src.benchmark.catalog import load_catalog

        descriptor = load_catalog().get(normalized)
        if descriptor.sealed:
            raise SealedScenarioError(
                f"S{normalized} must run through the external sealed controller"
            )
        return descriptor.split
    return "dev-public"


def _parse_scenario_ids(batch_arg: str) -> list[str]:
    """Parse --batch argument into a list of scenario ID strings.

    Examples:
        "1,2,3"  -> ["1", "2", "3"]
        "1,2h,4" -> ["1", "2h", "4"]
        "all"    -> all available scenario IDs sorted by filename
    """
    selector = batch_arg.strip().lower()
    if selector == "all":
        return _available_scenarios()
    from src.benchmark.catalog import CatalogError, load_catalog

    if selector not in {
        "dev", "dev-public", "test", "test-public", "public",
        "eval", "eval-sealed",
    }:
        resolved: list[str] = []
        for raw in selector.split(","):
            sid = raw.strip().removeprefix("s")
            if not sid:
                continue
            if sid.isdigit():
                try:
                    descriptor = load_catalog().get(sid)
                except CatalogError as exc:
                    raise ValueError(str(exc)) from exc
                if descriptor.sealed:
                    raise SealedScenarioError(
                        f"S{sid} must run through the external sealed controller"
                    )
                resolved.append(descriptor.id)
            elif default_export_store().exists(sid) or (GT_DIR / f"scenario_{sid}.yaml").exists():
                resolved.append(sid)
            else:
                raise ValueError(f"Unknown public scenario variant: S{sid}")
        if not resolved:
            raise ValueError(f"No valid scenario IDs found in --batch '{batch_arg}'")
        return list(dict.fromkeys(resolved))

    try:
        selected = load_catalog().resolve_selector(selector)
    except CatalogError as exc:
        raise ValueError(str(exc)) from exc
    sealed = [item.id for item in selected if item.sealed]
    if sealed:
        raise SealedScenarioError(
            "Sealed scenarios must run through the external controller: "
            + ", ".join(f"S{sid}" for sid in sealed)
        )
    return [item.id for item in selected]


def _parse_single_scenario_id(value: int | str) -> str:
    """Resolve one deployable public scenario, including hardened variants."""
    scenario_ids = _parse_scenario_ids(str(value))
    if len(scenario_ids) != 1:
        raise ValueError(
            f"Expected exactly one public scenario, got {len(scenario_ids)} from {value!r}"
        )
    return scenario_ids[0]


def _load_scenario_footholds(scenario_id: int | str) -> list[dict] | None:
    """Return the optional explicit footholds declared by a public scenario.

    A scenario YAML may declare ``initial_credentials:`` — benchmark-provided
    Phase 5 footholds, injected as explicit entry credentials rather than
    findings. Absent key (the common case) means no footholds.
    """
    import yaml

    path = ROOT / "benchmarks" / "scenarios" / f"S{scenario_id}.yaml"
    if not path.exists():
        return None
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError:
        return None
    credentials = data.get("initial_credentials")
    if credentials is None:
        return None
    if not isinstance(credentials, list) or not all(
        isinstance(item, dict) for item in credentials
    ):
        raise ValueError(
            f"S{scenario_id}: initial_credentials must be a list of objects"
        )
    return credentials


def _evaluation_metrics(evaluation: Any) -> dict[str, Any]:
    """Return stable per-run metrics with the strict-v3 scenario score as primary."""
    specificity = evaluation.specificity

    def rounded(value: Any, digits: int) -> float | None:
        return round(float(value), digits) if value is not None else None

    return {
        "recall": round(evaluation.recall, 3),
        "precision": round(evaluation.precision, 3),
        "f1": round(evaluation.f1_score, 3),
        "detection_f1": round(getattr(evaluation, "detection_f1", evaluation.f1_score), 3),
        "credited_f1": round(getattr(evaluation, "credited_f1", evaluation.f1_score), 3),
        "severity_adjusted_f1": round(getattr(evaluation, "severity_adjusted_f1", evaluation.f1_score), 3),
        "quality_adjusted_f1": rounded(getattr(evaluation, "quality_adjusted_f1", None), 3),
        "verified_f1": getattr(evaluation, "verified_f1", None),
        "verified_weighted_score": getattr(evaluation, "verified_weighted_score", None),
        "verified_severity_coverage": getattr(
            evaluation, "verified_severity_coverage", None
        ),
        "raw_precision": round(getattr(evaluation, "raw_precision", evaluation.precision), 3),
        "raw_false_positives": getattr(evaluation, "raw_false_positives", evaluation.false_positives),
        "hallucination_rate": getattr(evaluation, "hallucination_rate", 0.0),
        "unmatched_finding_rate": getattr(evaluation, "unmatched_finding_rate", 0.0),
        "bonus_finding_rate": getattr(evaluation, "bonus_finding_rate", 0.0),
        "bonus_allowance": getattr(evaluation, "bonus_allowance", 0),
        "bonus_overflow": getattr(evaluation, "bonus_overflow", 0),
        "bonus_untraceable": getattr(evaluation, "bonus_untraceable", 0),
        "bonus_cap_exceeded": getattr(evaluation, "bonus_cap_exceeded", 0),
        "bonus_duplicates": getattr(evaluation, "bonus_duplicates", 0),
        "weighted_score": round(evaluation.weighted_score, 3),
        "max_weighted_score": evaluation.max_weighted_score,
        # strict-v3 uses Verified F1 for positive scenarios; zero-GT controls
        # retain a separate binary clean-run score.
        # Keep the weighted percentage under an explicit compatibility name.
        "score_pct": rounded(evaluation.scenario_score_pct, 1),
        "weighted_score_pct": round(evaluation.score_pct, 1),
        "scenario_score_pct": rounded(evaluation.scenario_score_pct, 1),
        "tp": evaluation.true_positives,
        "fp": evaluation.false_positives,
        "fn": evaluation.false_negatives,
        "exploitation_coverage": rounded(evaluation.exploitation_coverage, 3),
        "phase4_candidates": getattr(evaluation, "phase4_candidates", 0),
        "phase4_conclusive": getattr(evaluation, "phase4_conclusive", 0),
        "phase4_completion_rate": getattr(evaluation, "phase4_completion_rate", None),
        "invalid_cve_claims": getattr(evaluation, "invalid_cve_claims", 0),
        "malformed_cve_claims": getattr(evaluation, "malformed_cve_claims", 0),
        "unknown_cve_claims": getattr(evaluation, "unknown_cve_claims", 0),
        "inapplicable_cve_claims": getattr(evaluation, "inapplicable_cve_claims", 0),
        "negative_controls_declared": getattr(evaluation, "negative_controls_declared", 0),
        "negative_controls_total": getattr(evaluation, "negative_controls_total", 0),
        "negative_controls_unevaluable": getattr(evaluation, "negative_controls_unevaluable", 0),
        "negative_controls_unevaluable_list": getattr(evaluation, "negative_controls_unevaluable_list", []),
        "negative_control_penalty_factor": getattr(evaluation, "negative_control_penalty_factor", 1.0),
        "negative_control_violations": getattr(evaluation, "negative_control_violations", 0),
        "negative_control_specificity": getattr(evaluation, "negative_control_specificity", None),
        "negative_control_clean_run": getattr(evaluation, "negative_control_clean_run", None),
        "evidence_metrics_available": getattr(evaluation, "evidence_metrics_available", False),
        "metric_contract_version": getattr(evaluation, "metric_contract_version", None),
        "run_metric_contract_version": getattr(evaluation, "run_metric_contract_version", None),
        "run_evidence_contract_version": getattr(evaluation, "run_evidence_contract_version", None),
        "evidence_contract_compatible": getattr(evaluation, "evidence_contract_compatible", False),
        "metrics_compatibility_reason": getattr(evaluation, "metrics_compatibility_reason", None),
        "evidence_provenance_available": getattr(evaluation, "evidence_provenance_available", False),
        "findings_with_declared_evidence": getattr(evaluation, "findings_with_declared_evidence", 0),
        "declared_evidence_coverage": getattr(evaluation, "declared_evidence_coverage", None),
        "findings_with_execution_evidence": getattr(evaluation, "findings_with_execution_evidence", 0),
        "execution_evidence_coverage": getattr(evaluation, "execution_evidence_coverage", None),
        "findings_with_traceable_evidence": getattr(evaluation, "findings_with_traceable_evidence", 0),
        "traceable_evidence_coverage": getattr(evaluation, "traceable_evidence_coverage", None),
        "traceable_true_positives": getattr(evaluation, "traceable_true_positives", 0),
        "traceable_false_positives": getattr(evaluation, "traceable_false_positives", 0),
        "evidence_precision": getattr(evaluation, "evidence_precision", None),
        "evidence_recall": getattr(evaluation, "evidence_recall", None),
        "evidence_f1": getattr(evaluation, "evidence_f1", None),
        "evidence_claims_total": getattr(evaluation, "evidence_claims_total", 0),
        "evidence_claims_supported": getattr(evaluation, "evidence_claims_supported", 0),
        "evidence_claims_contradicted": getattr(evaluation, "evidence_claims_contradicted", 0),
        "evidence_claims_unverifiable": getattr(evaluation, "evidence_claims_unverifiable", 0),
        "evidence_faithfulness": getattr(evaluation, "evidence_faithfulness", None),
        "evidence_macro_faithfulness": getattr(evaluation, "evidence_macro_faithfulness", None),
        "evidence_faithfulness_by_kind": getattr(evaluation, "evidence_faithfulness_by_kind", {}),
        "ambiguous_evidence_refs": getattr(evaluation, "ambiguous_evidence_refs", 0),
        "evidence_contradiction_rate": getattr(evaluation, "evidence_contradiction_rate", None),
        "path_coverage": round(getattr(evaluation, "path_coverage", 0.0), 3),
        "quality_path_coverage": rounded(getattr(evaluation, "quality_path_coverage", None), 3),
        "quality_attack_path_credit": round(getattr(evaluation, "quality_attack_path_credit", 0.0), 3),
        "verified_path_coverage": getattr(evaluation, "verified_path_coverage", None),
        "verified_attack_paths": getattr(evaluation, "verified_attack_paths", 0),
        "intrusion_paths_available": getattr(evaluation, "intrusion_paths_available", False),
        "attack_paths_detected": getattr(evaluation, "attack_paths_detected", 0),
        "total_attack_paths": getattr(evaluation, "total_attack_paths", 0),
        "mhr_1": getattr(evaluation, "mhr_1", None),
        "mhr_2": getattr(evaluation, "mhr_2", None),
        "mhr_3": getattr(evaluation, "mhr_3", None),
        "mhr_1_credited": getattr(evaluation, "mhr_1_credited", None),
        "mhr_2_credited": getattr(evaluation, "mhr_2_credited", None),
        "mhr_3_credited": getattr(evaluation, "mhr_3_credited", None),
        "mhr_1_verified": getattr(evaluation, "mhr_1_verified", None),
        "mhr_2_verified": getattr(evaluation, "mhr_2_verified", None),
        "mhr_3_verified": getattr(evaluation, "mhr_3_verified", None),
        "dhr_1": getattr(evaluation, "dhr_1", None),
        "dhr_2": getattr(evaluation, "dhr_2", None),
        "dhr_3": getattr(evaluation, "dhr_3", None),
        "dhr_1_verified": getattr(evaluation, "dhr_1_verified", None),
        "dhr_2_verified": getattr(evaluation, "dhr_2_verified", None),
        "dhr_3_verified": getattr(evaluation, "dhr_3_verified", None),
        "gt_at_depth": getattr(evaluation, "gt_at_depth", {}),
        "tp_at_depth": getattr(evaluation, "tp_at_depth", {}),
        "gt_at_dependency_depth": getattr(
            evaluation, "gt_at_dependency_depth", {}
        ),
        "tp_at_dependency_depth": getattr(
            evaluation, "tp_at_dependency_depth", {}
        ),
        "specificity": round(specificity, 3) if specificity is not None else None,
        "is_zero_gt": evaluation.is_zero_gt,
        "scoring_policy": evaluation.scoring_policy,
        "process_metrics_schema_version": getattr(evaluation, "process_metrics_schema_version", None),
        "process_metrics_available": getattr(evaluation, "process_metrics_available", False),
        "total_cost_usd": getattr(evaluation, "total_cost_usd", None),
        "cost_is_estimate": getattr(evaluation, "cost_is_estimate", None),
        "total_tokens": getattr(evaluation, "total_tokens", None),
        "total_turns": getattr(evaluation, "total_turns", None),
        "total_tool_calls": getattr(evaluation, "total_tool_calls", None),
        "cost_per_tp": getattr(evaluation, "cost_per_tp", None),
        "zero_tp": getattr(evaluation, "zero_tp", evaluation.true_positives == 0),
        "cost_per_expected_vulnerability": getattr(evaluation, "cost_per_expected_vulnerability", None),
        "turns_per_tp": getattr(evaluation, "turns_per_tp", None),
        "format_fallbacks": getattr(evaluation, "format_fallbacks", None),
        "format_attempts": getattr(evaluation, "format_attempts", None),
        "format_fallback_rate": getattr(evaluation, "format_fallback_rate", None),
        "validation_failures": getattr(evaluation, "validation_failures", None),
        "validation_attempts": getattr(evaluation, "validation_attempts", None),
        "validation_successes": getattr(evaluation, "validation_successes", None),
        "validation_success_rate": getattr(evaluation, "validation_success_rate", None),
        "total_tool_errors": getattr(evaluation, "total_tool_errors", None),
        "tool_error_rate": getattr(evaluation, "tool_error_rate", None),
    }


def _aggregate_batch_results(
    evaluations: Iterable[Any],
    results: list[dict[str, Any]],
    scenario_ids: Iterable[str],
) -> dict[str, Any]:
    """Build one aggregate schema for the CLI and dashboard batch runners."""
    expected = list(dict.fromkeys(str(sid) for sid in scenario_ids))
    if not expected:
        return {}

    from src.benchmark.aggregate import aggregate_evaluations

    completed = [result for result in results if result.get("metrics")]
    official = aggregate_evaluations(
        evaluations,
        expected_scenarios=expected,
        scenario_splits={sid: _public_scenario_split(sid) for sid in expected},
    )
    process = [result["metrics"] for result in completed if result["metrics"].get("process_metrics_available")]

    def _process_total(name: str) -> int:
        return sum(int(metrics.get(name) or 0) for metrics in process)

    format_attempts = _process_total("format_attempts")
    format_fallbacks = _process_total("format_fallbacks")
    validation_attempts = _process_total("validation_attempts")
    validation_successes = _process_total("validation_successes")
    tool_calls = _process_total("total_tool_calls")
    tool_errors = _process_total("total_tool_errors")
    return {
        **official,
        # Backward-compatible aliases now point to the scenario-macro metrics,
        # so scenarios with more repetitions no longer receive more weight.
        "avg_recall": official["macro_positive_recall"],
        "avg_precision": official["macro_positive_precision"],
        "avg_f1": official["macro_positive_f1"],
        "avg_score_pct": official["macro_scenario_score_pct"],
        "total_cost_usd": sum(float(metrics["total_cost_usd"]) for metrics in (result["metrics"] for result in completed) if metrics.get("total_cost_usd") is not None),
        "process_metrics_runs": len(process),
        "format_fallbacks": format_fallbacks,
        "format_attempts": format_attempts,
        "format_fallback_rate": round(format_fallbacks / format_attempts, 3) if format_attempts else None,
        "validation_successes": validation_successes,
        "validation_attempts": validation_attempts,
        "validation_success_rate": round(validation_successes / validation_attempts, 3) if validation_attempts else None,
        "total_tool_errors": tool_errors,
        "total_tool_calls": tool_calls,
        "tool_error_rate": round(tool_errors / tool_calls, 3) if tool_calls else None,
        "scenarios_evaluated": len(completed),
        "scenarios_skipped": len(expected) - len(completed),
    }


def run_batch(
    batch_arg: str,
    provider,
    dry_run: bool = False,
    phases: list[int] | None = None,
    blind: bool = False,
    execution_profile: str = "auto",
    manage_scenario: bool = True,
    auto_teardown: bool = True,
) -> Path:
    """Run scenarios sequentially and save batch_summary.json.

    Returns the path to the batch summary JSON file.
    """
    from src.agent.pipeline import Pipeline
    from src.agent.execution_profiles import resolve_execution_profile_for_model
    from src.benchmark.evaluator import evaluate

    scenario_ids = _parse_scenario_ids(batch_arg)
    profile_resolution = resolve_execution_profile_for_model(
        execution_profile, getattr(provider, "model", None)
    )
    if not scenario_ids:
        raise ValueError(f"No valid scenario IDs found in --batch '{batch_arg}'")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    batch_dir = OUTPUT_DIR / f"batch_{timestamp}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"BATCH RUN — {len(scenario_ids)} scenario(s): {', '.join(f'S{s}' for s in scenario_ids)}")
    print(f"Model : {getattr(provider, 'model', 'unknown')}")
    print(f"Mode  : {'blind' if blind else 'informed'}")
    print(
        f"Profile: {profile_resolution.profile.name} "
        f"({profile_resolution.resolution_basis})"
    )
    print(f"Output: {batch_dir}")
    print(f"{'=' * 60}\n")

    results: list[dict] = []
    evaluation_results = []

    for idx, sid in enumerate(scenario_ids, 1):
        scenario_id: int | str = int(sid) if sid.isdigit() else sid
        scenario_split = _public_scenario_split(sid)
        gt_file = resolve_ground_truth_path(sid)

        if not gt_file.exists():
            print(f"[{idx}/{len(scenario_ids)}] S{sid} — SKIPPED (ground truth not found: {gt_file})")
            results.append({
                "scenario_id": sid,
                "status": "skipped",
                "reason": "no ground truth file",
            })
            continue

        print(f"[{idx}/{len(scenario_ids)}] Running S{sid}...")

        pipeline = None
        try:
            pipeline = Pipeline(
                provider=provider,
                dry_run=dry_run,
                phases=phases,
                scenario_id=scenario_id,
                auto_teardown=auto_teardown,
                blind=blind,
                manage_scenario=manage_scenario,
                benchmark_split=scenario_split,
                execution_profile=execution_profile,
                initial_credentials=_load_scenario_footholds(sid),
            )
            run_results = pipeline.run()
            run_status = getattr(pipeline, "run_status", None)
            if isinstance(run_status, str) and run_status != "completed":
                raise RuntimeError(
                    f"pipeline finished with status {run_status}: {run_results}"
                )
        except Exception as exc:
            failed_run_dir = getattr(pipeline, "run_dir", None)
            tracker = getattr(pipeline, "tracker", None)
            cost = round(tracker.total_cost(), 4) if tracker is not None else 0.0
            entry = {
                "scenario_id": sid,
                "mode": "blind" if blind else "informed",
                "run_dir": str(failed_run_dir) if failed_run_dir else None,
                "cost_usd": cost,
                "status": "failed",
                "reason": str(exc),
            }
            print(f"  [!] Pipeline failed: {exc}")
            results.append(entry)
            _print_scenario_summary(sid, entry)
            continue

        run_dir = pipeline.run_dir
        cost = round(pipeline.tracker.total_cost(), 4)

        entry: dict = {
            "scenario_id": sid,
            "mode": "blind" if blind else "informed",
            "run_dir": str(run_dir),
            "pipeline_results": run_results,
            "cost_usd": cost,
            "status": "ok",
        }

        try:
            ev = evaluate(run_dir, gt_file, policy="strict-v3")
            ev.split = scenario_split
            evaluation_results.append(ev)
            entry["metrics"] = _evaluation_metrics(ev)
        except Exception as exc:
            print(f"  [!] Evaluation failed: {exc}")
            entry["status"] = "evaluation_failed"
            entry["reason"] = str(exc)

        results.append(entry)
        _print_scenario_summary(sid, entry)

    aggregate = _aggregate_batch_results(evaluation_results, results, scenario_ids)

    summary = {
        "batch_timestamp": timestamp,
        "model": getattr(provider, "model", None),
        "mode": "blind" if blind else "informed",
        "blind": bool(blind),
        "manage_scenario": bool(manage_scenario),
        "auto_teardown": bool(auto_teardown),
        **profile_resolution.metadata(),
        "scenarios": results,
        "aggregate": aggregate,
    }

    summary_path = batch_dir / "batch_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

    _print_batch_table(results, aggregate, summary_path)
    return summary_path


def _print_scenario_summary(sid: str, entry: dict) -> None:
    m = entry.get("metrics")
    cost = entry.get("cost_usd", 0)
    if m:
        score = f"{m['score_pct']:.1f}%" if m.get("score_pct") is not None else "N/A"
        print(
            f"  S{sid}: Recall={m['recall']:.3f}  Precision={m['precision']:.3f}  "
            f"F1={m['f1']:.3f}  Score={score}  "
            f"TP={m['tp']}  FP={m['fp']}  FN={m['fn']}  Cost=${cost:.4f}"
        )
    elif entry.get("status") == "failed":
        print(f"  S{sid}: pipeline failed ({entry.get('reason', 'unknown error')}). Cost=${cost:.4f}")
    elif entry.get("status") == "evaluation_failed":
        print(f"  S{sid}: evaluation failed ({entry.get('reason', 'unknown error')}). Cost=${cost:.4f}")
    else:
        print(f"  S{sid}: pipeline done, evaluation unavailable. Cost=${cost:.4f}")


def _print_batch_table(results: list[dict], aggregate: dict, summary_path: Path) -> None:
    col = {"s": 10, "r": 8, "p": 10, "f1": 7, "sc": 8, "tp": 5, "fp": 5, "fn": 5, "cost": 10}

    def fmt(value: Any, width: int, digits: int = 3) -> str:
        if value is None:
            return f"{'N/A':>{width}}"
        return f"{float(value):>{width}.{digits}f}"

    header = (
        f"  {'Scenario':<{col['s']}} {'Recall':>{col['r']}} {'Precision':>{col['p']}} "
        f"{'F1':>{col['f1']}} {'Score%':>{col['sc']}} "
        f"{'TP':>{col['tp']}} {'FP':>{col['fp']}} {'FN':>{col['fn']}} {'Cost':>{col['cost']}}"
    )
    sep = "  " + "-" * (len(header) - 2)

    print(f"\n{'=' * 60}")
    print("BATCH COMPLETE")
    print(f"{'=' * 60}")
    print(header)
    print(sep)

    for r in results:
        sid = r["scenario_id"]
        if r.get("status") != "ok" or "metrics" not in r:
            label = str(r.get("status", "skipped")).replace("_", " ").upper()
            print(f"  S{sid:<{col['s'] - 1}} {label:>{col['r']}}")
            continue
        m = r["metrics"]
        print(
            f"  S{sid:<{col['s'] - 1}} {fmt(m['recall'], col['r'])} {fmt(m['precision'], col['p'])} "
            f"{fmt(m['f1'], col['f1'])} {fmt(m['score_pct'], col['sc'], 1)} "
            f"{m['tp']:>{col['tp']}} {m['fp']:>{col['fp']}} {m['fn']:>{col['fn']}} "
            f"${r['cost_usd']:>{col['cost'] - 1}.4f}"
        )

    if aggregate:
        print(sep)
        print(
            f"  {'AVERAGE':<{col['s'] - 1}} {fmt(aggregate['avg_recall'], col['r'])} "
            f"{fmt(aggregate['avg_precision'], col['p'])} {fmt(aggregate['avg_f1'], col['f1'])} "
            f"{fmt(aggregate['avg_score_pct'], col['sc'], 1)}"
            f"{'':>{col['tp'] + col['fp'] + col['fn'] + 3}} "
            f"${aggregate['total_cost_usd']:>{col['cost'] - 1}.4f}"
        )

    print(f"\nSummary: {summary_path}")
