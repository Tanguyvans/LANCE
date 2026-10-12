"""Offline summarizer for archived S1-S12 campaign runs.

Reads already-collected JSON lifecycle/score/manifest evidence from a local
archive directory and emits a single JSON summary with explicit provenance.

Strictly offline post-processing: no network, no model calls, no scenario
launches, no score recalculation. Inputs are opened read-only; the summary
is never written inside the archive.

Run identifiers name immediate child directories of the archive root only.
Nothing is ever selected implicitly (no newest-by-mtime scan).

``lifecycle_complete_recorded`` is True only when the RECORDED metadata
reads top-level ``completed``, six ``completed`` phases, ``completed``
cleanup, no recorded lifecycle/usage errors and no explicit failure in
the recorded phase-3 diagnostics. It verifies metadata consistency, not
whether the recorded values are true and not vulnerability semantics.

``score-unavailable-response.json`` is accepted in both documented
archived forms: ``http_status`` with a dict ``body``, and ``status_code``
with a JSON-encoded string ``body``. A remotely unavailable score stays
``None`` (never zero); differing ``http_status``/``status_code`` values
are flagged and both preserved.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path

TOOL_NAME = "summarize_archived_campaign"
TOOL_VERSION = "1.1.2"

#: The six requested audit phases, in pipeline order.
PHASES = (
    "graph_analysis",
    "recon",
    "vuln_analysis",
    "exploitation",
    "intrusion",
    "report",
)

#: Per-run evidence files read verbatim (all optional).
RUN_FILES = (
    "run_meta.json",
    "scenario_meta.json",
    "score.json",
    "run_error.json",
    "score-unavailable-response.json",
    "metric-audit.json",
    "03_phase3_status.json",
    "04_exploitation.json",
    "cost_summary.json",
)

_RUN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

DEFAULT_SCENARIOS = tuple(str(n) for n in range(1, 13))


class SummaryError(Exception):
    """Fatal CLI misuse (unsafe path, missing input selection, ...)."""


def normalize_scenario(value):
    """Canonical scenario label (``"3"``) or ``None`` when absent."""
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(int(text, 10))
    except ValueError:
        return text


def parse_scenarios(spec):
    """Parse ``"1-12"``, ``"1,2,3"`` or a list into a sorted scenario list."""
    if spec is None:
        return list(DEFAULT_SCENARIOS)
    parts = spec if isinstance(spec, (list, tuple)) else str(spec).split(",")
    out = []
    for part in parts:
        token = str(part).strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            try:
                lo, hi = int(start.strip()), int(end.strip())
            except ValueError:
                raise SummaryError(f"invalid scenario range: {token!r}")
            if lo > hi:
                raise SummaryError(f"invalid scenario range: {token!r}")
            out.extend(str(n) for n in range(lo, hi + 1))
        else:
            label = normalize_scenario(token)
            if label is None:
                raise SummaryError(f"invalid scenario: {token!r}")
            out.append(label)
    seen = sorted(set(out), key=lambda s: (int(s) if s.isdigit() else 10**9, s))
    if not seen:
        raise SummaryError("empty scenario filter")
    return seen


def validate_run_id(run_id):
    """Accept only immediate child directory names (no traversal)."""
    if not isinstance(run_id, str) or not _RUN_ID_RE.match(run_id):
        raise SummaryError(
            f"unsafe run identifier {run_id!r}: must be an immediate child "
            "directory name (letters, digits, '.', '_' and '-', no '/')"
        )
    if run_id in (".", ".."):
        raise SummaryError(f"unsafe run identifier {run_id!r}")
    return run_id


def _is_within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def resolve_evidence_file(run_dir, root, name):
    """Resolve one evidence file without following escapes outside root.

    Returns ``(path_or_None, warning_or_None)``. A symlink (file or parent)
    resolving outside the archive root is never followed.
    """
    candidate = run_dir / name
    try:
        if candidate.is_symlink():
            target = candidate.resolve()
            if not _is_within(target, root):
                return None, (
                    f"{name}: symlink points outside archive root; not followed"
                )
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        return None, f"{name}: cannot resolve path ({exc})"
    if not _is_within(resolved, root):
        return None, f"{name}: resolves outside archive root; not followed"
    if not resolved.is_file():
        return None, None
    return resolved, None


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_evidence(path):
    """Read a JSON file read-only. Returns ``(data, sha256_or_None, error)``.

    Hashing happens inside the guarded section: an unreadable input yields a
    warning at the call site, never an exception here.
    """
    try:
        sha = sha256_file(path)
    except OSError as exc:
        return None, None, f"unreadable ({exc})"
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle), sha, None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, sha, f"malformed JSON ({exc})"
    except OSError as exc:
        return None, sha, f"unreadable ({exc})"


def phase_completed(value):
    """A phase counts as complete only when recorded ``completed*``."""
    return isinstance(value, str) and (
        value == "completed" or value.startswith("completed:")
    )


def phase3_failure_signals(phase3):
    """Explicit failure signals in recorded phase-3 diagnostics.

    Returns a list of human-readable blockers (empty when the recorded
    phase-3 diagnostics show no failure). A non-dict or absent phase-3
    record yields no signals: absence of evidence is not evidence here.
    """
    blockers = []
    if not isinstance(phase3, dict):
        return blockers
    status = phase3.get("status")
    if isinstance(status, str) and ("fail" in status.lower()
                                   or "error" in status.lower()):
        blockers.append(f"phase3 status {status!r} records failure")
    failed = phase3.get("devices_failed")
    if isinstance(failed, list) and failed:
        blockers.append(f"phase3 devices_failed lists {len(failed)} device(s)")
    scanner_errors = phase3.get("scanner_errors")
    if isinstance(scanner_errors, list) and scanner_errors:
        blockers.append(
            f"phase3 scanner_errors lists {len(scanner_errors)} error(s)")
    return blockers


def coerce_http_status(value):
    """An explicitly recorded HTTP status, or ``None`` when not recorded.

    Accepts ints and digit strings; anything else (including bools and
    absent values) yields ``None``. Never guesses: no default is invented.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            try:
                return int(text)
            except ValueError:
                return None
    return None


def unavailable_detail(body):
    """The recorded ``detail`` of a score-unavailable body, or ``None``.

    Supports both documented archived forms: a dict body carrying
    ``detail``, and a JSON-encoded string body that decodes to such a
    dict. A malformed or non-object optional body yields ``None`` without
    raising; absence of a parseable body is not evidence of a status.
    """
    if isinstance(body, dict):
        detail = body.get("detail")
        return detail if isinstance(detail, str) and detail else None
    if isinstance(body, str):
        text = body.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return None
        if isinstance(parsed, dict):
            detail = parsed.get("detail")
            return detail if isinstance(detail, str) and detail else None
    return None


def parse_score_unavailable(unavailable):
    """Normalize a ``score-unavailable-response.json`` payload.

    Returns ``{"http_status", "status_code", "detail", "conflict"}`` where
    ``http_status`` is the resolved status (``http_status`` preferred, else
    ``status_code``), ``status_code`` the explicitly recorded ``status_code``
    value, ``detail`` the decoded body detail (possibly ``None``) and
    ``conflict`` True when both keys are recorded and differ. Both supplied
    values are preserved so callers can report ambiguity instead of
    resolving it silently.
    """
    raw_status = unavailable.get("http_status")
    raw_code = unavailable.get("status_code")
    http_status = coerce_http_status(raw_status)
    status_code = coerce_http_status(raw_code)
    resolved = http_status if http_status is not None else status_code
    conflict = (
        http_status is not None
        and status_code is not None
        and http_status != status_code
    )
    return {
        "http_status": resolved,
        "status_code": status_code,
        "detail": unavailable_detail(unavailable.get("body")),
        "conflict": conflict,
    }


def summarize_run(root, run_id, requested, group="official"):
    """Summarize one archived run. Returns ``(entry, warnings, excluded)``."""
    validate_run_id(run_id)
    warnings = []
    run_dir = root / run_id
    try:
        run_resolved = run_dir.resolve()
    except (OSError, RuntimeError) as exc:
        raise SummaryError(f"run {run_id!r}: cannot resolve ({exc})")
    if run_dir.is_symlink() and not _is_within(run_resolved, root):
        raise SummaryError(
            f"run {run_id!r}: symlink points outside archive root; refused"
        )
    if not run_dir.is_dir():
        raise SummaryError(f"run {run_id!r}: not a directory of the archive")

    files = {}
    data = {}
    for name in RUN_FILES:
        path, symlink_warning = resolve_evidence_file(run_dir, root, name)
        if symlink_warning:
            warnings.append({"run_id": run_id, "code": "symlink_outside_root",
                             "message": symlink_warning})
            files[name] = {"present": False, "sha256": None,
                           "note": "symlink_outside_root"}
            data[name] = None
            continue
        if path is None:
            files[name] = {"present": False, "sha256": None}
            data[name] = None
            continue
        payload, sha, error = read_evidence(path)
        record = {"present": True, "sha256": sha, "path": str(path)}
        if error is not None:
            if error.startswith("unreadable"):
                record["unreadable"] = True
                warnings.append({"run_id": run_id, "code": "unreadable_file",
                                 "message": f"{name}: {error}"})
            else:
                record["malformed"] = True
                warnings.append({"run_id": run_id, "code": "malformed_file",
                                 "message": f"{name}: {error}"})
            data[name] = None
        else:
            data[name] = payload
        files[name] = record

    run_meta = data["run_meta.json"] if isinstance(
        data["run_meta.json"], dict) else None
    scenario_meta = data["scenario_meta.json"] if isinstance(
        data["scenario_meta.json"], dict) else None
    score = data["score.json"] if isinstance(data["score.json"], dict) else None
    if data["run_meta.json"] is not None and run_meta is None:
        warnings.append({"run_id": run_id, "code": "malformed_file",
                         "message": "run_meta.json: expected a JSON object"})
    if data["scenario_meta.json"] is not None and scenario_meta is None:
        warnings.append({"run_id": run_id, "code": "malformed_file",
                         "message": "scenario_meta.json: expected a JSON object"})
    if data["score.json"] is not None and score is None:
        warnings.append({"run_id": run_id, "code": "malformed_file",
                         "message": "score.json: expected a JSON object"})

    # Scenario: scenario_meta first, then score, then run_meta fallback.
    candidates = {}
    if scenario_meta is not None:
        candidates["scenario_meta"] = normalize_scenario(
            scenario_meta.get("scenario_id", scenario_meta.get("scenario")))
    if score is not None:
        candidates["score"] = normalize_scenario(score.get("scenario_id"))
    if run_meta is not None:
        candidates["run_meta"] = normalize_scenario(
            run_meta.get("scenario_id", run_meta.get("scenario")))
    scenario = (
        candidates.get("scenario_meta")
        or candidates.get("score")
        or candidates.get("run_meta")
    )
    distinct = {v for v in candidates.values() if v is not None}
    if len(distinct) > 1:
        warnings.append({
            "run_id": run_id, "code": "score_meta_scenario_mismatch",
            "message": "scenario disagreement: "
            + ", ".join(f"{k}={v}" for k, v in sorted(candidates.items())),
        })
    if scenario is None:
        warnings.append({"run_id": run_id, "code": "scenario_unknown",
                         "message": "no scenario in scenario_meta/score/run_meta"})

    if scenario is not None and scenario not in set(requested):
        return (
            {"run_id": run_id, "group": group, "scenario": scenario,
             "excluded": True,
             "exclusion_reason": "scenario_out_of_scope",
             "requested_scenarios": list(requested),
             "files": files},
            warnings,
            True,
        )

    # Lifecycle: reflect recorded values; never infer phases from status.
    status = run_meta.get("status") if run_meta else None
    cleanup = run_meta.get("cleanup_status") if run_meta else None
    results = run_meta.get("results") if run_meta else None
    if results is None:
        results = {}
    if not isinstance(results, dict):
        warnings.append({"run_id": run_id, "code": "malformed_file",
                         "message": "run_meta.results: expected an object"})
        results = {}
    phase_results = {phase: results.get(phase) for phase in PHASES}
    six_complete = all(phase_completed(v) for v in phase_results.values())
    # lifecycle_complete_recorded checks RECORDED metadata only: every phase
    # status reads completed, top-level status reads completed, cleanup reads
    # completed, no recorded lifecycle/usage errors, and no explicit failure
    # in the recorded phase-3 diagnostics. It says nothing about whether the
    # recorded values are true or whether the findings are semantically valid.
    blockers = []
    if cleanup != "completed":
        blockers.append(f"cleanup_status is {cleanup!r}, not 'completed'")
    for key in ("lifecycle_errors", "usage_errors"):
        errors = run_meta.get(key) if run_meta else None
        if errors:
            count = len(errors) if isinstance(errors, list) else "?"
            blockers.append(f"run_meta.{key} records {count} error(s)")
    blockers.extend(phase3_failure_signals(data["03_phase3_status.json"]))
    lifecycle_complete = (
        status == "completed" and six_complete and not blockers
    )
    if status == "completed" and not six_complete:
        warnings.append({
            "run_id": run_id, "code": "stale_completed_status",
            "message": "top-level status is 'completed' but at least one of "
            "the six recorded phases is not 'completed'; lifecycle completion "
            "is not recorded",
        })
    if status == "completed" and six_complete and not lifecycle_complete:
        warnings.append({
            "run_id": run_id, "code": "lifecycle_completion_refused",
            "message": "top-level status is 'completed' with six completed "
            "phases, but recorded lifecycle completion is refused: "
            + "; ".join(blockers),
        })
    if run_meta is None:
        warnings.append({"run_id": run_id, "code": "missing_run_meta",
                         "message": "run_meta.json absent or malformed; "
                         "lifecycle unknown"})

    # Score: copied verbatim, never recalculated; missing stays null.
    score_entry = None
    score_explanation = None
    if score is not None:
        funnel = score.get("funnel") if isinstance(
            score.get("funnel"), dict) else {}
        stages = funnel.get("stages") if isinstance(
            funnel.get("stages"), dict) else {}
        confirmed = stages.get("confirmed")
        if isinstance(confirmed, dict) and confirmed.get("available") is True:
            score_entry = copy.deepcopy(confirmed)
            score_explanation = None
        else:
            score_explanation = (
                score.get("score_unavailable_reason")
                or "score recorded without an available confirmed funnel; "
                "unavailable, not zero"
            )
    else:
        reasons = []
        unavailable = data["score-unavailable-response.json"]
        if isinstance(unavailable, dict):
            parsed = parse_score_unavailable(unavailable)
            if parsed["conflict"]:
                warnings.append({
                    "run_id": run_id,
                    "code": "score_unavailable_status_conflict",
                    "message": "score-unavailable-response records both "
                    f"http_status={unavailable.get('http_status')!r} and "
                    f"status_code={unavailable.get('status_code')!r}; "
                    "values differ, both preserved",
                })
            if parsed["http_status"] is not None and (
                    coerce_http_status(unavailable.get("http_status"))
                    is not None):
                status_label = (
                    f"http_status={parsed['http_status']}"
                    + (f" status_code={parsed['status_code']}"
                       if parsed["status_code"] is not None else "")
                )
            else:
                status_label = f"status_code={parsed['http_status']}"
            detail = parsed["detail"]
            reasons.append(
                "official score endpoint " + status_label
                + (f" detail={detail!r}" if detail else "")
            )
        run_error = data["run_error.json"]
        if isinstance(run_error, dict):
            reasons.append(
                f"run_error phase={run_error.get('phase')!r} "
                f"{run_error.get('exception_class') or run_error.get('exception_module') or ''}"
                f": {run_error.get('message')}".rstrip()
            )
        elif run_meta and isinstance(run_meta.get("run_error"), dict):
            embedded = run_meta["run_error"]
            reasons.append(
                f"run_meta.run_error phase={embedded.get('phase')!r}: "
                f"{embedded.get('message')}"
            )
        if status is not None and status != "completed":
            reasons.append(f"recorded run status {status!r}")
        if not files["score.json"]["present"]:
            reasons.append("score.json absent from archive")
        if files["score.json"].get("malformed"):
            reasons.append("score.json present but malformed")
        score_explanation = (
            "; ".join(r for r in reasons if r)
            or "score.json absent from archive; unavailable, not zero"
        )
    if score_entry is None:
        warnings.append({"run_id": run_id, "code": "score_unavailable",
                         "message": score_explanation or "score unavailable"})

    # Contracts and commit: preserved distinctly, disagreements flagged.
    commit = run_meta.get("git_commit") if run_meta else None
    meta_commit = scenario_meta.get("git_commit") if scenario_meta else None
    if commit and meta_commit and commit != meta_commit:
        warnings.append({
            "run_id": run_id, "code": "commit_mismatch",
            "message": f"run_meta git_commit={commit!r} but scenario_meta "
            f"git_commit={meta_commit!r}",
        })
    contracts = {
        "run_metric_contract": run_meta.get("metric_contract_version")
        if run_meta else None,
        "run_evidence_contract": run_meta.get("evidence_contract_version")
        if run_meta else None,
        "score_metric_contract": score.get("metric_contract_version")
        if score else None,
        "score_evidence_contract": score.get("evidence_contract_version")
        if score else None,
    }
    if (score and contracts["run_metric_contract"]
            and contracts["score_metric_contract"]
            and contracts["run_metric_contract"]
            != contracts["score_metric_contract"]):
        warnings.append({
            "run_id": run_id, "code": "contract_mismatch",
            "message": "run_meta and score.json metric contracts disagree",
        })

    # Diagnostics retained separately; never merged into the score.
    diagnostics = {}
    run_error = data["run_error.json"]
    if isinstance(run_error, dict):
        diagnostics["run_error"] = {
            "phase": run_error.get("phase"),
            "exception_class": run_error.get("exception_class"),
            "exception_module": run_error.get("exception_module"),
            "message": run_error.get("message"),
        }
    unavailable = data["score-unavailable-response.json"]
    if isinstance(unavailable, dict):
        parsed_unavailable = parse_score_unavailable(unavailable)
        diagnostics["score_unavailable_response"] = {
            "http_status": parsed_unavailable["http_status"],
            "status_code": parsed_unavailable["status_code"],
            "detail": parsed_unavailable["detail"],
            "reason": unavailable.get("reason"),
        }
    audit = data["metric-audit.json"]
    if isinstance(audit, dict):
        checks = audit.get("checks")
        diagnostics["metric_audit"] = {
            "check_count": len(checks) if isinstance(checks, list) else None,
            "review_required": audit.get("review_required"),
            "unavailable_artifacts": audit.get("unavailable_artifacts"),
        }
    phase3 = data["03_phase3_status.json"]
    if isinstance(phase3, dict):
        diagnostics["phase3_status"] = {
            k: phase3.get(k) for k in
            ("status", "devices_total", "devices_analyzed", "devices_failed",
             "scanner_errors")
            if k in phase3
        }
    exploitation = data["04_exploitation.json"]
    if isinstance(exploitation, dict):
        tests = exploitation.get("tests")
        if isinstance(tests, list):
            diagnostics["verification"] = {
                "rows": len(tests),
                "not_tested": sum(
                    1 for t in tests
                    if isinstance(t, dict)
                    and t.get("verification_status") == "not_tested"
                ),
            }
    cost = data["cost_summary.json"]
    if isinstance(cost, dict):
        diagnostics["cost"] = {
            k: cost.get(k) for k in
            ("total_cost_usd", "cost_is_estimate", "wall_clock_duration_s",
             "total_turns", "total_tool_calls", "total_tool_errors")
            if k in cost
        }
    if run_meta and isinstance(run_meta.get("environment_validation"), dict):
        diagnostics["environment_validation"] = run_meta["environment_validation"]
    for key in ("lifecycle_errors", "usage_errors"):
        if run_meta and run_meta.get(key):
            diagnostics[key] = run_meta[key]

    entry = {
        "run_id": run_id,
        "group": group,
        "scenario": scenario,
        "scenario_sources": candidates,
        "status_recorded": status,
        "cleanup_status": cleanup,
        "phase_results": phase_results,
        "six_phases_complete": six_complete,
        "lifecycle_complete_recorded": lifecycle_complete,
        "commit": commit,
        "scenario_meta_commit": meta_commit,
        "contracts": contracts,
        "score_confirmed": score_entry,
        "score_explanation": score_explanation,
        "total_gt_vulns": score.get("total_gt_vulns") if score else None,
        "diagnostics": diagnostics,
        "files": files,
    }
    return entry, warnings, False


def summarize_review(path, root):
    """Record a supplemental review file (hash + header) without merging."""
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        return {"path": str(path), "present": False,
                "error": f"cannot resolve ({exc})"}, [{
                    "run_id": None, "code": "review_unreadable",
                    "message": f"{path}: cannot resolve ({exc})"}]
    record = {"path": str(resolved)}
    try:
        is_file = resolved.is_file()
    except OSError as exc:
        return {**record, "present": False,
                "error": f"cannot stat ({exc})"}, [{
                    "run_id": None, "code": "review_unreadable",
                    "message": f"{path}: cannot stat ({exc})"}]
    try:
        record["sha256"] = sha256_file(resolved) if is_file else None
    except OSError as exc:
        return {**record, "present": is_file}, [{
            "run_id": None, "code": "review_unreadable",
            "message": f"{path}: unreadable ({exc})"}]
    if not is_file:
        return {**record, "present": False}, [{
            "run_id": None, "code": "review_missing",
            "message": f"{path}: review file not found"}]
    payload, _, error = read_evidence(resolved)
    if error is not None or not isinstance(payload, dict):
        code = ("review_unreadable" if error and error.startswith("unreadable")
                else "review_malformed")
        return {**record, "present": True, "malformed": error is not None}, [{
            "run_id": None, "code": code,
            "message": f"{path}: {error or 'expected a JSON object'}"}]
    header = {k: payload.get(k) for k in
              ("scenario", "run_id", "status", "run_status", "observed_at",
               "reviewed_at", "commit", "deployed_commit")
              if k in payload}
    return {**record, "present": True, "header": header}, []


def build_summary(archive_root, run_ids, scenarios=None, diagnostic_runs=(),
                  reviews=(), observed_at=None):
    """Build the deterministic summary dict (no I/O besides input reads)."""
    root = Path(archive_root).resolve()
    if not root.is_dir():
        raise SummaryError(f"archive root {str(archive_root)!r} is not a directory")
    requested = parse_scenarios(scenarios) if scenarios is not None else None
    if requested is None:
        requested = list(DEFAULT_SCENARIOS)

    seen = set()
    ordered = []
    for run_id in run_ids:
        validate_run_id(run_id)
        if run_id in seen:
            raise SummaryError(f"duplicate run identifier {run_id!r}")
        seen.add(run_id)
        ordered.append(run_id)
    if not ordered:
        raise SummaryError("no runs selected: pass explicit --run IDs or a manifest")
    diag = set()
    for run_id in diagnostic_runs:
        validate_run_id(run_id)
        diag.add(run_id)

    runs = []
    excluded = []
    warnings = []
    for run_id in sorted(ordered):
        group = "diagnostic" if run_id in diag else "official"
        try:
            entry, run_warnings, is_excluded = summarize_run(
                root, run_id, requested, group)
        except SummaryError as exc:
            warnings.append({"run_id": run_id, "code": "run_rejected",
                             "message": str(exc)})
            continue
        warnings.extend(run_warnings)
        (excluded if is_excluded else runs).append(entry)

    supplemental = []
    for review in reviews:
        record, review_warnings = summarize_review(Path(review), root)
        supplemental.append(record)
        warnings.extend(review_warnings)

    summary = {
        "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
        "archive_root": str(root),
        "requested_scenarios": requested,
        "run_ids": sorted(ordered),
        "diagnostic_run_ids": sorted(diag),
        "runs": sorted(runs, key=lambda e: e["run_id"]),
        "excluded": sorted(excluded, key=lambda e: e["run_id"]),
        "supplemental_reviews": supplemental,
        "warnings": warnings,
    }
    if observed_at is not None:
        summary["observed_at"] = observed_at
    return summary


def load_manifest(path):
    """Load an explicit manifest: runs/diagnostic_runs/scenarios lists."""
    with open(path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SummaryError(f"manifest {str(path)!r}: expected a JSON object")
    runs = payload.get("runs", payload.get("run_ids", []))
    if not isinstance(runs, list) or not runs:
        raise SummaryError(
            f"manifest {str(path)!r}: 'runs' must be a non-empty list")
    diagnostics = payload.get("diagnostic_runs", [])
    if not isinstance(diagnostics, list):
        raise SummaryError(
            f"manifest {str(path)!r}: 'diagnostic_runs' must be a list")
    for key, values in (("runs", runs),
                        ("diagnostic_runs", diagnostics)):
        for value in values:
            if not isinstance(value, str):
                raise SummaryError(
                    f"manifest {str(path)!r}: {key} entries must be strings, "
                    f"got {value!r}")
    scenarios = payload.get("scenarios")
    if scenarios is not None and not isinstance(scenarios, list):
        raise SummaryError(
            f"manifest {str(path)!r}: 'scenarios' must be a list")
    manifest_sha = sha256_file(Path(path))
    return runs, diagnostics, scenarios, manifest_sha


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Summarize archived campaign runs offline with provenance.")
    parser.add_argument("--archive-root", required=True,
                        help="archive directory holding one subdirectory per run")
    parser.add_argument("--run", action="append", default=[],
                        help="explicit run ID (immediate child directory); repeatable")
    parser.add_argument("--manifest",
                        help="explicit JSON manifest with runs/diagnostic_runs/scenarios")
    parser.add_argument("--diagnostic-run", action="append", default=[],
                        help="run ID retained as diagnostic, not official; repeatable")
    parser.add_argument("--scenarios", default=None,
                        help="comma-separated scenario filter, e.g. '1-12' (default 1-12)")
    parser.add_argument("--review", action="append", default=[],
                        help="supplemental review JSON recorded separately; repeatable")
    parser.add_argument("--output", required=True,
                        help="destination JSON file ('-' for stdout)")
    parser.add_argument("--overwrite", action="store_true",
                        help="allow overwriting an existing output file")
    parser.add_argument("--observed-at", default=None,
                        help="explicit observation timestamp (otherwise omitted)")
    return parser.parse_args(argv)


def _consumed_input_paths(summary):
    """Resolved paths of every file consumed as evidence input."""
    paths = set()
    for section in ("runs", "excluded"):
        for entry in summary.get(section, []):
            files = entry.get("files", {})
            if isinstance(files, dict):
                for record in files.values():
                    if isinstance(record, dict) and record.get("present"):
                        path = record.get("path")
                        if isinstance(path, str):
                            paths.add(path)
    for review in summary.get("supplemental_reviews", []):
        if isinstance(review, dict) and review.get("present"):
            path = review.get("path")
            if isinstance(path, str):
                paths.add(path)
    return paths


def main(argv=None):
    args = parse_args(argv)
    root = Path(args.archive_root).resolve()

    manifest_runs, manifest_diag, manifest_scenarios = [], [], None
    manifest_record = None
    if args.manifest:
        manifest_path = Path(args.manifest)
        try:
            manifest_runs, manifest_diag, manifest_scenarios, manifest_sha = \
                load_manifest(manifest_path)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: manifest unreadable: {exc}", file=sys.stderr)
            return 2
        except SummaryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        manifest_record = {"path": str(manifest_path), "sha256": manifest_sha}

    run_ids = list(manifest_runs) + list(args.run)
    diagnostic_runs = list(manifest_diag) + list(args.diagnostic_run)
    scenarios = args.scenarios
    if scenarios is None and manifest_scenarios is not None:
        scenarios = manifest_scenarios

    # Output placement: never inside the archive, never over an input.
    out_path = None
    out_resolved = None
    if args.output != "-":
        out_path = Path(args.output)
        try:
            out_resolved = out_path.resolve()
        except (OSError, RuntimeError) as exc:
            print(f"error: cannot resolve --output: {exc}", file=sys.stderr)
            return 2
        if _is_within(out_resolved, root) or out_resolved == root:
            print("error: --output must not be inside the archive root",
                  file=sys.stderr)
            return 2
        if out_resolved.exists() and not args.overwrite:
            print("error: --output exists (pass --overwrite to replace)",
                  file=sys.stderr)
            return 2
        if out_resolved.exists() and out_resolved.is_dir():
            print("error: --output is a directory", file=sys.stderr)
            return 2

    try:
        summary = build_summary(
            root, run_ids,
            scenarios=scenarios,
            diagnostic_runs=diagnostic_runs,
            reviews=args.review,
            observed_at=args.observed_at,
        )
    except SummaryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if manifest_record is not None:
        manifest_record["path"] = str(Path(args.manifest).resolve())
        summary["manifest"] = manifest_record

    text = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        # Never overwrite any consumed input (run evidence, manifest,
        # reviews): refuse exact, symlink and hardlink aliases by file
        # identity, never by content equality.
        consumed = _consumed_input_paths(summary)
        if manifest_record is not None:
            consumed.add(manifest_record["path"])
        try:
            out_stat = out_resolved.stat() if out_resolved.exists() else None
        except OSError as exc:
            print(f"error: cannot stat --output: {exc}", file=sys.stderr)
            return 2
        for consumed_path in consumed:
            if out_resolved == Path(consumed_path):
                print("error: --output aliases a consumed input file "
                      f"({consumed_path}); refusing", file=sys.stderr)
                return 2
            if out_stat is not None:
                try:
                    same = os.path.samestat(out_stat, os.stat(consumed_path))
                except OSError:
                    same = False
                if same:
                    print("error: --output is a hardlink alias of a consumed "
                          f"input file ({consumed_path}); refusing",
                          file=sys.stderr)
                    return 2
        out_path.parent.mkdir(parents=True, exist_ok=True)
        # Read-only inputs: write via a uniquely-created temp file in the
        # destination directory plus atomic replace; the temp file is
        # removed if anything fails.
        fd, tmp_name = tempfile.mkstemp(
            prefix=out_path.name + ".", dir=str(out_path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, out_path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    print(f"runs={len(summary['runs'])} excluded={len(summary['excluded'])} "
          f"warnings={len(summary['warnings'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
