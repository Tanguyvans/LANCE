"""Run-local report cards: source facts are immutable; prose is commentary only."""
from __future__ import annotations

from collections import Counter
import hashlib
import html
import json
import os
from pathlib import Path

from src.agent.artifacts import resolve_run_artifact
from src.agent.evidence.records import observed_targets
from src.agent.phases.intrusion.observations import project_intrusion_observations
from src.agent.phases.report.context import _execution_facts
from src.agent.phases.report.traceability import ReportTraceIndex
from src.agent.report_evidence import verification_state


CONTEXT_MAX_BYTES = 24_000
NOTE_MAX_CHARS = 4_000
OBSERVATION_EXCERPT_CHARS = 1_600
OBSERVATION_MAX_REFS = 6
MANIFEST = "06_report_sections.json"


def _is_audit_mode() -> bool:
    return os.environ.get("LANCE_MODE", "lab").strip().lower() == "audit"


def render_summary(facts: dict) -> str:
    """Describe recorded facts only; never let prose invent ledger incidents."""
    audit = _is_audit_mode()

    def count(value):
        return str(value) if type(value) is int and value >= 0 else ("unknown" if audit else "inconnu")

    analysis = facts.get("analysis_counts", {})
    states = facts.get("recorded_verification_states", {})
    if audit:
        lines = [
            f"Analysis: {count(analysis.get('devices_analyzed'))}/{count(analysis.get('devices_total'))} devices analyzed; "
            f"{count(analysis.get('devices_failed'))} failed.",
        ]
        if facts.get("source_issues"):
            lines.append("Missing or invalid sources: verification counts are not exhaustive.")
        else:
            labels = {"confirmed": "confirmed in verification phase", "inconclusive": "inconclusive",
                      "not_tested": "not tested", "error": "error", "ambiguous": "ambiguous identity"}
            lines.append("Hypotheses: " + "; ".join(
                f"{count(states.get(key, 0))} {label}" for key, label in labels.items()) + ".")
        lines.append("These counts are recorded observations, not deduplicated unique flaws.")
        intrusion = facts.get("intrusion", {})
        if intrusion.get("available"):
            lines.append(f"Intrusion: {count(intrusion.get('observed_access_count'))} observed access(es). An observed access does not prove a network pivot.")
        else:
            lines.append("Intrusion: observations unavailable; coverage unknown.")
        if not intrusion.get("transition_evidence_available"):
            lines.append("No network transition evidence available in this projection.")
        ledger = facts.get("execution_facts", {})
        if ledger.get("ledger_readable") is False:
            lines.append("Tool ledger is missing, unreadable, or malformed; completeness cannot be established.")
        writing = facts.get("writing", {})
        lines.append(f"Report cards: {count(writing.get('usable'))} usable; {count(writing.get('incomplete'))} incomplete.")
        for phase, status in sorted(facts.get("phase_statuses", {}).items()):
            if status != "completed":
                lines.append(f"Recorded status — {phase}: {status}.")
        return "\n".join(lines)

    lines = [
        f"Analyse : {count(analysis.get('devices_analyzed'))}/{count(analysis.get('devices_total'))} machines analysées ; "
        f"{count(analysis.get('devices_failed'))} en échec.",
    ]
    if facts.get("source_issues"):
        lines.append("Sources manquantes ou invalides : les décomptes de vérification ne sont pas exhaustifs.")
    else:
        labels = {"confirmed": "confirmées selon la phase de vérification", "inconclusive": "non concluantes",
                  "not_tested": "non testées", "error": "en erreur", "ambiguous": "à identité ambiguë"}
        lines.append("Hypothèses : " + " ; ".join(
            f"{count(states.get(key, 0))} {label}" for key, label in labels.items()) + ".")
    lines.append("Ces décomptes ne sont ni un nombre de failles uniques ni les VP/FP du benchmark.")
    intrusion = facts.get("intrusion", {})
    if intrusion.get("available"):
        lines.append(f"Intrusion : {count(intrusion.get('observed_access_count'))} accès observés. Un accès ne prouve pas un pivot.")
    else:
        lines.append("Intrusion : observations indisponibles ; couverture inconnue.")
    if not intrusion.get("transition_evidence_available"):
        lines.append("Aucune preuve de transition réseau disponible dans cette projection.")
    ledger = facts.get("execution_facts", {})
    if ledger.get("ledger_readable") is False:
        lines.append("Le journal d’outils est absent, illisible ou mal formé ; sa complétude ne peut pas être établie.")
    writing = facts.get("writing", {})
    lines.append(f"Rédaction des fiches : {count(writing.get('usable'))} utilisables ; {count(writing.get('incomplete'))} incomplètes.")
    for phase, status in sorted(facts.get("phase_statuses", {}).items()):
        if status != "completed":
            lines.append(f"État enregistré — {phase} : {status}.")
    return "\n".join(lines)


def generation_policy(provider: str, token_limit: int) -> dict:
    """Bound prose recovery without changing analysis/verification model settings.

    The registered ollama / ollama-* providers use Ollama's documented
    reasoning_effort control. Other compatible APIs receive no extra option.
    """
    ollama = provider == "ollama" or provider.startswith("ollama-")
    return {
        "token_limits": [token_limit, max(token_limit, min(8192, token_limit * 2))],
        "reasoning_effort": "none" if ollama else None,
    }


def encoded(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value: object) -> str:
    return hashlib.sha256(encoded(value).encode("utf-8")).hexdigest()


def read_object(run_dir: Path, name: str) -> dict:
    path = resolve_run_artifact(run_dir, name)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name}: expected object")
    return value


def write_object(run_dir: Path, name: str, value: dict) -> None:
    path = resolve_run_artifact(run_dir, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = resolve_run_artifact(run_dir, name + ".tmp")
    temporary.write_text(encoded(value), encoding="utf-8")
    temporary.replace(path)


def build_cards(run_dir: Path, phase_results: dict | None = None) -> tuple[list[dict], dict]:
    """Keep every Phase 3 row and every unmatched test; never deduplicate claims."""
    issues = []

    def rows(name, field):
        try:
            data = read_object(run_dir, name)
            if not isinstance(data.get(field), list):
                raise ValueError("expected list")
            return data[field]
        except (OSError, ValueError):
            issues.append(f"{name}: missing or invalid {field}")
            return []

    findings = rows("03_vuln_analysis.json", "vulnerabilities")
    tests = rows("04_exploitation.json", "tests")
    trace = ReportTraceIndex(run_dir)

    def optional_object(name):
        try:
            return read_object(run_dir, name)
        except (OSError, ValueError):
            return {}

    metadata_results = optional_object("run_meta.json").get("results", {})
    results = dict(metadata_results) if isinstance(metadata_results, dict) else {}
    results.update(phase_results or {})
    # Phase 6's own previous status must not invalidate its resumable inputs.
    execution_statuses = {k: v for k, v in results.items()
                          if k != "report" and isinstance(v, str)}
    phase3 = optional_object("03_phase3_status.json")
    analysis_counts = {k: phase3.get(k) for k in ("devices_total", "devices_analyzed", "devices_failed")}
    if isinstance(analysis_counts["devices_failed"], list):
        analysis_counts["devices_failed"] = len(analysis_counts["devices_failed"])

    def observations(test):
        """Attribute ledger excerpts, bounded so card prompts stay O(1).

        Returns (items, omitted): at most OBSERVATION_MAX_REFS excerpts
        are embedded; further attributable references are counted as
        omitted. Digests still cover every reference and the full ledger
        stays the source, so nothing is lost.
        """
        result, omitted = [], 0
        refs = test.get("evidence_refs")
        if not isinstance(refs, list) or not trace.intact:
            return result, omitted
        for ref in refs:
            records = trace.records.get(str(ref).strip(), [])
            if len(records) != 1:
                continue
            record = records[0]
            if (not test.get("vuln_id") or record.get("vuln_id") != test["vuln_id"]
                    or not test.get("device_ip") or test["device_ip"] not in observed_targets(record)):
                continue
            if len(result) >= OBSERVATION_MAX_REFS:
                omitted += 1
                continue
            raw = encoded(record.get("result"))
            result.append({"evidence_ref": ref, "tool": record.get("tool"),
                           "result_excerpt": raw[:OBSERVATION_EXCERPT_CHARS],
                           "excerpt_truncated": len(raw) > OBSERVATION_EXCERPT_CHARS,
                           "full_source": "tool_calls.jsonl", "record_digest": digest(record)})
        return result, omitted
    identifiers = Counter(str(v.get("id") or "") for v in findings if isinstance(v, dict))
    matched = set()
    cards = []
    states = Counter()
    for index, finding in enumerate(findings):
        identifier = str(finding.get("id") or "") if isinstance(finding, dict) else ""
        linked = [(i, t) for i, t in enumerate(tests)
                  if identifier and isinstance(t, dict) and str(t.get("vuln_id") or "") == identifier]
        matched.update(i for i, _ in linked)
        ambiguous = not identifier or identifiers[identifier] != 1 or len(linked) > 1
        state = "ambiguous" if ambiguous else verification_state(linked[0][1] if linked else {})
        states[state] += 1
        def _bounded_test_record(record: dict) -> tuple[dict, bool]:
            """Cap oversized raw evidence fields in card snapshots; full payload stays in 04_exploitation.json."""
            bounded = dict(record)
            truncated = False
            for field in ("evidence", "data_extracted", "raw_output", "output", "stdout"):
                val = bounded.get(field)
                if isinstance(val, str) and len(val) > OBSERVATION_EXCERPT_CHARS:
                    bounded[field] = val[:OBSERVATION_EXCERPT_CHARS]
                    truncated = True
                elif isinstance(val, (dict, list)):
                    raw_val = encoded(val)
                    if len(raw_val) > OBSERVATION_EXCERPT_CHARS:
                        bounded[field] = raw_val[:OBSERVATION_EXCERPT_CHARS]
                        truncated = True
            return bounded, truncated

        linked_tests = []
        for i, t in linked:
            attributed, omitted = observations(t)
            bounded_t, record_truncated = _bounded_test_record(t)
            linked_tests.append({
                "source": f"04_exploitation.json#/tests/{i}", "record": bounded_t,
                "record_excerpt_truncated": record_truncated,
                "reference_diagnostic": trace.describe(t),
                "attributed_observations": attributed,
                "omitted_observations": omitted,
                "evidence_records_digest": digest([
                    trace.records.get(str(ref).strip(), []) for ref in
                    (t["evidence_refs"] if isinstance(t.get("evidence_refs"), list) else [])
                ])})
        audit = _is_audit_mode()
        cards.append({
            "key": f"finding-{index + 1:04d}", "kind": "finding",
            "title": (f"Finding {identifier or '(missing id)'}" if audit else f"Hypothèse {identifier or '(identifiant manquant)'}"),
            "facts": {
                "source": f"03_vuln_analysis.json#/vulnerabilities/{index}",
                "hypothesis": finding, "recorded_verification_state": state,
                "tests": linked_tests,
                "evidence_source": "tool_calls.jsonl",
                "interpretation": "Recorded Phase 4 state, not independent benchmark proof acceptance. Failed attempts do not refute a hypothesis.",
            },
            "source_issue": "ambiguous_identity" if ambiguous else None,
        })
    audit = _is_audit_mode()
    for index, test in enumerate(tests):
        if index not in matched:
            cards.append({"key": f"orphan-{index + 1:04d}", "kind": "diagnostic",
                          "title": ("Unmatched verification test" if audit else "Test sans hypothèse attribuable"),
                          "facts": {"source": f"04_exploitation.json#/tests/{index}", "test": test},
                          "source_issue": "unmatched_test"})

    # This projection already enforces runner ownership/reference integrity.
    # Model-authored chains are not upgraded to verified network transitions.
    intrusion = project_intrusion_observations(run_dir)
    intrusion["execution_status"] = execution_statuses.get("intrusion")
    intrusion["status_source"] = "pipeline phase results; absent means unknown"
    accesses = intrusion.get("accesses", [])
    for index, access in enumerate(accesses):
        cards.append({"key": f"access-{index + 1:04d}", "kind": "intrusion",
                      "title": (f"Observed access — {access['device_ip']}" if audit else f"Accès observé — {access['device_ip']}"),
                      "facts": {"access": access, "source": "tool_calls.jsonl (Phase 5)",
                                "interpretation": "An observed access is not a network pivot."},
                      "source_issue": None})
    cards.append({"key": "intrusion-limits", "kind": "intrusion",
                  "title": ("Intrusion — coverage and limits" if audit else "Intrusion — couverture et limites"),
                  "facts": {k: v for k, v in intrusion.items() if k != "accesses"},
                  "source_issue": None})
    if issues:
        cards.append({"key": "source-errors", "kind": "diagnostic",
                      "title": ("Missing or invalid sources" if audit else "Sources manquantes ou invalides"), "facts": {"issues": issues},
                      "source_issue": "source_invalid"})
    summary = {
        "hypothesis_count": len(findings), "recorded_verification_states": dict(states),
        "unmatched_tests": len(tests) - len(matched), "source_issues": issues,
        "intrusion": {"available": intrusion.get("available"),
                      "observed_access_count": len(accesses) if intrusion.get("available") else None,
                      "transition_evidence_available": intrusion.get("transition_evidence_available"),
                      "execution_status": intrusion["execution_status"],
                      "reason": intrusion.get("reason")},
        "phase_statuses": execution_statuses,
        "analysis_counts": {"source": "03_phase3_status.json", **analysis_counts},
        "execution_facts": _execution_facts(run_dir),
        "interpretation": "Counts describe records, not unique flaws or benchmark TP/FP. Missing evidence means unknown, not zero. No findings are reconstructed from this summary.",
    }
    return cards, summary


def section_prompt(card: dict) -> str:
    template = Path(__file__).resolve().parents[2] / "prompts" / "report.txt"
    return template.read_text(encoding="utf-8").replace("{{report_section_context}}", encoded(card))


def reusable(run_dir: Path, filename: str, fingerprint: str, card: dict) -> dict | None:
    try:
        record = read_object(run_dir, filename)
        text = record.get("text")
        if (record.get("fingerprint") == fingerprint and record.get("card") == card
                and record.get("status") == "usable"
                and isinstance(text, str) and text.strip() and len(text) <= NOTE_MAX_CHARS
                and record.get("text_digest") == digest(text)):
            return record
    except (OSError, ValueError):
        pass
    return None


def _escape(value: str) -> str:
    return html.escape(value).replace("|", "&#124;")


def _fact_paragraph(label: str, value: object) -> str:
    if isinstance(value, (list, dict)):
        value = json.dumps(value, ensure_ascii=False)
    missing = "not recorded" if _is_audit_mode() else "non renseigné"
    sep = ":" if _is_audit_mode() else " :"
    return f"<p><strong>{label}{sep}</strong> {_escape(str(value if value is not None else missing))}</p>"


def _readable_facts(card: dict) -> str:
    audit = _is_audit_mode()
    facts = card["facts"]
    lines = []
    if card["kind"] == "finding" and isinstance(facts.get("hypothesis"), dict):
        finding = facts["hypothesis"]
        field_rows = (
            ("Target" if audit else "Cible", finding.get("device_ip") or finding.get("device_id")),
            ("Service / port", f"{finding.get('service', '?')} / {finding.get('port', '?')}"),
            ("Declared type" if audit else "Propriété annoncée", finding.get("type")),
            ("Declared severity" if audit else "Sévérité déclarée", finding.get("severity")),
            ("Hypothesis" if audit else "Hypothèse", finding.get("details") or finding.get("evidence")),
            ("Recorded verification state" if audit else "État de vérification enregistré", facts["recorded_verification_state"]),
        )
        for label, value in field_rows:
            lines.append(_fact_paragraph(label, value))
        for linked in facts["tests"]:
            test = linked["record"]
            lines.extend((_fact_paragraph("Observation", test.get("evidence")),
                          _fact_paragraph("Tools" if audit else "Outils", test.get("tools_used") or test.get("tool_used")),
                          _fact_paragraph("References" if audit else "Références", test.get("evidence_refs", [])),
                          _fact_paragraph("Attribution (not proof validation)" if audit else "Attribution (pas validation de preuve)", linked["reference_diagnostic"])))
        if not facts["tests"]:
            lines.append(_fact_paragraph(
                "Verification" if audit else "Vérification",
                "No attributed test; hypothesis not confirmed." if audit else "Aucun test attribué ; hypothèse non confirmée.",
            ))
    elif card["kind"] == "intrusion":
        if "access" in facts:
            lines.extend((_fact_paragraph("Observed access" if audit else "Accès observé", facts["access"].get("device_ip")),
                          _fact_paragraph("References" if audit else "Références", facts["access"].get("evidence_refs", []))))
        else:
            lines.extend((_fact_paragraph("Observations available" if audit else "Observations disponibles", facts.get("available")),
                          _fact_paragraph("Intrusion execution status" if audit else "Statut d’exécution de l’intrusion", facts.get("execution_status")),
                          _fact_paragraph("Transition evidence available" if audit else "Preuves de transition disponibles", facts.get("transition_evidence_available")),
                          _fact_paragraph("Limit" if audit else "Limite", facts.get("reason") or ("An observed access does not prove a pivot." if audit else "Un accès ne prouve pas un pivot."))))
    return "\n".join(lines)


def render_cards(run_dir: Path, manifest: dict, *, intrusion: bool = False) -> str:
    """Render all active cards only; reject missing/corrupted/mismatched snapshots."""
    audit = _is_audit_mode()
    blocks = []
    seen = set()
    for entry in manifest["sections"]:
        if entry["key"] in seen:
            raise ValueError("Duplicate report card")
        seen.add(entry["key"])
        record = read_object(run_dir, entry["artifact"])
        card = record["card"]
        if (record["fingerprint"] != entry["fingerprint"] or card["key"] != entry["key"]
                or digest(card) != entry["facts_digest"] or record["status"] != entry["status"]):
            raise ValueError("Report card/source mismatch")
        if record["status"] == "usable" and record.get("text_digest") != digest(record.get("text")):
            raise ValueError("Report card/text mismatch")
        if card["kind"] == "summary" or (card["kind"] == "intrusion") != intrusion:
            continue
        facts_header = (
            "Facts and references recorded by the pipeline (not a new validation):\n\n"
            if audit else
            "Faits et références conservés par le pipeline (pas une nouvelle validation) :\n\n"
        )
        details_summary = "Full structured facts and sources" if audit else "Faits structurés complets et sources"
        blocks.append(f"#### {_escape(card['title'])} — {card['key']}\n\n"
                      + facts_header
                      + _readable_facts(card)
                      + f"\n\n<details><summary>{details_summary}</summary>\n"
                      f"<pre>{_escape(json.dumps(card['facts'], ensure_ascii=False, indent=2))}</pre></details>\n")
        if record["status"] == "usable" and record.get("text_digest") == digest(record["text"]):
            analysis_header = "Model commentary (unvalidated):\n\n" if audit else "Analyse du modèle (non validée) :\n\n"
            blocks.append(analysis_header
                          + "<p>" + _escape(record["text"]).replace("\n", "<br>") + "</p>")
        else:
            unavail = (
                f"Commentary unavailable — `{record['cause']}`. Facts preserved; partial section."
                if audit else
                f"Rédaction indisponible — `{record['cause']}`. Faits conservés ; section partielle."
            )
            blocks.append(unavail)
    if len(seen) != manifest["expected_sections"]:
        raise ValueError("Incomplete report card coverage")
    return "\n\n".join(blocks)
