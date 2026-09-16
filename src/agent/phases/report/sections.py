"""Run-local report cards: source facts are immutable; prose is commentary only."""
from __future__ import annotations

from collections import Counter
import hashlib
import html
import json
from pathlib import Path

from src.agent.artifacts import resolve_run_artifact
from src.agent.evidence.records import observed_targets
from src.agent.phases.intrusion.observations import project_intrusion_observations
from src.agent.phases.report.context import _execution_facts
from src.agent.phases.report.traceability import ReportTraceIndex
from src.agent.report_evidence import verification_state


CONTEXT_MAX_BYTES = 24_000
NOTE_MAX_CHARS = 4_000
MANIFEST = "06_report_sections.json"


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
        result = []
        refs = test.get("evidence_refs")
        if not isinstance(refs, list) or not trace.intact:
            return result
        for ref in refs:
            records = trace.records.get(str(ref).strip(), [])
            if len(records) != 1:
                continue
            record = records[0]
            if (not test.get("vuln_id") or record.get("vuln_id") != test["vuln_id"]
                    or not test.get("device_ip") or test["device_ip"] not in observed_targets(record)):
                continue
            raw = encoded(record.get("result"))
            result.append({"evidence_ref": ref, "tool": record.get("tool"),
                           "result_excerpt": raw[:1600], "excerpt_truncated": len(raw) > 1600,
                           "full_source": "tool_calls.jsonl", "record_digest": digest(record)})
        return result
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
        cards.append({
            "key": f"finding-{index + 1:04d}", "kind": "finding",
            "title": f"Hypothèse {identifier or '(identifiant manquant)'}",
            "facts": {
                "source": f"03_vuln_analysis.json#/vulnerabilities/{index}",
                "hypothesis": finding, "recorded_verification_state": state,
                "tests": [{"source": f"04_exploitation.json#/tests/{i}", "record": t,
                           "reference_diagnostic": trace.describe(t),
                           "attributed_observations": observations(t),
                           "evidence_records_digest": digest([
                               trace.records.get(str(ref).strip(), []) for ref in
                               (t["evidence_refs"] if isinstance(t.get("evidence_refs"), list) else [])
                           ])} for i, t in linked],
                "evidence_source": "tool_calls.jsonl",
                "interpretation": "Recorded Phase 4 state, not independent benchmark proof acceptance. Failed attempts do not refute a hypothesis.",
            },
            "source_issue": "ambiguous_identity" if ambiguous else None,
        })
    for index, test in enumerate(tests):
        if index not in matched:
            cards.append({"key": f"orphan-{index + 1:04d}", "kind": "diagnostic",
                          "title": "Test sans hypothèse attribuable",
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
                      "title": f"Accès observé — {access['device_ip']}",
                      "facts": {"access": access, "source": "tool_calls.jsonl (Phase 5)",
                                "interpretation": "An observed access is not a network pivot."},
                      "source_issue": None})
    cards.append({"key": "intrusion-limits", "kind": "intrusion",
                  "title": "Intrusion — couverture et limites",
                  "facts": {k: v for k, v in intrusion.items() if k != "accesses"},
                  "source_issue": None})
    if issues:
        cards.append({"key": "source-errors", "kind": "diagnostic",
                      "title": "Sources manquantes ou invalides", "facts": {"issues": issues},
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
    return f"<p><strong>{label} :</strong> {_escape(str(value if value is not None else 'non renseigné'))}</p>"


def _readable_facts(card: dict) -> str:
    facts = card["facts"]
    lines = []
    if card["kind"] == "finding" and isinstance(facts.get("hypothesis"), dict):
        finding = facts["hypothesis"]
        for label, value in (
            ("Cible", finding.get("device_ip") or finding.get("device_id")),
            ("Service / port", f"{finding.get('service', '?')} / {finding.get('port', '?')}"),
            ("Propriété annoncée", finding.get("type")),
            ("Sévérité déclarée", finding.get("severity")),
            ("Hypothèse", finding.get("details") or finding.get("evidence")),
            ("État de vérification enregistré", facts["recorded_verification_state"]),
        ):
            lines.append(_fact_paragraph(label, value))
        for linked in facts["tests"]:
            test = linked["record"]
            lines.extend((_fact_paragraph("Observation", test.get("evidence")),
                          _fact_paragraph("Outils", test.get("tools_used") or test.get("tool_used")),
                          _fact_paragraph("Références", test.get("evidence_refs", [])),
                          _fact_paragraph("Attribution (pas validation de preuve)", linked["reference_diagnostic"])))
        if not facts["tests"]:
            lines.append(_fact_paragraph("Vérification", "Aucun test attribué ; hypothèse non confirmée."))
    elif card["kind"] == "intrusion":
        if "access" in facts:
            lines.extend((_fact_paragraph("Accès observé", facts["access"].get("device_ip")),
                          _fact_paragraph("Références", facts["access"].get("evidence_refs", []))))
        else:
            lines.extend((_fact_paragraph("Observations disponibles", facts.get("available")),
                          _fact_paragraph("Statut d’exécution de l’intrusion", facts.get("execution_status")),
                          _fact_paragraph("Preuves de transition disponibles", facts.get("transition_evidence_available")),
                          _fact_paragraph("Limite", facts.get("reason") or "Un accès ne prouve pas un pivot.")))
    return "\n".join(lines)


def render_cards(run_dir: Path, manifest: dict, *, intrusion: bool = False) -> str:
    """Render all active cards only; reject missing/corrupted/mismatched snapshots."""
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
        blocks.append(f"#### {_escape(card['title'])} — {card['key']}\n\n"
                      "Faits et références conservés par le pipeline (pas une nouvelle validation) :\n\n"
                      + _readable_facts(card)
                      + "\n\n<details><summary>Faits structurés complets et sources</summary>\n"
                      f"<pre>{_escape(json.dumps(card['facts'], ensure_ascii=False, indent=2))}</pre></details>\n")
        if record["status"] == "usable" and record.get("text_digest") == digest(record["text"]):
            blocks.append("Analyse du modèle (non validée) :\n\n"
                          + "<p>" + _escape(record["text"]).replace("\n", "<br>") + "</p>")
        else:
            blocks.append(f"Rédaction indisponible — `{record['cause']}`. Faits conservés ; section partielle.")
    if len(seen) != manifest["expected_sections"]:
        raise ValueError("Incomplete report card coverage")
    return "\n\n".join(blocks)
