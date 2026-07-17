"""Security and anti-gaming tests for the strict-v3 evaluation policy."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from src.benchmark.evaluator import STRICT_V3, _load_llm_findings, evaluate
from src.benchmark.proofs import (
    FindingVerdict,
    PathVerdict,
    ProofError,
    TrustedProofLedger,
    canonical_findings_sha256,
    ground_truth_sha256,
    issue_canary,
    new_canary_secret,
    verify_canary,
)


PROOF_DIGEST = "a" * 64
VERIFIER_ID = "sealed-canary-v1"
PROOF_SECRET = b"s" * 32
SESSION_ID = "12345678-1234-5678-9234-567812345678"


def _finding(
    finding_id: str,
    *,
    ip: str,
    finding_type: str,
    severity: str = "high",
    evidence_level: int = 0,
    cve_ids: list[str] | None = None,
) -> dict:
    return {
        "id": finding_id,
        "device_ip": ip,
        "type": finding_type,
        "severity": severity,
        "details": "worker-controlled claim",
        "evidence": "worker-controlled evidence",
        "evidence_level": evidence_level,
        "cve_ids": cve_ids or [],
    }


def _vulnerability(
    vuln_id: str,
    *,
    ip: str,
    expected_type: str,
    category: str = "misconfiguration",
    severity: str = "high",
    cve: str | None = None,
) -> dict:
    return {
        "id": vuln_id,
        "device": f"device-{vuln_id}",
        "ip": ip,
        "title": f"Expected vulnerability {vuln_id}",
        "category": category,
        "expected_type": expected_type,
        "severity": severity,
        "cve": cve,
    }


def _write_run(tmp_path: Path, findings: list[dict]) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "03_vuln_analysis.json").write_text(
        json.dumps({"vulnerabilities": findings}),
        encoding="utf-8",
    )
    return run_dir


def _write_gt(
    tmp_path: Path,
    vulnerabilities: list[dict],
    *,
    attack_paths: list[dict] | None = None,
    bonus_types: list[str] | None = None,
) -> Path:
    path = tmp_path / "scenario_99.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "scenario_id": "99",
                "vulnerabilities": vulnerabilities,
                "attack_paths": attack_paths or [],
                "bonus_types": bonus_types or [],
                "scoring": {
                    "weights": {
                        "critical": 4,
                        "high": 3,
                        "medium": 2,
                        "low": 1,
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return path


def _verdict(
    index: int,
    *,
    disposition: str,
    gt_id: str | None = None,
    level: int = 0,
) -> FindingVerdict:
    return FindingVerdict(
        finding_index=index,
        disposition=disposition,  # type: ignore[arg-type]
        gt_id=gt_id,
        evidence_level=level,
        verifier_id=VERIFIER_ID,
        proof_digest=PROOF_DIGEST,
    )


def _ledger(
    run_dir: Path,
    gt_file: Path,
    verdicts: tuple[FindingVerdict, ...],
    *,
    path_verdicts: tuple[PathVerdict, ...] = (),
) -> TrustedProofLedger:
    findings = _load_llm_findings(run_dir)
    return TrustedProofLedger.issue(
        secret=PROOF_SECRET,
        session_id=SESSION_ID,
        scenario_id="99",
        findings_sha256=canonical_findings_sha256(findings),
        ground_truth_sha256=ground_truth_sha256(gt_file),
        finding_verdicts=verdicts,
        path_verdicts=path_verdicts,
    )


def _evaluate_strict(
    run_dir: Path,
    gt_file: Path,
    ledger: TrustedProofLedger,
):
    return evaluate(
        run_dir,
        gt_file,
        policy=STRICT_V3,
        proof_ledger=ledger,
        proof_secret=PROOF_SECRET,
        proof_session_id=SESSION_ID,
    )


def test_strict_v3_fails_closed_without_trusted_ledger(tmp_path: Path):
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
    )
    run_dir = _write_run(
        tmp_path,
        [_finding("F1", ip="10.0.0.1", finding_type="no_auth")],
    )

    with pytest.raises(ProofError, match="requires an evaluator-owned"):
        evaluate(run_dir, gt_file, policy=STRICT_V3)


def test_strict_v3_requires_explicit_canonical_expected_type(tmp_path: Path):
    vulnerability = _vulnerability(
        "V1",
        ip="10.0.0.1",
        expected_type="no_auth",
    )
    vulnerability["expected_type"] = "unauthenticated_access"
    gt_file = _write_gt(tmp_path, [vulnerability])
    run_dir = _write_run(
        tmp_path,
        [_finding("F1", ip="10.0.0.1", finding_type="no_auth")],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="verified_gt", gt_id="V1", level=1),),
    )

    with pytest.raises(ValueError, match="expected_type must be canonical"):
        _evaluate_strict(run_dir, gt_file, ledger)


def test_strict_v3_rejects_broad_category_match(tmp_path: Path):
    gt_file = _write_gt(
        tmp_path,
        [
            _vulnerability(
                "V1",
                ip="10.0.0.1",
                expected_type="insecure_protocol",
                category="misconfiguration",
            )
        ],
    )
    run_dir = _write_run(
        tmp_path,
        [_finding("F1", ip="10.0.0.1", finding_type="no_auth")],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="rejected"),),
    )

    result = _evaluate_strict(run_dir, gt_file, ledger)

    assert result.true_positives == 0
    assert result.false_negatives == 1
    assert result.false_positives == 1
    assert result.matches[0]["expected_type"] == "insecure_protocol"


def test_strict_v3_uses_verifier_level_not_model_evidence_level(tmp_path: Path):
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
    )
    run_dir = _write_run(
        tmp_path,
        [
            _finding(
                "F1",
                ip="10.0.0.1",
                finding_type="no_auth",
                evidence_level=3,
            )
        ],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="verified_gt", gt_id="V1", level=1),),
    )

    result = _evaluate_strict(run_dir, gt_file, ledger)

    assert result.true_positives == 1
    assert result.tp_exploited == 0
    assert result.tp_detected_only == 1
    assert result.matches[0]["proof_verified"] is True
    assert result.matches[0]["proof_level"] == 1


def test_strict_v3_does_not_neutralize_global_bonus_spam(tmp_path: Path):
    findings = [_finding("F0", ip="10.0.0.1", finding_type="no_auth")]
    findings.extend(
        _finding(
            f"F{index}",
            ip=f"198.51.100.{index}",
            finding_type="known_cve",
            cve_ids=["CVE-2024-12345"],
        )
        for index in range(1, 101)
    )
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
        bonus_types=["known_cve"],
    )
    run_dir = _write_run(tmp_path, findings)
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="verified_gt", gt_id="V1", level=1),),
    )

    result = _evaluate_strict(run_dir, gt_file, ledger)

    assert result.true_positives == 1
    assert result.false_positives == 100
    assert result.bonus_findings == 0
    assert result.unsupported_claims == 100
    assert result.precision == pytest.approx(1 / 101, abs=0.001)


def test_strict_v3_neutralizes_only_a_verifier_confirmed_extra(tmp_path: Path):
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
    )
    run_dir = _write_run(
        tmp_path,
        [
            _finding("F1", ip="10.0.0.1", finding_type="no_auth"),
            _finding("F2", ip="10.0.0.2", finding_type="weak_cipher"),
        ],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (
            _verdict(0, disposition="verified_gt", gt_id="V1", level=1),
            _verdict(1, disposition="verified_extra", level=2),
        ),
    )

    result = _evaluate_strict(run_dir, gt_file, ledger)

    assert result.false_positives == 0
    assert result.verified_extras == 1
    assert result.bonus_findings == 0
    assert result.verified_extra_findings_list[0]["proof_level"] == 2


def test_strict_v3_attack_path_requires_separate_path_proof(tmp_path: Path):
    vulnerabilities = [
        _vulnerability("V1", ip="10.0.0.1", expected_type="no_auth"),
        _vulnerability("V2", ip="10.0.0.2", expected_type="no_auth"),
    ]
    paths = [
        {
            "id": "P1",
            "title": "Two verified hops",
            "chain": [{"hop": 1}, {"hop": 2}],
            "vulnerabilities_used": ["V1", "V2"],
        }
    ]
    gt_file = _write_gt(tmp_path, vulnerabilities, attack_paths=paths)
    run_dir = _write_run(
        tmp_path,
        [
            _finding("F1", ip="10.0.0.1", finding_type="no_auth"),
            _finding("F2", ip="10.0.0.2", finding_type="no_auth"),
        ],
    )
    verdicts = (
        _verdict(0, disposition="verified_gt", gt_id="V1", level=2),
        _verdict(1, disposition="verified_gt", gt_id="V2", level=2),
    )

    without_path_proof = _evaluate_strict(
        run_dir,
        gt_file,
        _ledger(run_dir, gt_file, verdicts),
    )
    path_verdict = PathVerdict(
        path_id="P1",
        verified=True,
        deepest_verified_hop=2,
        verifier_id=VERIFIER_ID,
        proof_digest=PROOF_DIGEST,
    )
    with_path_proof = _evaluate_strict(
        run_dir,
        gt_file,
        _ledger(
            run_dir,
            gt_file,
            verdicts,
            path_verdicts=(path_verdict,),
        ),
    )

    assert without_path_proof.true_positives == 2
    assert without_path_proof.path_coverage == 0.0
    assert with_path_proof.path_coverage == 1.0
    assert with_path_proof.path_matches[0]["proof_verified"] is True


def test_strict_v3_detects_ledger_replay_after_finding_mutation(tmp_path: Path):
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
    )
    run_dir = _write_run(
        tmp_path,
        [_finding("F1", ip="10.0.0.1", finding_type="no_auth")],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="verified_gt", gt_id="V1", level=1),),
    )
    (run_dir / "03_vuln_analysis.json").write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    _finding("F1", ip="10.0.0.1", finding_type="weak_cipher")
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ProofError, match="findings digest mismatch"):
        _evaluate_strict(run_dir, gt_file, ledger)


def test_strict_v3_rejects_forged_signature_and_cross_session_replay(
    tmp_path: Path,
):
    gt_file = _write_gt(
        tmp_path,
        [_vulnerability("V1", ip="10.0.0.1", expected_type="no_auth")],
    )
    run_dir = _write_run(
        tmp_path,
        [_finding("F1", ip="10.0.0.1", finding_type="no_auth")],
    )
    ledger = _ledger(
        run_dir,
        gt_file,
        (_verdict(0, disposition="verified_gt", gt_id="V1", level=1),),
    )
    round_tripped = TrustedProofLedger.from_json(ledger.to_json())
    round_tripped.verify_signature(PROOF_SECRET)
    assert round_tripped == ledger

    with pytest.raises(ProofError, match="signature mismatch"):
        evaluate(
            run_dir,
            gt_file,
            policy=STRICT_V3,
            proof_ledger=ledger,
            proof_secret=b"x" * 32,
            proof_session_id=SESSION_ID,
        )

    with pytest.raises(ProofError, match="session_id mismatch"):
        evaluate(
            run_dir,
            gt_file,
            policy=STRICT_V3,
            proof_ledger=ledger,
            proof_secret=PROOF_SECRET,
            proof_session_id="87654321-4321-6789-9234-567812345678",
        )


def test_canary_is_session_bound_and_tamper_evident():
    secret = new_canary_secret()
    session_id = str(uuid4())
    challenge_id = str(uuid4())
    token = issue_canary(
        secret,
        session_id=session_id,
        challenge_id=challenge_id,
    )

    assert verify_canary(secret, session_id=session_id, token=token) == challenge_id
    assert verify_canary(secret, session_id=str(uuid4()), token=token) is None
    replacement = "0" if token[-1] != "0" else "1"
    assert (
        verify_canary(secret, session_id=session_id, token=token[:-1] + replacement)
        is None
    )
    assert challenge_id.replace("-", "") in token
    assert "V1" not in token


def test_direct_proof_constructors_enforce_invariants():
    with pytest.raises(ProofError, match="requires evidence_level"):
        _verdict(0, disposition="verified_extra", level=0)

    with pytest.raises(ProofError, match="unverified path"):
        PathVerdict(
            path_id="P1",
            verified=False,
            deepest_verified_hop=1,
            verifier_id=VERIFIER_ID,
            proof_digest=PROOF_DIGEST,
        )
