from __future__ import annotations

import base64
import json
import zipfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.benchmark.artifacts import (
    ArtifactError,
    build_submission_manifest,
    collect_artifacts,
    create_submission_bundle,
    is_allowed_artifact,
    manifest_sha256,
    verify_submission_manifest,
)
from src.benchmark.contracts import (
    ChallengeContract,
    ContractError,
    EvaluationSummary,
    SubmissionManifest,
    SuiteEvaluationSummary,
)
from src.benchmark.controller import ControllerError, SealedControllerClient


def _valid_contract_dict() -> dict:
    return {
        "schema_version": "1",
        "session_id": "12345678-1234-5678-9234-567812345678",
        "scenario_id": "24",
        "split": "eval-sealed",
        "benchmark_version": "3.2.0",
        "scope": {
            "ingress_cidrs": ["10.77.20.0/24"],
            "entrypoints": ["gateway.eval.internal:443"],
        },
        "limits": {
            "expires_at": "2030-01-01T00:00:00+00:00",
            "max_cost_usd": 2.0,
            "max_tool_calls": 500,
        },
        "artifact_schema_version": "1",
    }


def test_challenge_contract_strict_round_trip():
    raw = _valid_contract_dict()
    contract = ChallengeContract.from_dict(raw)

    assert contract.scenario_id == "24"
    assert contract.scope.ingress_cidrs == ("10.77.20.0/24",)
    assert ChallengeContract.from_json(contract.to_json()) == contract
    assert json.loads(contract.to_json()) == raw


def test_challenge_contract_accepts_missing_optional_entrypoint_hints():
    raw = _valid_contract_dict()
    raw["scope"].pop("entrypoints")

    contract = ChallengeContract.from_dict(raw)

    assert contract.scope.ingress_cidrs == ("10.77.20.0/24",)
    assert contract.scope.entrypoints == ()
    # Serialization is canonical even when the optional field was omitted.
    assert json.loads(contract.to_json())["scope"]["entrypoints"] == []


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda data: data.update({"topology": {"nodes": []}}), "forbidden/unknown"),
        (lambda data: data["scope"].update({"seed": 42}), "forbidden/unknown"),
        (lambda data: data.update({"scenario_id": "23"}), "S24-S29"),
        (lambda data: data.update({"split": "dev-public"}), "eval-sealed"),
        (lambda data: data["scope"].pop("ingress_cidrs"), "missing required"),
        (lambda data: data["scope"].update({"ingress_cidrs": []}), "at least one CIDR"),
        (lambda data: data["scope"].update({"ingress_cidrs": ["10.77.20.1/24"]}), "canonical"),
        (lambda data: data["limits"].update({"expires_at": "2030-01-01T00:00:00"}), "timezone"),
        (lambda data: data["limits"].update({"max_tool_calls": True}), "positive integer"),
    ],
)
def test_challenge_contract_fails_closed(mutator, message):
    raw = _valid_contract_dict()
    mutator(raw)
    with pytest.raises(ContractError, match=message):
        ChallengeContract.from_dict(raw)


def test_artifact_allowlist_rejects_traversal_and_oracle_files():
    assert is_allowed_artifact("03_vuln_analysis.json") is True
    assert is_allowed_artifact("03_device_gateway.json") is True
    assert is_allowed_artifact("03_device_gateway_analysis.md") is True
    assert is_allowed_artifact("03_scans/gateway.json") is True
    assert is_allowed_artifact("04_exploits/gateway/v1.json") is True
    assert is_allowed_artifact("06_report.md") is True
    assert is_allowed_artifact("01_graph_evidence.json") is True
    assert is_allowed_artifact("02_recon_evidence.json") is True
    assert is_allowed_artifact("03_vuln_analysis_raw.json") is True
    assert is_allowed_artifact("06_report_analysis_context.json") is True
    assert is_allowed_artifact("06_report_analysis.md") is True
    assert is_allowed_artifact("deliverable_attempts.jsonl") is True
    assert is_allowed_artifact("model_outputs.jsonl") is True
    assert is_allowed_artifact(
        ".attempts/02_recon.md/attempt-abc.md"
    ) is True
    assert is_allowed_artifact("scenario_meta.json") is True
    assert is_allowed_artifact("ground_truth.yaml") is False
    assert is_allowed_artifact("ansible_06_verify.log") is False
    assert is_allowed_artifact("04_exploits/too/deep/v1.json") is False
    with pytest.raises(ArtifactError, match="unsafe"):
        is_allowed_artifact("../ground_truth.yaml")
    with pytest.raises(ArtifactError, match="POSIX"):
        is_allowed_artifact(r"03_scans\gateway.json")


def _write_run_artifacts(run_dir: Path) -> None:
    (run_dir / "03_scans").mkdir(parents=True)
    (run_dir / "04_exploits" / "gateway").mkdir(parents=True)
    (run_dir / "run_meta.json").write_text('{"model":"test"}', encoding="utf-8")
    (run_dir / "scenario_meta.json").write_text(
        '{"scenario_id":"24","split":"eval-sealed"}',
        encoding="utf-8",
    )
    (run_dir / "03_vuln_analysis.json").write_text('{"vulnerabilities":[]}', encoding="utf-8")
    (run_dir / "03_device_gateway.json").write_text('{"vulnerabilities":[]}', encoding="utf-8")
    (run_dir / "03_scans" / "gateway.json").write_text('{"ports":[443]}', encoding="utf-8")
    (run_dir / "04_exploits" / "gateway" / "v1.json").write_text('{"status":"FAILED"}', encoding="utf-8")
    (run_dir / "06_report.md").write_text("# Final report\n", encoding="utf-8")
    # Explicit oracle-like files are present to prove the positive allowlist does not include them.
    (run_dir / "ground_truth.yaml").write_text("secret: canary", encoding="utf-8")
    (run_dir / "ansible_06_verify.log").write_text("oracle canary", encoding="utf-8")


def test_manifest_hashes_only_allowlisted_artifacts_and_detects_mutation(tmp_path: Path):
    run_dir = tmp_path / "run-1"
    run_dir.mkdir()
    _write_run_artifacts(run_dir)
    contract = ChallengeContract.from_dict(_valid_contract_dict())

    artifacts = collect_artifacts(run_dir)
    paths = [artifact.path for artifact in artifacts]
    assert paths == sorted(paths)
    assert "ground_truth.yaml" not in paths
    assert "ansible_06_verify.log" not in paths
    assert "06_report.md" in paths
    assert "scenario_meta.json" in paths

    manifest = build_submission_manifest(run_dir, contract, run_id="run-1")
    assert SubmissionManifest.from_dict(manifest.to_dict()) == manifest
    assert len(manifest_sha256(manifest)) == 64
    verify_submission_manifest(run_dir, manifest)

    (run_dir / "03_vuln_analysis.json").write_text('{"vulnerabilities":[{"id":"changed"}]}', encoding="utf-8")
    with pytest.raises(ArtifactError, match="mismatch"):
        verify_submission_manifest(run_dir, manifest)


def test_submission_bundle_contains_manifest_and_allowlist_only(tmp_path: Path):
    run_dir = tmp_path / "run-2"
    run_dir.mkdir()
    _write_run_artifacts(run_dir)
    contract = ChallengeContract.from_dict(_valid_contract_dict())
    bundle_path = tmp_path / "submission.zip"

    created, manifest, digest = create_submission_bundle(
        run_dir,
        contract,
        run_id="run-2",
        output_path=bundle_path,
    )
    assert created == bundle_path
    assert len(digest) == 64
    with zipfile.ZipFile(created) as archive:
        names = sorted(archive.namelist())
        assert "manifest.json" in names
        assert "ground_truth.yaml" not in names
        assert "ansible_06_verify.log" not in names
        assert sorted(names) == sorted(["manifest.json", *(artifact.path for artifact in manifest.artifacts)])

    with pytest.raises(ArtifactError, match="outside the run directory"):
        create_submission_bundle(
            run_dir,
            contract,
            run_id="run-2",
            output_path=run_dir / "submission.zip",
        )


def test_collect_artifacts_rejects_allowlisted_symlink(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (run_dir / "run_meta.json").symlink_to(outside)

    with pytest.raises(ArtifactError, match="symlink"):
        collect_artifacts(run_dir)


def test_submission_and_evaluation_contracts_reject_extra_detail():
    contract = ChallengeContract.from_dict(_valid_contract_dict())
    manifest = {
        "schema_version": "1",
        "session_id": contract.session_id,
        "scenario_id": "24",
        "run_id": "run-1",
        "benchmark_version": "3.2.0",
        "artifact_schema_version": "1",
        "artifacts": [{"path": "run_meta.json", "sha256": "a" * 64, "size_bytes": 2}],
        "ground_truth": "oracle",
    }
    with pytest.raises(ContractError, match="forbidden/unknown"):
        SubmissionManifest.from_dict(manifest)

    summary = {
        "schema_version": "1",
        "submission_id": "87654321-4321-6789-9234-567812345678",
        "scenario_id": "24",
        "benchmark_version": "3.2.0",
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {"overall_score": 0.5, "true_positives": 12},
        "signature": "signed",
    }
    with pytest.raises(ContractError, match="forbidden/unknown"):
        EvaluationSummary.from_dict(summary)


def test_evaluation_summary_uses_normalized_ratios_and_nonnegative_usd():
    summary = {
        "schema_version": "1",
        "submission_id": "87654321-4321-6789-9234-567812345678",
        "scenario_id": "24",
        "benchmark_version": "3.2.0",
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {"overall_score": 0.875, "f1": 0.8, "cost_usd": 1.25},
        "signature": "signed",
    }

    parsed = EvaluationSummary.from_dict(summary)
    assert parsed.metrics == summary["metrics"]

    invalid_ratio = {**summary, "metrics": {"overall_score": 87.5}}
    with pytest.raises(ContractError, match="normalized ratio"):
        EvaluationSummary.from_dict(invalid_ratio)

    invalid_cost = {**summary, "metrics": {"overall_score": 0.5, "cost_usd": -1.0}}
    with pytest.raises(ContractError, match="non-negative USD"):
        EvaluationSummary.from_dict(invalid_cost)


def test_official_sealed_result_is_bound_to_a_suite_not_one_submission():
    summary = {
        "schema_version": "1",
        "suite_id": "12345678-1234-5678-9234-567812345678",
        "benchmark_version": "3.2.0",
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {"overall_score": 0.75, "f1": 0.7, "cost_usd": 8.0},
        "signature": "signed-suite-envelope",
    }

    parsed = SuiteEvaluationSummary.from_dict(summary)
    assert parsed.suite_id == summary["suite_id"]
    assert parsed.metrics == summary["metrics"]

    leaked = {**summary, "scenario_id": "24"}
    with pytest.raises(ContractError, match="forbidden/unknown"):
        SuiteEvaluationSummary.from_dict(leaked)


def test_complete_suite_signature_payload_is_verified_by_client():
    suite_id = "12345678-1234-5678-9234-567812345678"
    unsigned = {
        "schema_version": "1",
        "suite_id": suite_id,
        "benchmark_version": "3.2.0",
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {
            "overall_score": 0.75,
            "verified_f1": 0.75,
            "planned_runs": 18,
            "completed_runs": 18,
        },
        "signature": "placeholder",
    }
    parsed = SuiteEvaluationSummary.from_dict(unsigned)
    private_key = Ed25519PrivateKey.generate()
    signature = private_key.sign(parsed.signature_payload())
    payload = {
        **unsigned,
        "signature": "ed25519:" + base64.urlsafe_b64encode(signature).rstrip(b"=").decode(),
    }

    class Response:
        status_code = 200
        headers = {}

        @staticmethod
        def json():
            return payload

    class Session:
        trust_env = True

        def request(self, *_args, **_kwargs):
            return Response()

        def close(self):
            return None

    client = SealedControllerClient(
        "https://controller.internal",
        "top-secret",
        session=Session(),
        signature_public_key=private_key.public_key(),
    )

    result = client.get_suite_evaluation(suite_id)

    assert result.metrics["verified_f1"] == 0.75
    assert client._session.trust_env is False


def test_complete_suite_without_trusted_key_fails_closed():
    suite_id = "12345678-1234-5678-9234-567812345678"
    payload = {
        "schema_version": "1",
        "suite_id": suite_id,
        "benchmark_version": "3.2.0",
        "status": "complete",
        "score_visibility": "aggregate",
        "metrics": {"overall_score": 0.75},
        "signature": "ed25519:" + "A" * 86,
    }

    class Response:
        status_code = 200
        headers = {}

        @staticmethod
        def json():
            return payload

    class Session:
        def request(self, *_args, **_kwargs):
            return Response()

        def close(self):
            return None

    client = SealedControllerClient(
        "https://controller.internal", "top-secret", session=Session()
    )
    with pytest.raises(ControllerError, match="trusted Ed25519 public key"):
        client.get_suite_evaluation(suite_id)


def test_controller_client_requires_tls_and_redacts_its_token():
    with pytest.raises(ControllerError, match="requires HTTPS"):
        SealedControllerClient("http://controller.internal", "top-secret")

    client = SealedControllerClient("https://controller.internal", "top-secret")
    try:
        assert "top-secret" not in repr(client)
        assert "<redacted>" in repr(client)
    finally:
        client.close()
