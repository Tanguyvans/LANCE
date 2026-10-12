"""SSH access and weak-credential findings are separate proof contracts."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.agent.evidence.capabilities import access_supported
from src.agent.phases.verification.run import VerificationPhase
from src.agent.phases.verification.contract import _phase4_verification_plan
from src.agent.evidence.credentials import ssh_request
from src.agent.phases.report.rendering import pregenerate_report_sections
from src.benchmark.evaluator import _semantic_output_supports_finding
from tests.test_proof_contract import test_pipeline_and_final_score_share_observed_proof_rules as check_funnel


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("hints,user,password", [
    ({"details": "SSH default credentials must be tested (ubnt:ubnt)"}, "ubnt", "ubnt"),
    ({"details": "Test root:root, admin:admin"}, "root", "root"),
    ({"technique": "Test SSH with pi:raspberry"}, "pi", "raspberry"),
    ({}, "admin", "admin"),
    ({"details": "alice:unique-password"}, "admin", "admin"),
    ({"details": "notubnt:ubntsuffix"}, "admin", "admin"),
    ({"details": "ubnt:ubnt; $(touch /tmp/unwanted)"}, "ubnt", "ubnt"),
    ({"details": ["ubnt:ubnt"], "technique": None}, "admin", "admin"),
])
def test_ssh_plan_selects_only_explicit_policy_pairs_and_keeps_destination(compact, hints, user, password):
    plan = _phase4_verification_plan({"type": "default_credentials", "service": "ssh",
        "device_ip": "192.0.2.17", "port": 2222, **hints}, compact=compact)
    request = ssh_request({"tool": plan["tool"], "args": plan["args_hint"]})
    assert request == {"host": "192.0.2.17", "port": 2222, "user": user, "password": password}
    assert plan["args_hint"]["command_string"].endswith(" 'id'")
    assert "touch" not in plan["args_hint"]["command_string"]


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("overrides,accepted", [
    ({}, True),
    ({"ip": "192.0.2.2"}, False),
    ({"port": 2222}, False),
    ({"user": "alice", "password": "unique-generated-credential"}, False),
    ({"password": None}, False),
])
def test_pipeline_binds_ssh_target_and_weak_pair_without_losing_access(compact, overrides, accepted):
    finding = {"id": "V1", "device_ip": "192.0.2.1", "service": "ssh",
               "port": 22, "type": "default_credentials"}
    args = {"ip": "192.0.2.1", "port": 22, "user": "admin",
            "password": "admin", "command": "id", **overrides}
    record = {"tool": "ssh_exec", "args": args, "evidence_ref": "tc-ssh",
              "result": {"return_code": 0, "stdout": "uid=1000(admin) gid=1000(admin)"}}
    verdict = VerificationPhase._resolve_exploit_verdict(
        SimpleNamespace(_uses_compact_local_moe=lambda: compact), finding,
        Path("unused-model-artifact"), tool_records=[record],
    )
    assert (verdict["status"] == "CONFIRMED") is accepted
    assert _semantic_output_supports_finding("ssh_exec", record["result"], finding, args=args) is accepted
    # A credential not in the weak-pair policy is still a successful access;
    # do not erase the independent intrusion observation.
    assert access_supported(record)


@pytest.mark.parametrize("ip,password,accepted", [
    ("192.0.2.1", "admin", True),
    ("192.0.2.2", "admin", False),
    ("192.0.2.1", "unique-generated-credential", False),
])
def test_final_funnel_rejects_wrong_host_and_nonweak_credentials(tmp_path, ip, password, accepted):
    check_funnel(tmp_path, "default_credentials", "ssh", 22, "", "ssh_exec",
                 {"ip": ip, "user": "admin", "password": password, "command": "id"},
                 {"stdout": "uid=1000(admin) gid=1000(admin)"}, accepted)
    pregenerate_report_sections(tmp_path)
    report = (tmp_path / "06_report_prefill.md").read_text()
    assert ("No selected Phase 3 hypothesis" not in report) is accepted


def test_ssh_cannot_confirm_another_service():
    finding = {"type": "default_credentials", "service": "http", "port": 22,
               "device_ip": "192.0.2.1"}
    assert not _semantic_output_supports_finding("ssh_exec", {
        "return_code": 0, "stdout": "uid=0(root)",
    }, finding, args={"ip": "192.0.2.1", "user": "root", "password": "root"})


def test_http_credential_attempt_cannot_confirm_ssh():
    assert not _semantic_output_supports_finding("try_credential", {
        "success": True, "authenticated": True,
        "unauthenticated_http_code": 401, "http_code": 200,
    }, {"type": "default_credentials", "service": "ssh", "port": 22,
        "device_ip": "192.0.2.1"}, args={
            "ip": "192.0.2.1", "port": 22, "service": "http",
            "user": "admin", "password": "admin",
        })
