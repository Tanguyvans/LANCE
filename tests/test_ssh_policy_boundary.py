"""The pipeline and offline evaluator share the same SSH evidence contract."""
import json

import pytest

from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.phases.verification.evidence import _make_test_entry
from src.benchmark.evaluator import _semantic_output_supports_finding


def finding():
    return {"id": "SSH-1", "type": "weak_cipher", "device_ip": "192.0.2.10",
            "service": "ssh", "port": 22, "evidence_level": 2}


@pytest.mark.parametrize("compact", [False, True])
@pytest.mark.parametrize("output,accepted", [
    ("(kex) diffie-hellman-group14-sha1 -- [fail] deprecated", True),
    ("(enc) aes128-cbc -- [warn] weak cipher mode", True),
    ("(key) ssh-rsa (2048-bit) -- [fail] SHA-1 signature", True),
    ("(kex) ecdh-sha2-nistp256 -- [fail] suspected backdoor", False),
    ("(mac) hmac-sha1 -- [fail] SHA-1", False),
    ("[fail] weak cipher; consider removing aes128-cbc", False),
    ("(rec) -aes128-cbc -- remove cipher", False),
    ("(enc) aes128-cbc -- [warn] not supported", False),
    ("(kex) kex-strict-s-v00@openssh.com -- counter-measure CVE-2023-48795", False),
])
def test_ssh_policy_same_in_both_profiles_and_evaluator(compact, output, accepted):
    vuln = finding()
    args = {"host": "192.0.2.10", "port": 22}
    result = {"stdout": output, "return_code": 3}
    verdict = synthesize_exploit_result(vuln, [{"tool": "ssh_audit", "args": args,
        "result": json.dumps(result), "evidence_ref": "tc-ssh"}], compact=compact)
    assert (verdict["evidence_level"] >= 2) == accepted
    assert _semantic_output_supports_finding("ssh_audit", result, vuln, args=args) == accepted
    if accepted:
        assert verdict["evidence_level"] == 2
        assert "not negotiation" in verdict["evidence"]
    assert _make_test_entry(vuln, status=verdict["status"], result=verdict)["crypto_observations"]


@pytest.mark.parametrize("args,result", [
    ({"host": "192.0.2.11", "port": 22}, {"stdout": "(enc) aes128-cbc", "return_code": 3}),
    ({"host": "192.0.2.10", "port": 2222}, {"stdout": "(enc) aes128-cbc", "return_code": 3}),
    ({"host": "192.0.2.10", "port": 22}, {"stderr": "(enc) aes128-cbc", "return_code": 3}),
    ({"host": "192.0.2.10", "port": 22}, {"stdout": "(enc) aes128-cbc", "return_code": 1}),
])
def test_wrong_target_error_or_stderr_cannot_confirm_ssh(args, result):
    verdict = synthesize_exploit_result(finding(), [{"tool": "ssh_audit", "args": args, "result": result}])
    assert verdict["evidence_level"] < 2


def test_ssh_nmap_markers_cannot_bypass_algorithm_policy():
    verdict = synthesize_exploit_result(finding(), [{"tool": "nmap_scan",
        "args": {"target": "192.0.2.10", "ports": "22"},
        "result": {"stdout": "22/tcp open ssh\nweak algorithms [warn]", "return_code": 0}}])
    assert verdict["evidence_level"] < 2
