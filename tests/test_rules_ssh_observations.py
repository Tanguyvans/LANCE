"""SSH audit exit codes describe findings independently of probe failures."""
import pytest

from src.agent.phases.verification.rules import _observation


@pytest.mark.parametrize("code", [2, 3])
def test_ssh_audit_findings_are_responses_not_execution_errors(code):
    assert _observation({
        "return_code": code, "stdout": "(enc) aes128-cbc -- [warn] weak cipher mode",
    }, tool="ssh_audit") == "response"


@pytest.mark.parametrize("code", [1, 2, 3])
def test_ssh_audit_without_observations_remains_a_tool_error(code):
    assert _observation({"return_code": code, "stdout": ""}, tool="ssh_audit") == "tool_error"


def test_unrelated_command_failure_cannot_become_a_security_finding():
    assert _observation({
        "return_code": 3, "stdout": "(enc) aes128-cbc -- [warn] weak cipher mode",
    }, tool="nmap_scan") == "tool_error"
