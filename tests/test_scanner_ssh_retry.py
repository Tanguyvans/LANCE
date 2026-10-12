"""A connection timeout is retried only after fresh reachability evidence."""
import json
from unittest.mock import Mock

import pytest

from src.agent.scanner import scan_device, _fold_repeated_tool_errors
from src.agent.cost_tracker import BudgetExceeded

DEVICE = {"id": "router", "ip": "192.0.2.1", "services": [{"name": "ssh", "port": 2222}]}
TIMEOUT = json.dumps({"stdout": "[exception] cannot connect to 192.0.2.1 port 2222: timed out\n", "return_code": 1})
OBSERVATION = json.dumps({"stdout": "(gen) banner: SSH-2.0-fixture\n(enc) aes128-cbc -- [warn] weak cipher mode", "return_code": 2})


def scan(first=TIMEOUT, second=OBSERVATION, *, state="open", code=0, device=DEVICE):
    audit = Mock(side_effect=[first, second, AssertionError("More than one retry")])
    # Mock is callable but has arbitrary attributes; expose no fake ledger hook.
    audit.last_observation = lambda: None
    nmap = lambda **kw: json.dumps({"stdout": f"2222/tcp {state} ssh", "return_code": code})
    results = scan_device(device, {"ssh_audit": audit, "nmap_scan": nmap})
    return audit, results


def test_timeout_retries_same_host_and_custom_port_and_preserves_both_attempts():
    audit, results = scan()
    assert audit.call_count == 2
    assert [call.kwargs for call in audit.call_args_list] == [{"host": "192.0.2.1", "port": 2222}] * 2
    assert results["ssh"][0]["result"] == TIMEOUT
    assert results["ssh"][-1]["result"] == OBSERVATION
    assert results["ssh"][-1]["retry_of"] == 0
    assert _fold_repeated_tool_errors("router", results) == []


@pytest.mark.parametrize("state,code", [("closed", 0), ("filtered", 0), ("open", 1)])
def test_no_retry_without_successful_open_port_observation(state, code):
    audit, results = scan(state=state, code=code)
    assert audit.call_count == 1
    assert any("ssh_audit" in error for error in _fold_repeated_tool_errors("router", results))


def test_failed_retry_remains_incomplete_and_keeps_both_failures():
    audit, results = scan(second=TIMEOUT)
    assert audit.call_count == 2
    assert _fold_repeated_tool_errors("router", results) == ["router: ssh_audit returned an error (×2)"]


@pytest.mark.parametrize("result", [OBSERVATION, json.dumps({"stdout": "unrelated error", "return_code": 1})])
def test_findings_and_non_transport_errors_are_not_retried(result):
    audit, _ = scan(first=result)
    assert audit.call_count == 1


def test_duplicate_services_do_not_repeat_the_retry():
    audit, _ = scan(device={**DEVICE, "services": DEVICE["services"] * 2})
    assert audit.call_count == 2


def test_wrong_target_or_empty_retry_cannot_resolve_timeout():
    _, results = scan()
    results["ssh"][-1]["kwargs"]["host"] = "192.0.2.2"
    assert _fold_repeated_tool_errors("router", results) == ["router: ssh_audit returned an error"]
    _, results = scan(second=json.dumps({"stdout": "", "return_code": 0}))
    assert _fold_repeated_tool_errors("router", results) == ["router: ssh_audit returned an error"]


def test_retry_cannot_bypass_executor_budget_failure():
    with pytest.raises(BudgetExceeded):
        scan(second=BudgetExceeded("No calls remaining"))
