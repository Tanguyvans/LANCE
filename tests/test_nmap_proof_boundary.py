"""Nmap/Modbus proof must stay bound to the claimed host, port and service."""

import pytest

from src.agent.exploit_evidence import synthesize_exploit_result
from src.benchmark.evaluator import _semantic_output_supports_finding
from tests.test_proof_contract import (
    test_pipeline_and_final_score_share_observed_proof_rules as check_funnel,
)


HOST_A = "192.0.2.1"
HOST_B = "192.0.2.11"


def record(tool, stdout, *, target=HOST_A, ports="502", stderr=""):
    return {
        "tool": tool,
        "args": {"target": target, "ports": ports},
        "result": {"return_code": 0, "stdout": stdout, "stderr": stderr},
    }


def finding(**overrides):
    return {
        "id": "V-modbus",
        "device_id": "meter-a",
        "device_ip": HOST_A,
        "type": "no_auth",
        "service": "modbus",
        "port": 502,
        "protocol": "tcp",
        **overrides,
    }


NSE_OUTPUT = """Nmap scan report for 192.0.2.1
Host is up.
PORT    STATE SERVICE
502/tcp open  modbus
| modbus-discover:
|   sid 0x64:
|     Device identification: Acme Meter v1.2
|_    Read device identification: supported
"""


@pytest.mark.parametrize("compact", [False, True])
def test_real_modbus_nse_identity_proof_is_accepted_by_shared_contract(compact):
    item = record("nmap_scan", NSE_OUTPUT)
    result = synthesize_exploit_result(finding(), [item], compact=compact)

    assert result["status"] == "EXPLOITED"
    assert _semantic_output_supports_finding(
        "nmap_scan", item["result"], finding(), args=item["args"]
    )


@pytest.mark.parametrize("tool", ["nmap_scan", "modbus_scan"])
@pytest.mark.parametrize("compact", [False, True])
def test_bare_open_modbus_port_does_not_prove_no_auth(tool, compact):
    item = record(tool, f"Nmap scan report for {HOST_A}\n502/tcp open modbus")

    result = synthesize_exploit_result(finding(), [item], compact=compact)

    assert result["status"] != "EXPLOITED"
    assert not _semantic_output_supports_finding(
        tool, item["result"], finding(), args=item["args"]
    )


def test_sid_error_only_does_not_prove_modbus_identity_or_no_auth():
    item = record(
        "nmap_scan",
        f"""Nmap scan report for {HOST_A}
502/tcp open modbus
| modbus-discover:
|   sid 0x64:
|_    error: unable to read device identification
""",
    )

    assert synthesize_exploit_result(finding(), [item])["status"] != "EXPLOITED"


def test_ssh_and_anonymous_ftp_evidence_cannot_confirm_ssh_finding():
    item = record(
        "nmap_scan",
        f"""Nmap scan report for {HOST_A}
21/tcp open ftp
| ftp-anon: Anonymous login allowed
22/tcp open ssh
""",
        ports="21,22",
    )
    ssh_finding = finding(type="no_auth", service="ssh", port=22)

    assert synthesize_exploit_result(ssh_finding, [item])["status"] != "EXPLOITED"
    assert not _semantic_output_supports_finding(
        "nmap_scan", item["result"], ssh_finding, args=item["args"]
    )


def test_real_anonymous_ftp_on_port_21_is_positive():
    item = record(
        "nmap_scan",
        f"Nmap scan report for {HOST_A}\n21/tcp open ftp\n| ftp-anon: Anonymous login allowed",
        ports="21",
    )
    ftp_finding = finding(type="no_auth", service="ftp", port=21)

    assert synthesize_exploit_result(ftp_finding, [item])["status"] == "EXPLOITED"


def test_nmap_report_for_other_host_cannot_prove_claimed_host():
    item = record("nmap_scan", NSE_OUTPUT.replace(HOST_A, HOST_B))

    assert synthesize_exploit_result(finding(), [item])["status"] != "EXPLOITED"


def test_ftp_script_on_an_ssh_label_is_not_an_ssh_authentication_proof():
    item = record("nmap_scan", "22/tcp open ssh\n| ftp-anon: Anonymous FTP login allowed", ports="22")
    assert synthesize_exploit_result(finding(service="ssh", port=22), [item])["status"] != "EXPLOITED"


def test_other_port_timeout_does_not_erase_valid_modbus_read():
    item = record("nmap_scan", NSE_OUTPUT + "80/tcp open http\n| http-title: timed out\n", ports="80,502")
    assert synthesize_exploit_result(finding(), [item])["status"] == "EXPLOITED"


def test_multi_target_output_cannot_borrow_modbus_proof_from_other_host():
    item = record(
        "nmap_scan",
        f"""Nmap scan report for {HOST_A}
502/tcp open modbus
Nmap scan report for {HOST_B}
502/tcp open modbus
| modbus-discover:
|   sid 0x64:
|     Device identification: Acme Meter v1.2
""",
    )

    assert synthesize_exploit_result(finding(), [item])["status"] != "EXPLOITED"


@pytest.mark.parametrize(
    "stdout,stderr",
    [
        (
            "Nmap scan report for 192.0.2.1\n80/tcp open http\n"
            "| modbus-discover: sid 0x64: Device identification: Acme Meter v1.2",
            "",
        ),
        (
            "Nmap scan report for 192.0.2.1\n502/tcp open modbus",
            "| modbus-discover: sid 0x64: Device identification: Acme Meter v1.2",
        ),
    ],
)
def test_nmap_proof_cannot_be_borrowed_from_other_port_or_stderr(stdout, stderr):
    item = record("nmap_scan", stdout, stderr=stderr)

    assert synthesize_exploit_result(finding(), [item])["status"] != "EXPLOITED"


@pytest.mark.parametrize("tool", ["nmap_scan", "modbus_scan"])
def test_wrong_service_or_port_cannot_reuse_modbus_proof(tool):
    item = record("nmap_scan", NSE_OUTPUT)
    wrong = finding(service="http", port=80)

    assert synthesize_exploit_result(wrong, [{**item, "tool": tool}])["status"] != "EXPLOITED"
    assert not _semantic_output_supports_finding(
        tool, item["result"], wrong, args=item["args"]
    )


def test_same_host_and_port_with_wrong_service_cannot_reuse_modbus_proof():
    item = record("nmap_scan", NSE_OUTPUT)
    wrong_service = finding(service="http", port=502)

    assert synthesize_exploit_result(wrong_service, [item])["status"] != "EXPLOITED"


def test_crossservice_no_auth_ssh_is_rejected_by_end_to_end_funnel(tmp_path):
    check_funnel(
        tmp_path,
        "no_auth",
        "ssh",
        22,
        "",
        "nmap_scan",
        {"target": HOST_A, "ports": "21,22"},
        {"stdout": (
            f"Nmap scan report for {HOST_A}\n"
            "21/tcp open ftp\n| ftp-anon: Anonymous login allowed\n"
            "22/tcp open ssh\n"
        )},
        False,
    )


def test_unrelated_cve_marker_cannot_use_generic_data_exposure_fallback():
    vuln = finding(type="data_exposure", service="http", port=80)
    item = record(
        "nmap_scan",
        "Nmap scan report for 192.0.2.1\n80/tcp open http\nCVE-2026-99999: VULNERABLE",
        ports="80",
    )

    assert synthesize_exploit_result(vuln, [item])["status"] != "EXPLOITED"
    assert not _semantic_output_supports_finding(
        "nmap_scan", item["result"], vuln, args=item["args"]
    )


def test_modbus_nse_proof_survives_end_to_end_funnel(tmp_path):
    check_funnel(
        tmp_path,
        "no_auth",
        "modbus",
        502,
        "",
        "nmap_scan",
        {"target": HOST_A, "ports": "502"},
        {"stdout": NSE_OUTPUT},
        True,
    )
