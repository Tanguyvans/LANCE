"""Offline regression: the real Phase 4 resolver and evaluator agree on traces."""
import json
from types import SimpleNamespace

import pytest
import yaml

from src.agent.exploit_evidence import synthesize_exploit_result
from src.agent.phases.verification.run import VerificationPhase
from src.benchmark.evaluator import evaluate, _record_implied_ports
from src.benchmark.metric_contract import metric_contract_metadata


@pytest.mark.parametrize("kind,service,port,endpoint,tool,args,output,accepted", [
    ("data_exposure", "http", 80, "/backup.sql", "http_get", {},
     {"status_code": 200, "body": '<form>Enter your password <input type="password"></form>'}, False),
    ("data_exposure", "http", 80, "/backup.sql", "http_get", {},
     {"status_code": 200, "body": '{"password":"s3cret-value"}'}, True),
    ("data_exposure", "http", 80, "/backup.sql", "http_get", {},
     {"status_code": 200, "body": '{"password":"[redacted]"}'}, False),
    ("data_exposure", "http", 80, "/backup.sql", "http_get", {},
     {"status_code": 403, "body": "password=secret"}, False),
    ("data_exposure", "http", 80, "/backup.sql", "http_get", {},
     {"success": False, "status_code": 200, "body": "password=secret"}, False),
    ("insecure_update", "http", 80, "/update", "http_request",
     {"method": "POST", "body": "unsigned-test-firmware"},
     {"status_code": 200, "body": "Update accepted. Signature not required."}, True),
    ("info_disclosure", "ssh", 22, "", "ssh_audit", {},
     {"stdout": "(gen) banner: SSH-2.0-OpenSSH_9.6"}, True),
    ("default_credentials", "ssh", 22, "", "try_credential",
     {"ip": "192.0.2.1", "service": "ssh", "user": "admin", "password": "admin", "port": None},
     {"success": True, "authenticated": True, "service": "ssh", "stdout": "__ok__"}, True),
    ("default_credentials", "mysql", 3306, "", "try_credential",
     {"ip": "192.0.2.1", "service": "mysql", "user": "admin", "password": "admin"},
     {"success": True, "authenticated": True, "stdout": "user\thost\nadmin\t%\n"}, True),
    ("default_credentials", "mysql", 3306, "", "mysql_query",
     {"user": "root", "query": "SELECT USER(), CURRENT_USER();", "skip_ssl": True,
      },
     {"stdout": "root@192.0.2.1\troot@%",
      "execution_attestation": {
          "protocol": "TCP", "host": "192.0.2.1", "port": 3306,
          "user": "root", "query": "SELECT USER(), CURRENT_USER();",
          "no_defaults": True, "protocol_tcp": True, "empty_password_cli": True,
      }}, True),
    ("default_credentials", "ssh", 22, "", "ssh_login", {},
     {"success": True}, False),
    ("default_credentials", "ssh", 22, "", "ssh_exec", {},
     {"success": True, "stdout": "uid=1000(admin) gid=1000(admin)"}, True),
    ("default_credentials", "ssh", 22, "", "try_credential",
     {"ip": "192.0.2.1", "service": "ssh", "user": "admin", "password": "admin"},
     {"success": True, "authenticated": True}, False),
    ("data_exposure", "http", 80, "/backup.sql", "nmap_scan", {},
     {"stdout": "80/tcp open http"}, False),
])
def test_pipeline_and_final_score_share_observed_proof_rules(
    tmp_path, kind, service, port, endpoint, tool, args, output, accepted,
):
    finding = {
        "id": "V1", "device_id": "device1", "device_ip": "192.0.2.1",
        "type": kind, "severity": "high", "service": service, "port": port,
        "protocol": "tcp", "endpoint": endpoint, "cve_ids": [],
    }
    args = {"host": "192.0.2.1", "port": port, **args}
    if endpoint:
        args["url"] = f"http://192.0.2.1{endpoint}"
    record = {"vuln_id": "V1", "evidence_ref": "proof-1", "tool": tool,
              "args": args, "result": {"return_code": 0, **output}}
    exploit = tmp_path / "exploit.json"
    exploit.write_text(json.dumps({"status": "CONFIRMED", "evidence_level": 3}))
    test = VerificationPhase._resolve_exploit_verdict(
        SimpleNamespace(_uses_compact_local_moe=lambda: False), finding, exploit,
        evidence_refs=["proof-1"], tools_used=[tool], tool_records=[record],
    )
    assert (test["status"] == "CONFIRMED") is accepted
    artifacts = {
        "run_meta.json": metric_contract_metadata(),
        "03_vuln_analysis_raw.json": {"candidates": [{"candidate_finding": finding}]},
        "03_vuln_analysis.json": {"vulnerabilities": [finding]},
        "04_exploitation.json": {"tests": [test]},
    }
    for filename, payload in artifacts.items():
        (tmp_path / filename).write_text(json.dumps(payload))
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(record) + "\n")
    gt = tmp_path / "gt.yaml"
    gt.write_text(yaml.safe_dump({"scenario_id": "demo", "vulnerabilities": [{
        "id": "GT1", "title": kind, "ip": "192.0.2.1", "category": kind,
        "severity": "high", "accepted_types": [kind], "services": [service],
        "ports": [port], "protocols": ["tcp"], "endpoints": [endpoint] if endpoint else [],
    }]}))
    evaluation = evaluate(tmp_path, gt, policy="strict-v3")
    final = evaluation.funnel["stages"]["confirmed"]
    assert evaluation.funnel["stages"]["filtered"]["true_positives"] == 1
    assert final["true_positives"] == int(accepted)
    assert final["false_positives"] == 0  # the normal pipeline rejects invalid claims
    assert final["false_negatives"] == int(not accepted)
    assert evaluation.scenario_score_pct == (100.0 if accepted else 0.0)
    assert evaluation.funnel["diagnostics"]["proofs"] == {
        "available": True, "accepted": int(accepted), "rejected": 0, "missing": 0,
    }


@pytest.mark.parametrize("output,accepted", [
    ({"status_code": 200, "headers": {"X-Frame-Options": "DENY"}}, False),
    ({"status_code": 200, "headers": {"x-frame-options": "DENY"}}, False),
    ({"status_code": 200, "body": "Welcome"}, False),
    ({"status_code": 200, "headers": {}, "body": "X-Frame-Options: DENY"}, True),
    ({"stdout": "HTTP/1.1 200 OK\r\nX-Frame-Options: DENY\r\n\r\n"}, False),
    ({"stdout": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\nX-Frame-Options: DENY"}, True),
])
def test_header_absence_requires_headers_and_ignores_case_and_body(output, accepted):
    result = synthesize_exploit_result(
        {"type": "missing_header", "details": "Missing X-Frame-Options"},
        [{"tool": "curl_headers", "args": {}, "result": {"return_code": 0, **output}}],
    )
    assert (result["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("service,output,accepted", [
    ("http", {"unauthenticated_http_code": 401, "http_code": 200}, True),
    ("http", {"unauthenticated_http_code": 401, "http_code": 500}, False),
    ("http", {"unauthenticated_http_code": 200, "http_code": 200}, False),
    ("ftp", {"anonymous_access": True, "stdout": "welcome"}, False),
    ("ftp", {"anonymous_access": False, "stdout": "welcome"}, True),
    ("mqtt", {"anonymous_access": False, "stdout": ""}, False),
    ("mysql", {"stdout": "user\thost\n"}, False),
])
def test_credential_proof_checks_service_result_not_only_success(service, output, accepted):
    result = synthesize_exploit_result(
        {"type": "default_credentials"}, [{"tool": "try_credential", "args": {"service": service},
        "result": {"success": True, "authenticated": True, **output}}],
    )
    assert (result["status"] == "EXPLOITED") is accepted


@pytest.mark.parametrize("tool,args,ports", [
    ("http_get", {"url": "http://192.0.2.1:8080"}, {8080}),
    ("http_get", {"url": "https://192.0.2.1:8443/"}, {8443}),
    ("http_get", {"url": "https://192.0.2.1/"}, {443}),
    ("ssh_audit", {"host": "192.0.2.1", "port": 2222}, {2222}),
    ("ssh_audit", {"host": "192.0.2.1"}, {22}),
    ("try_credential", {"ip": "192.0.2.1", "service": "ssh"}, {22}),
])
def test_explicit_tool_port_does_not_also_imply_default_port(tool, args, ports):
    assert _record_implied_ports({"tool": tool, "args": args}) == ports
