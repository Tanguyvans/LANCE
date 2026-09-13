from pathlib import Path
import os
import re
import subprocess

import pytest
import yaml
from jinja2 import StrictUndefined
from jinja2.nativetypes import NativeEnvironment


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "benchmarks/ansible/playbooks/06_verify.yml"
INJECT = ROOT / "benchmarks/ansible/playbooks/04_inject_vulns.yml"


def tasks(path):
    play = yaml.safe_load(path.read_text(encoding="utf-8"))[0]
    return play["tasks"]


def task_registered_as(path, register):
    return next(task for task in tasks(path) if task.get("register") == register)


def render(expression, values):
    environment = NativeEnvironment(undefined=StrictUndefined)
    # Ansible's 'search' test is a Python regexp search. Execute the actual
    # production expressions, not a reimplementation of their accounting.
    environment.tests["search"] = lambda value, pattern: re.search(pattern, str(value)) is not None
    return environment.from_string(expression).render(values)


def strict_results_ok(results, expected):
    preparation = next(t["ansible.builtin.set_fact"] for t in tasks(VERIFY)
        if t.get("name") == "Préparer les résultats des checks vulnérables")
    consolidation = next(t["ansible.builtin.set_fact"] for t in tasks(VERIFY)
        if t.get("name") == "Évaluer les résultats — consolider les checks OK/FAIL")
    executed = render(preparation["_mqtt_results"], {"mqtt_conn_check": {"results": results}})
    return render(consolidation["_check_mqtt_ok"], {"_mqtt_results": executed, "_mqtt_expected": expected})


def test_injection_enables_server_tokens_only_in_vulnerable_nginx_block():
    scripts = [
        task["ansible.builtin.copy"]["content"]
        for task in tasks(INJECT)
        if task.get("register") is None
        and task.get("ansible.builtin.copy", {}).get("dest") == "/tmp/inject_web.sh"
    ]

    assert len(scripts) == 1
    assert "server_tokens on;" in scripts[0]
    assert "security_profile" not in scripts[0]


def test_web_version_check_targets_each_item_ip_and_hides_response_body():
    task = task_registered_as(VERIFY, "web_version_check")
    shell = task["ansible.builtin.shell"]
    rendered = shell.replace("{{ item.ip }}", "192.0.2.44")

    assert "http://192.0.2.44/" in rendered
    assert "127.0.0.1" not in rendered
    assert "--max-time 5" in rendered
    assert "--max-redirs 0" in rendered
    assert "--dump-header -" in rendered
    assert "--output /dev/null" in rendered
    assert "--noproxy '*'" in rendered
    assert "HTTP_STATUS" not in rendered


def test_web_version_check_requires_http_200_and_numeric_nginx_version():
    task = task_registered_as(VERIFY, "web_version_check")
    shell = task["ansible.builtin.shell"]

    assert "status" in shell
    assert 'status == "200"' in shell
    assert "nginx\\/[0-9]+(\\.[0-9]+)+" in shell
    assert "tolower(line)" in shell
    assert "sub(/\\r$/, \"\", line)" in shell


def test_multiline_success_is_valid_but_missing_or_fail_line_is_not():
    assert strict_results_ok([{"rc": 0, "stdout": "config line\nOK\n"}], 1)
    assert not strict_results_ok([{"rc": 0, "stdout": "config line\n"}], 1)
    assert not strict_results_ok([{"rc": 0, "stdout": "OK\nFAIL\n"}], 1)
    assert not strict_results_ok([{"rc": 1, "stdout": "OK\n"}], 1)
    assert not strict_results_ok([], 1)
    assert strict_results_ok([], 0)


def test_skipped_results_do_not_count_but_missing_expected_execution_fails():
    assert strict_results_ok([{"skipped": False, "rc": 0, "stdout": "OK"}], 1)
    assert strict_results_ok([
        {"skipped": True, "stdout": "", "rc": 0},
        {"skipped": False, "rc": 0, "stdout": "diagnostic\nOK\n"},
    ], 1)
    assert not strict_results_ok([{"skipped": False, "rc": 1, "stdout": "OK\n"}], 1)
    assert not strict_results_ok([{"skipped": True, "stdout": ""}], 1)


def test_consolidation_mentions_web_version_failure_and_checks_all_named_registers():
    verify_text = VERIFY.read_text(encoding="utf-8")
    for result_var in (
        "_mqtt_results", "_db_results", "_ssh_results", "_web_results",
        "_redis_results", "_modbus_results",
    ):
        assert result_var in verify_text
    assert "_web_version_results" in verify_text
    assert "Web HTTP/nginx version" in verify_text
    consolidation = next(t["ansible.builtin.set_fact"] for t in tasks(VERIFY)
        if t.get("name") == "Évaluer les résultats — consolider les checks OK/FAIL")
    for role in ("mqtt", "db", "ssh", "web", "redis", "modbus"):
        assert "'FAIL' not in" not in consolidation[f"_check_{role}_ok"]


@pytest.mark.parametrize("headers,returncode,expected", [
    ("HTTP/1.1 200 OK\r\nServer: nginx/1.22.1\r\n\r\n", 0, "OK"),
    ("HTTP/1.1 200 OK\r\nsErVeR: nginx/1.26.2\r\n\r\n", 0, "OK"),
    ("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 0, "FAIL"),
    ("HTTP/1.1 301 Moved\r\nServer: nginx/1.22.1\r\n\r\n", 0, "FAIL"),
    ("HTTP/1.1 404 Not Found\r\nServer: nginx/1.22.1\r\n\r\n", 0, "FAIL"),
    ("HTTP/1.1 200 OK\r\nServer: nginx/unknown\r\n\r\n", 0, "FAIL"),
    ("", 0, "FAIL"),
    ("HTTP/1.1 100 Continue\r\nServer: nginx/1.22.1\r\n\r\nHTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n", 0, "FAIL"),
    ("HTTP/1.1 200 OK\r\nServer: nginx/1.22.1\r\n\r\n", 28, "FAIL"),
])
def test_real_shell_requires_response_from_expected_target(headers, returncode, expected):
    shell = task_registered_as(VERIFY, "web_version_check")["ansible.builtin.shell"]
    rendered = render(shell, {"item": {"ip": "192.0.2.44"}})
    mock = '''curl() {
      found=0
      for arg in "$@"; do
        case "$arg" in http*) [ "$arg" = "http://192.0.2.44/" ] || return 97; found=1;; esac
      done
      [ "$found" = 1 ] || return 98
      printf '%s' "$MOCK_HEADERS"
      return "$MOCK_RC"
    }
    '''
    result = subprocess.run(["bash", "-c", mock + rendered], capture_output=True, text=True,
        timeout=5, env={**os.environ, "MOCK_HEADERS": headers, "MOCK_RC": str(returncode)})
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


@pytest.mark.parametrize("role,key,filtered", [
    ("mqtt_broker", "mqtt", True), ("ssh_server", "ssh", True),
    ("web_server", "web", True), ("db_server_v2", "redis", True),
    ("db_server", "db", False), ("modbus_server", "modbus", False),
])
def test_actual_expected_population_matches_role_and_security_profile(role, key, filtered):
    preparation = next(t["ansible.builtin.set_fact"] for t in tasks(VERIFY)
        if t.get("name") == "Préparer les résultats des checks vulnérables")
    services = [{"role": role}, {"role": role, "security_profile": "vulnerable"},
        {"role": role, "security_profile": "hardened"}, {"role": "unrelated"}]
    values = {"scenario_id": "1", "benchmark_scenarios": {"1": {"services": services}}}
    assert render(preparation[f"_{key}_expected"], values) == (2 if filtered else 3)


@pytest.mark.parametrize("key", ["mqtt", "db", "ssh", "web", "redis", "modbus"])
@pytest.mark.parametrize("results,expected,valid", [
    ([{"rc": 0, "stdout": "active\nOK"}], 1, True),
    ([{"rc": 0, "stdout": "OK\nFAIL"}], 1, False),
    ([{"rc": 1, "stdout": "OK"}], 1, False),
    ([{"rc": 0, "stdout": "NOT OK"}], 1, False),
    ([], 1, False), ([], 0, True),
    ([{"rc": 0, "stdout": "OK"}], 2, False),
])
def test_each_production_role_expression_requires_all_positive_results(key, results, expected, valid):
    consolidation = next(t["ansible.builtin.set_fact"] for t in tasks(VERIFY)
        if t.get("name") == "Évaluer les résultats — consolider les checks OK/FAIL")
    values = {f"_{key}_expected": expected, f"_{key}_results": results,
        "_web_version_results": results}
    assert render(consolidation[f"_check_{key}_ok"], values) is valid
