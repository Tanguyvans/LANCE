"""Run the production fact tasks with real Ansible, without hosts or probes."""
import copy
import os
from pathlib import Path
import shutil
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "benchmarks/ansible/playbooks/06_verify.yml"
REGISTERS = {
    "mqtt_conn_check": "mqtt", "db_nopass_check": "db",
    "ssh_creds_check": "ssh", "web_listing_check": "web",
    "web_version_check": "web_version", "redis_ping_check": "redis",
    "modbus_svc_check": "modbus",
}
ROLES = ["mqtt_broker", "db_server", "ssh_server", "web_server", "db_server_v2", "modbus_server"]


def test_preflight_fact_tasks_with_real_ansible(tmp_path):
    executable = shutil.which("ansible-playbook")
    if not executable:
        if os.environ.get("CI"):
            pytest.fail("CI must install ansible-core to exercise the preflight runtime")
        pytest.skip("ansible-playbook is not installed")

    production = yaml.safe_load(VERIFY.read_text())[0]["tasks"]
    names = {
        "Préparer les résultats des checks vulnérables",
        "Évaluer les résultats — consolider les checks OK/FAIL",
        "Calculer le statut global de vérification",
    }
    fact_tasks = [task for task in production if task.get("name") in names]
    assert len(fact_tasks) == 3
    assert all("ansible.builtin.set_fact" in task for task in fact_tasks)
    # These are the real preparation and verdict tasks. No deployment,
    # command, shell, remote host or service probe is ever included.
    cases = [
        ("missing_skipped", [{"rc": 0, "stdout": "active\nOK", "marker": "keep"},
                              {"skipped": True}], True, 1),
        ("explicit_false", [{"rc": 0, "stdout": "OK", "skipped": False},
                             {"skipped": True}], True, 1),
        ("both_success_shapes", [{"rc": 0, "stdout": "OK"},
                                 {"rc": 0, "stdout": "OK", "skipped": False},
                                 {"skipped": True}], True, 2),
        ("only_skipped", [{"skipped": True}], False, 1),
        ("missing_execution", [], False, 1),
        ("tool_failed", [{"rc": 1, "stdout": "OK"}], False, 1),
        ("negative_line", [{"rc": 0, "stdout": "OK\nFAIL"}], False, 1),
        ("empty_output", [{"rc": 0, "stdout": ""}], False, 1),
        ("missing_register_results", None, False, 1),
        ("missing_register", None, False, 1),
        ("absent_roles", [], True, 0),
    ]
    blocks = []
    for name, results, expected, population in cases:
        variables = {
            "scenario_id": "1", "source_scenario_id": "1",
            "benchmark_scenarios": {"1": {"router_vulns": [], "services": [
                {"role": role} for role in ROLES for _ in range(population)
            ]}},
            **{register: {"results": results} if results is not None else {}
               for register in REGISTERS},
        }
        executed = [row for row in (results or []) if row.get("skipped") is not True]
        variables["expected_rows"] = executed
        variables["expected_verdict"] = expected
        if name == "missing_register":
            for register in REGISTERS:
                variables.pop(register)
        blocks.append({"name": name, "vars": variables, "block": [
            *copy.deepcopy(fact_tasks),
            {"ansible.builtin.assert": {"that": [
                "_verify_all_ok == expected_verdict",
                *[f"_check_{key}_ok == expected_verdict" for key in REGISTERS.values()
                  if key != "web_version"],
                *[f"_{key}_results == expected_rows" for key in REGISTERS.values()],
            ]}},
        ]})

    playbook = tmp_path / "preflight-runtime.yml"
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    playbook.write_text(yaml.safe_dump([{
        "name": "Local preflight regression", "hosts": "localhost",
        "connection": "local", "gather_facts": False, "tasks": blocks,
    }], allow_unicode=True, sort_keys=False))
    result = subprocess.run(
        [executable, "-i", "localhost,", str(playbook)], cwd=tmp_path,
        env={**os.environ, "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
             "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"),
             "ANSIBLE_NOCOLOR": "1", "ANSIBLE_CONFIG": str(config)},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
