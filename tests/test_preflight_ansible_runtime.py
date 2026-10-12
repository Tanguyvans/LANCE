"""Run the production fact tasks with real Ansible, without hosts or probes."""
import copy
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "benchmarks/ansible/playbooks/06_verify.yml"
REGISTERS = {
    "mqtt_conn_check": "mqtt", "db_nopass_check": "db",
    "ssh_creds_check": "ssh", "web_listing_check": "web",
    "web_version_check": "web_version", "redis_ping_check": "redis",
    "modbus_svc_check": "modbus",
    "nodered_port_check": "nodered", "nodered_admin_check": "nodered_admin",
}
ROLES = ["mqtt_broker", "db_server", "ssh_server", "web_server", "db_server_v2", "modbus_server", "nodered_server"]


@pytest.mark.parametrize("responses,refresh_code,expected", [
    ([b"SSH-2.0-fixture\r\n"], 0, True),
    ([b"", b"SSH-2.0-fixture\r\n"], 0, True),
    ([b"HTTP/1.1 200 OK\r\n"], 0, False),
    (None, 0, False),
    ([b"SSH-2.0-fixture\r\n"], 1, False),
], ids=["ssh_ready", "transient_connection", "wrong_protocol", "port_closed", "refresh_failed"])
def test_router_readiness_uses_runner_tcp_banner_and_blocks_unready_audit(tmp_path, responses, refresh_code, expected):
    executable = shutil.which("ansible-playbook")
    if not executable:
        if os.environ.get("CI"):
            pytest.fail("CI must install ansible-core")
        pytest.skip("ansible-playbook is not installed")
    production = yaml.safe_load(VERIFY.read_text())[0]["tasks"]
    task = copy.deepcopy(next(t for t in production
        if t.get("register") == "router_runner_ssh_ready"))
    refresh = copy.deepcopy(next(t for t in production
        if t.get("register") == "router_runner_neighbor_refresh"))
    assert production.index(refresh) < production.index(task)
    # Exercise the real delegated command without altering any host's ARP
    # cache. Its fixture records the exact target and can simulate failure.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    mock_ip = bin_dir / "ip"
    mock_ip.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$LANCE_TEST_IP_LOG"\nexit "$LANCE_TEST_IP_RC"\n')
    mock_ip.chmod(0o755)
    ip_log = tmp_path / "ip-args"
    refresh["environment"] = {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
        "LANCE_TEST_IP_LOG": str(ip_log), "LANCE_TEST_IP_RC": str(refresh_code)}
    # An unreachable Proxmox host must never be contacted: this prerequisite
    # must execute on the actual controller, using the selected gateway.
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]
    stop = threading.Event()
    connections = []
    if responses is not None:
        server.listen()
        server.settimeout(0.1)
        def serve():
            while not stop.is_set():
                try:
                    client, _ = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                with client:
                    response = responses[min(len(connections), len(responses) - 1)]
                    connections.append(response)
                    client.sendall(response)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
    else:
        server.close()
    # Use an ephemeral fixture port and shorten only the production deadline.
    task["ansible.builtin.wait_for"].update(port=port, timeout=4 if expected else 1, sleep=1)
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    inventory = tmp_path / "inventory"
    inventory.write_text("proxmox ansible_host=192.0.2.100 ansible_connection=ssh\n")
    playbook = tmp_path / "router-ready.yml"
    playbook.write_text(yaml.safe_dump([{
        "hosts": "proxmox", "gather_facts": False,
        "vars": {"benchmark_gateway": "127.0.0.1"}, "tasks": [refresh, task],
    }], allow_unicode=True, sort_keys=False))
    try:
        result = subprocess.run([executable, "-i", str(inventory), str(playbook)],
            cwd=tmp_path, env={**os.environ, "ANSIBLE_CONFIG": str(config),
                "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
                "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"), "ANSIBLE_NOCOLOR": "1"},
            capture_output=True, text=True, timeout=20)
        assert (result.returncode == 0) is expected, result.stdout + result.stderr
        assert "proxmox -> localhost" in result.stdout
        assert ip_log.read_text().splitlines() == ["neigh", "flush", "to", "127.0.0.1"]
        if refresh_code:
            assert not connections  # Do not start the probe after a failed refresh.
        elif responses is not None:
            assert connections
        if expected and len(responses) > 1:
            assert len(connections) >= 2
    finally:
        stop.set()
        server.close()
        if responses is not None:
            worker.join(timeout=2)


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
                  if key not in {"web_version", "nodered_admin"}],
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


def test_suid_preflight_runtime_requires_behavior_not_mode_bits(tmp_path):
    executable = shutil.which("ansible-playbook")
    if not executable:
        if os.environ.get("CI"):
            pytest.fail("CI must install ansible-core")
        pytest.skip("ansible-playbook is not installed")
    production = yaml.safe_load(VERIFY.read_text())[0]["tasks"]
    names = {
        "Préparer les résultats des checks vulnérables",
        "Évaluer les résultats — consolider les checks OK/FAIL",
        "Calculer le statut global de vérification",
    }
    facts = [task for task in production if task.get("name") in names]
    assert len(facts) == 3
    assert all("ansible.builtin.set_fact" in task for task in facts)
    blocks = []
    for name, results, expected in [
        ("privileged_read", [{"rc": 0, "stdout": "OK"}], True),
        ("explicit_not_skipped", [{"rc": 0, "stdout": "OK", "skipped": False}], True),
        ("mode_bits_only", [{"rc": 0, "stdout": "4755"}], False),
        ("read_failed", [{"rc": 1, "stdout": "OK"}], False),
        ("missing_read", [], False),
        ("contradicted", [{"rc": 0, "stdout": "OK\nFAIL"}], False),
    ]:
        blocks.append({"name": name, "vars": {
            "scenario_id": "7", "source_scenario_id": "7",
            "benchmark_scenarios": {"7": {"router_vulns": [],
                "services": [{"role": "ssh_server"}]}},
            "ssh_creds_check": {"results": [{"rc": 0, "stdout": "OK"}]},
            "privesc_behavior_check": {"results": results},
            "expected_verdict": expected,
        }, "block": [*copy.deepcopy(facts), {"ansible.builtin.assert": {"that": [
            "_privesc_expected == 1", "_check_privesc_ok == expected_verdict",
            "_verify_all_ok == expected_verdict", "_check_ssh_ok",
        ]}}]})
    playbook = tmp_path / "suid-preflight-runtime.yml"
    config = tmp_path / "ansible.cfg"
    config.write_text("[defaults]\n")
    playbook.write_text(yaml.safe_dump([{
        "hosts": "localhost", "connection": "local", "gather_facts": False,
        "tasks": blocks,
    }], allow_unicode=True, sort_keys=False))
    result = subprocess.run([executable, "-i", "localhost,", str(playbook)],
        cwd=tmp_path, env={**os.environ, "ANSIBLE_CONFIG": str(config),
            "ANSIBLE_LOCAL_TEMP": str(tmp_path / "local"),
            "ANSIBLE_REMOTE_TEMP": str(tmp_path / "remote"), "ANSIBLE_NOCOLOR": "1"},
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
