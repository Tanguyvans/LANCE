"""Offline tests for strict SSH request extraction and credential evidence."""

import pytest

from src.agent.evidence.capabilities import access_supported
from src.agent.evidence.credentials import (
    SSH_CREDENTIAL_POLICY_VERSION,
    known_weak_ssh_credential,
    ssh_request,
)


def record(tool="ssh_exec", **args):
    return {"tool": tool, "args": args}


@pytest.mark.parametrize("tool", ["ssh_exec", "ssh_login"])
def test_structured_request_returns_real_arguments(tool):
    assert ssh_request(record(
        tool, ip="192.0.2.11", user="admin", password="admin", port=2222,
    )) == {"host": "192.0.2.11", "port": 2222, "user": "admin", "password": "admin"}


def test_structured_legacy_fixture_fallbacks_and_missing_password_are_explicit():
    assert ssh_request(record(
        "ssh_exec", host="192.0.2.12", username="operator",
    )) == {"host": "192.0.2.12", "port": 22, "user": "operator", "password": None}
    assert ssh_request(record(
        "ssh_exec", ip="192.0.2.12", user="operator", password="",
    ))["password"] == ""


@pytest.mark.parametrize("command_string,expected", [
    (
        "sshpass -p admin ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null -p 2222 admin@192.0.2.11 'id'",
        {"host": "192.0.2.11", "port": 2222, "user": "admin", "password": "admin"},
    ),
    (
        "sshpass -p '' ssh -o ConnectTimeout=5 root@192.0.2.12 'id'",
        {"host": "192.0.2.12", "port": 22, "user": "root", "password": ""},
    ),
])
def test_legacy_command_string_with_ssh_options_is_supported(command_string, expected):
    assert ssh_request(record("ssh_login", command_string=command_string)) == expected


@pytest.mark.parametrize("args", [
    {"ip": "router.local", "user": "admin", "password": "admin"},
    {"command_string": "sshpass -p admin ssh admin@router.local 'id'"},
    {"command_string": "sshpass -p admin ssh admin@192.0.2.11 id"},
    {"command_string": "sshpass -p admin ssh -p nope admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin sh -c 'ssh admin@192.0.2.11 id'"},
    {"command_string": "sshpass -p $PASSWORD ssh admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o ProxyCommand=nc admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o HostName=192.0.2.99 admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o ProxyJump=bastion admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o User=other admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -p 22 -p 2222 admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o LogLevel=$LEVEL admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o LogLevel=INFO; admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o LogLevel=INFO|nc admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o LogLevel=INFO\\ admin@192.0.2.11 'id'"},
    {"command_string": "sshpass -p admin ssh -o LogLevel=INFO admin@192.0.2.11 \"echo $HOME\""},
    {"command_string": "sshpass -p admin ssh -o LogLevel=INFO admin@192.0.2.11 \"id `date`\""},
])
def test_ambiguous_hostname_or_shell_forms_are_rejected(args):
    assert ssh_request(record("ssh_login", **args)) is None


def test_command_string_has_priority_over_structured_arguments():
    assert ssh_request(record(
        "ssh_login",
        ip="192.0.2.99", user="unique", password="unique-password", port=2200,
        command_string="sshpass -p admin ssh -p 2222 admin@192.0.2.11 'id'",
    )) == {"host": "192.0.2.11", "port": 2222, "user": "admin", "password": "admin"}


def test_identity_helper_does_not_convert_unique_credentials_to_defaults():
    known = record("ssh_exec", ip="192.0.2.11", user="admin", password="admin")
    unique = record("ssh_exec", ip="192.0.2.11", user="operator", password="one-off-secret")

    assert SSH_CREDENTIAL_POLICY_VERSION == "ssh-weak-credentials-v1"
    assert known_weak_ssh_credential(ssh_request(known))
    assert not known_weak_ssh_credential(ssh_request(unique))


@pytest.mark.parametrize("user,password", [
    ("admin", "admin"), ("admin", "password"), ("root", "root"),
    ("admin", "1234"), ("root", "toor"), ("ubnt", "ubnt"), ("pi", "raspberry"),
    ("admin", ""), ("root", ""), ("test", "test"), ("user", "user"),
])
def test_known_weak_pair_alone_is_not_successful_authentication(user, password):
    request = record("ssh_exec", ip="192.0.2.11", user=user, password=password)
    failed = {"tool": "ssh_exec", "args": request["args"], "result": {"return_code": 1}}
    succeeded = {
        "tool": "ssh_exec", "args": request["args"],
        "result": {"return_code": 0, "stdout": "uid=1000(operator)"},
    }

    assert known_weak_ssh_credential(ssh_request(request))
    assert not access_supported(failed)
    assert access_supported(succeeded)


def test_unique_password_is_not_a_known_weak_pair_even_when_prose_is_irrelevant():
    request = record(
        "ssh_login", ip="192.0.2.11", user="admin",
        password="model-mentioned-but-not-policy-password",
    )

    assert not known_weak_ssh_credential(ssh_request(request))
