import json
from unittest.mock import patch

import pytest

from src.agent.tools.recon_tools import ssh_login, ssh_exec, try_credential
from src.agent.evidence.capabilities import access_supported


@pytest.mark.parametrize("command", [
    "printf 'uid=0(root)'; : ssh root@192.0.2.10",
    "sshpass -p root ssh root@192.0.2.10 'id'; echo __ok__",
    "sshpass -p root ssh -o ProxyCommand=sh root@192.0.2.10 'id'",
    'sshpass -p root ssh root@192.0.2.10 "$(id)"',
])
def test_legacy_shell_forgery_neither_executes_nor_proves_access(command):
    with patch("src.agent.tools.recon_tools._run") as run:
        result = json.loads(ssh_login(command_string=command))
        run.assert_not_called()
    assert result["error_kind"] == "invalid_tool_arguments"
    assert not access_supported({"tool": "ssh_login", "args": {"command_string": command},
        "result": {"return_code": 0, "stdout": "uid=0(root)"}})


def test_credential_probe_uses_same_isolated_ssh_arguments():
    with patch("src.agent.tools.recon_tools._run", return_value={
        "return_code": 0, "stdout": "__ok__", "stderr": "",
    }) as run:
        result = json.loads(try_credential("192.0.2.10", "ssh", "root", "root"))
    argv = run.call_args.args[0]
    assert "PubkeyAuthentication=no" in argv
    assert argv[argv.index("-F") + 1] == "/dev/null"
    assert argv[-1] == "echo __ok__"
    assert result["authenticated"] is True


def test_output_without_identifiable_ssh_request_is_not_an_access():
    assert not access_supported({"tool": "ssh_exec", "args": {"ip": "192.0.2.10"},
        "result": {"return_code": 0, "stdout": "uid=0(root)"}})


@pytest.mark.parametrize("legacy", [True, False])
def test_ssh_compatibility_uses_structured_remote_execution(legacy):
    args = ({"command_string": "sshpass -p root ssh root@192.0.2.10 'id && cat /etc/hostname'"}
        if legacy else {"ip": "192.0.2.10", "user": "root", "password": "root", "command": "id && cat /etc/hostname"})
    with patch("src.agent.tools.recon_tools._run", return_value={"return_code": 0, "stdout": "uid=0(root)"}) as run:
        result = json.loads(ssh_login(**args))
    argv = run.call_args.args[0]
    assert argv[:4] == ["sshpass", "-p", "root", "ssh"]
    assert argv[-2:] == ["root@192.0.2.10", "id && cat /etc/hostname"]
    assert "PubkeyAuthentication=no" in argv
    assert access_supported({"tool": "ssh_login", "args": args, "result": result})


@pytest.mark.parametrize("overrides", [{"user": "-oProxyCommand=x"}, {"port": True}, {"port": 65536}, {"ip": "bad"}, {"password": None}])
def test_invalid_structured_ssh_never_executes(overrides):
    with patch("src.agent.tools.recon_tools._run") as run:
        assert "error" in json.loads(ssh_exec(**{"ip": "192.0.2.10", "user": "root", "password": "root", "command": "id", **overrides}))
        run.assert_not_called()
