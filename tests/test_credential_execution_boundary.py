"""Credentials stay literal data; authentication requires observed success."""
import json
import os
import shutil
import subprocess
import io
import sys
from threading import Event
from unittest.mock import Mock

import pytest

from src.agent.tools import recon_tools
from src.agent.tools.runtime import tool_stop_context


@pytest.mark.parametrize("service", ["telnet", "redis"])
def test_credentials_are_literal_input_to_a_constant_program(tmp_path, monkeypatch, service):
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash unavailable")
    # Local stand-ins consume stdin only: neither sleep nor nc reaches a network.
    nc = tmp_path / "nc"
    nc.write_text('#!/bin/sh\n/bin/cat\n', encoding="utf-8")
    nc.chmod(0o755)
    sleep = tmp_path / "sleep"
    sleep.write_text('#!/bin/sh\nexit 0\n', encoding="utf-8")
    sleep.chmod(0o755)
    marker = tmp_path / "must-not-exist"
    password = f"review'$(touch {marker})'`printf marker`\\password"
    user = "operator'$(printf user-marker)'"
    executed = []

    def local_run(cmd, timeout, **kwargs):
        executed.append(cmd)
        process = subprocess.run(
            [bash, *cmd[1:]] if cmd[0] == "bash" else [str(nc), *cmd[1:]],
            input=kwargs.get("input_data"), capture_output=True, text=True,
            timeout=timeout, env={**os.environ, "PATH": str(tmp_path)},
        )
        return {"stdout": process.stdout, "stderr": process.stderr, "return_code": process.returncode}

    monkeypatch.setattr(recon_tools, "_run", local_run)
    result = json.loads(recon_tools.try_credential("192.0.2.10", service, user, password))
    if service == "telnet":
        assert result["stdout"] == f"{user}\n{password}\nid\n"
    else:
        # subprocess text decoding converts CRLF to LF, so assert the
        # transport payload separately in the RESP regression below.
        assert password in result["stdout"]
    assert not marker.exists()
    assert password not in executed[0][2]
    assert result["authenticated"] is False


@pytest.mark.parametrize("password", ["two words", "élève🔑", "line1\r\nPING\r\nline2", "quote'$(printf marker)"])
def test_redis_password_remains_one_resp_argument(monkeypatch, password):
    runner = Mock(return_value={"stdout": "+OK\r\n+PONG\r\n", "return_code": 0})
    monkeypatch.setattr(recon_tools, "_run", runner)
    result = json.loads(recon_tools.try_credential("192.0.2.10", "redis", "admin", password))
    command = runner.call_args.args[0]
    assert command == ["nc", "-w", "5", "192.0.2.10", "6379"]
    wire = runner.call_args.kwargs["input_data"].encode("utf-8")
    stream = io.BytesIO(wire)
    assert recon_tools._redis_read_response(stream) == ["AUTH", password]
    assert recon_tools._redis_read_response(stream) == ["PING"]
    assert recon_tools._redis_read_response(stream) == ["KEYS", "*"]
    assert stream.read() == b""
    assert result["authenticated"] is True


@pytest.mark.parametrize("cooperative", [False, True])
def test_command_runner_preserves_stdin_bytes_in_both_execution_paths(cooperative):
    payload = "*2\r\n$4\r\nAUTH\r\n$4\r\nclé\r\n"
    # The child only encodes stdin bytes as hex; no credential can become code.
    command = [sys.executable, "-c", "import sys; print(sys.stdin.buffer.read().hex())"]
    with tool_stop_context(Event() if cooperative else None):
        result = recon_tools._run(command, timeout=5, input_data=payload)
    assert result["return_code"] == 0
    assert result["stdout"].strip() == payload.encode("utf-8").hex()


@pytest.mark.parametrize("anonymous,authenticated,rc,expected", [
    ("401", "200", 0, True), ("403", "204", 0, True),
    ("401", "500", 0, False), ("401", "302", 0, False),
    ("401", "404", 0, False), ("401", "200", 1, False),
    ("200", "200", 0, False), ("401", "000", 0, False),
    ("500", "500", 0, False),
])
def test_http_credential_requires_successful_authenticated_response(monkeypatch, anonymous, authenticated, rc, expected):
    monkeypatch.setattr(recon_tools, "_run", Mock(side_effect=[
        {"stdout": anonymous, "return_code": 0},
        {"stdout": authenticated, "return_code": rc},
    ]))
    result = json.loads(recon_tools.try_credential("192.0.2.10", "http", "admin", "fixture"))
    assert result["success"] is expected
    assert result["authenticated"] is expected
    assert result["anonymous_access"] is (anonymous == "200")


@pytest.mark.parametrize("service,stdout,rc,expected", [
    ("telnet", "Welcome #", 0, False),
    ("telnet", "uid=1000(operator)", 0, True),
    ("telnet", "uid=0(root)", 1, False),
    ("redis", "-WRONGPASS invalid credentials\r\n+PONG\r\n", 0, False),
    ("redis", "+PONG\r\n", 0, False),
    ("redis", "+OK\r\n+PONG\r\n", 0, True),
])
def test_credential_flags_require_authentication_evidence(monkeypatch, service, stdout, rc, expected):
    monkeypatch.setattr(recon_tools, "_run", Mock(return_value={"stdout": stdout, "return_code": rc}))
    result = json.loads(recon_tools.try_credential("192.0.2.10", service, "admin", "fixture"))
    assert result["success"] is expected
    assert result["authenticated"] is expected
