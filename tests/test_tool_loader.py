"""Tests for YAML tool loader and generated functions."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agent.tools.tool_loader import (
    load_tool_yaml,
    build_input_schema,
    build_subprocess_function,
    load_all_tools,
    register_python_handler,
    filter_unavailable_tools,
    reset_tool_cache,
    DEFINITIONS_DIR,
)


class TestLoadToolYaml:
    """Test YAML parsing and validation."""

    def test_load_nmap(self):
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        assert data["name"] == "nmap_scan"
        assert data["command"] == "nmap"
        assert data["enabled"] is True
        assert len(data["parameters"]) == 5

    def test_load_ssh_audit(self):
        data = load_tool_yaml(DEFINITIONS_DIR / "ssh_audit.yaml")
        assert data["name"] == "ssh_audit"
        assert data["command"] == "ssh-audit"

    def test_load_nvd_lookup_python_handler(self):
        data = load_tool_yaml(DEFINITIONS_DIR / "nvd_lookup.yaml")
        assert data["handler"] == "python"
        assert "command" not in data or data.get("command") is None

    def test_missing_keys_raises(self, tmp_path):
        bad_yaml = tmp_path / "bad.yaml"
        bad_yaml.write_text("name: bad_tool\n")
        with pytest.raises(ValueError, match="missing keys"):
            load_tool_yaml(bad_yaml)


class TestBuildInputSchema:
    """Test JSON Schema generation from YAML parameters."""

    def test_nmap_schema(self):
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        schema = build_input_schema(data)
        assert schema["type"] == "object"
        assert "target" in schema["properties"]
        assert "ports" in schema["properties"]
        assert schema["required"] == ["target"]

    def test_mqtt_schema_has_defaults(self):
        data = load_tool_yaml(DEFINITIONS_DIR / "mqtt_listen.yaml")
        schema = build_input_schema(data)
        assert schema["properties"]["topic"]["default"] == "#"
        assert schema["properties"]["count"]["default"] == 10

    def test_nmap_schema_required_field(self):
        """Nmap target must be required, ports optional."""
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        schema = build_input_schema(data)
        assert "target" in schema["required"]
        assert "ports" not in schema["required"]


class TestBuildSubprocessFunction:
    """Test auto-generated subprocess functions."""

    @patch("src.agent.tools.recon_tools._run")
    def test_nmap_positional(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        fn = build_subprocess_function(data)
        result = fn(target="192.168.88.1")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-T4", "--max-retries=1", "192.168.88.1"]

    @patch("src.agent.tools.recon_tools._run")
    def test_nmap_with_ports(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        fn = build_subprocess_function(data)
        fn(target="192.168.88.1", ports="22,80")
        cmd = mock_run.call_args[0][0]
        assert cmd == [
            "nmap", "-sV", "-T4", "--max-retries=1",
            "-p", "22,80", "192.168.88.1",
        ]

    @patch("src.agent.tools.recon_tools._run")
    def test_curl_positional(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "curl_headers.yaml")
        fn = build_subprocess_function(data)
        fn(url="http://192.168.88.1")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["curl", "-s", "-D", "-", "--max-time", "10", "-L", "http://192.168.88.1"]

    @patch("src.agent.tools.recon_tools._run")
    def test_mqtt_flags_and_defaults(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "mqtt_listen.yaml")
        fn = build_subprocess_function(data)
        fn(broker="192.168.88.100")
        cmd = mock_run.call_args[0][0]
        assert "-h" in cmd
        assert "192.168.88.100" in cmd
        assert "-t" in cmd
        assert "#" in cmd
        assert "-C" in cmd
        assert "10" in cmd

    @patch("src.agent.tools.recon_tools._run")
    def test_ssh_audit_port_suffix(self, mock_run):
        mock_run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "ssh_audit.yaml")
        fn = build_subprocess_function(data)
        fn(host="192.168.88.1")
        cmd = mock_run.call_args[0][0]
        assert "192.168.88.1:22" in cmd

    @patch("src.agent.tools.recon_tools._run")
    def test_function_returns_json(self, mock_run):
        mock_run.return_value = {"stdout": "test", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "nmap.yaml")
        fn = build_subprocess_function(data)
        result = fn(target="192.168.88.1")
        parsed = json.loads(result)
        assert parsed["stdout"] == "test"
        assert parsed["return_code"] == 0

    @patch("src.agent.tools.recon_tools._run")
    def test_ssh_login_accepts_structured_arguments(self, mock_run):
        mock_run.return_value = {"stdout": "uid=1000(admin)", "stderr": "", "return_code": 0}
        data = load_tool_yaml(DEFINITIONS_DIR / "ssh_login.yaml")
        fn = build_subprocess_function(data)

        result = fn(ip="192.0.2.10", user="admin", password="admin", command="id")

        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ["bash", "-c"]
        command = cmd[2]
        assert "UserKnownHostsFile=/dev/null" in command
        assert "admin@192.0.2.10" in command
        assert "id" in command
        assert json.loads(result)["return_code"] == 0

    @patch("src.agent.tools.recon_tools._run")
    def test_reset_tool_cache_prevents_cross_run_mqtt_replay(self, mock_run):
        reset_tool_cache()
        mock_run.side_effect = [
            {"stdout": 'sensors/temp {"temp":1}', "stderr": "", "return_code": 0},
            {"stdout": 'sensors/temp {"temp":999}', "stderr": "", "return_code": 0},
            {"stdout": 'sensors/temp {"temp":999}', "stderr": "", "return_code": 0},
        ]
        definition = load_tool_yaml(DEFINITIONS_DIR / "mqtt_listen.yaml")
        fn = build_subprocess_function(definition)

        first = json.loads(fn(broker="192.0.2.10", topic="sensors/#"))
        replayed = json.loads(fn(broker="192.0.2.10", topic="sensors/#"))
        reset_tool_cache()
        fresh = json.loads(fn(broker="192.0.2.10", topic="sensors/#"))

        assert first["stdout"] == 'sensors/temp {"temp":1}'
        assert replayed["stdout"] == first["stdout"]
        assert replayed["cache_replayed"] is True
        assert fresh["stdout"] == 'sensors/temp {"temp":999}'
        assert "cache_replayed" not in fresh
        reset_tool_cache()


class TestLoadAllTools:
    """Test loading all tools from the definitions directory."""

    def test_loads_all_enabled(self):
        tools = load_all_tools()
        names = {t["name"] for t in tools}
        assert "nmap_scan" in names
        assert "ssh_audit" in names
        assert "curl_headers" in names
        assert "mqtt_listen" in names
        assert "nvd_lookup" in names

    def test_all_have_required_fields(self):
        tools = load_all_tools()
        for tool in tools:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool

    def test_python_handler_has_no_function(self):
        tools = load_all_tools()
        nvd = next(t for t in tools if t["name"] == "nvd_lookup")
        assert nvd["function"] is None

    def test_redis_tool_uses_native_handler_and_survives_missing_cli(self):
        definition = load_tool_yaml(DEFINITIONS_DIR / "redis_cmd.yaml")
        assert definition["handler"] == "python"
        assert "command" not in definition

        from src.agent.tools.recon_tools import RECON_TOOLS

        redis_tool = next(tool for tool in RECON_TOOLS if tool["name"] == "redis_cmd")
        assert callable(redis_tool["function"])
        available, unavailable = filter_unavailable_tools([redis_tool])
        assert [tool["name"] for tool in available] == ["redis_cmd"]
        assert "redis_cmd" not in unavailable


class TestRedisHandler:
    def test_redis_handler_sends_resp_and_renders_array(self):
        from src.agent.tools.recon_tools import redis_cmd

        class FakeSocket:
            def __init__(self):
                self.sent = b""

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _timeout):
                pass

            def sendall(self, payload):
                self.sent = payload

            def makefile(self, _mode):
                return io.BytesIO(b"*2\r\n$4\r\nkey1\r\n$4\r\nkey2\r\n")

        fake = FakeSocket()
        with patch(
            "src.agent.tools.recon_tools.socket.create_connection",
            return_value=fake,
        ):
            result = json.loads(redis_cmd("192.0.2.10", command="KEYS *"))

        assert result["return_code"] == 0
        assert result["stdout"] == "key1\nkey2"
        assert fake.sent.startswith(b"*2\r\n$4\r\nKEYS\r\n$1\r\n*\r\n")

    def test_subprocess_tools_have_function(self):
        tools = load_all_tools()
        nmap = next(t for t in tools if t["name"] == "nmap_scan")
        assert nmap["function"] is not None
        assert callable(nmap["function"])

    def test_disabled_tool_skipped(self, tmp_path):
        yaml_content = (
            "name: test_disabled\n"
            "command: echo\n"
            "enabled: false\n"
            "description: test\n"
            "parameters:\n"
            "  - name: msg\n"
            "    type: string\n"
            "    description: message\n"
            "    required: true\n"
        )
        (tmp_path / "disabled.yaml").write_text(yaml_content)
        tools = load_all_tools(tmp_path)
        assert len(tools) == 0

    def test_empty_directory(self, tmp_path):
        tools = load_all_tools(tmp_path)
        assert tools == []


class TestFilterUnavailableTools:
    def test_filters_missing_command_and_python_module(self):
        tools = [
            {"name": "present", "command": "sh"},
            {"name": "missing", "command": "not-installed-lance-tool"},
            {"name": "module-missing", "requires_modules": ("not_a_real_lance_module",)},
        ]

        filtered, unavailable = filter_unavailable_tools(tools)

        assert [tool["name"] for tool in filtered] == ["present"]
        assert unavailable == {
            "missing": "missing_command:not-installed-lance-tool",
            "module-missing": "missing_python_module:not_a_real_lance_module",
        }


class TestRegisterPythonHandler:
    """Test attaching Python functions to YAML-defined tools."""

    def test_register_existing(self):
        tools = load_all_tools()
        dummy = lambda query: "test"  # noqa: E731
        register_python_handler(tools, "nvd_lookup", dummy)
        nvd = next(t for t in tools if t["name"] == "nvd_lookup")
        assert nvd["function"] is dummy

    def test_register_unknown_raises(self):
        tools = load_all_tools()
        with pytest.raises(KeyError, match="nonexistent"):
            register_python_handler(tools, "nonexistent", lambda: None)


class TestExpectedTools:
    """Verify all expected tools are present in YAML definitions."""

    def test_tool_count(self):
        tools = load_all_tools()
        assert len(tools) == 42

    def test_expected_names(self):
        names = {t["name"] for t in load_all_tools()}
        expected_sw = {
            "nmap_scan", "nmap_discovery", "arp_scan", "ssh_audit",
            "curl_headers", "mqtt_listen", "nvd_lookup", "modbus_scan",
            "traceroute",
        }
        expected_exploit = {
            "ssh_login", "ssh_exec", "mysql_query", "telnet_connect",
            "ftp_list", "http_get", "redis_cmd", "try_credential",
            "modbus_write",
        }
        expected_hw = {"hackrf_capture", "flipper_zero", "exploit_iot_kit", "proxmark3"}
        # New offensive/recon tools added by the agent-tools-expansion PR.
        expected_new_offensive = {
            "sqlmap", "gobuster_dir", "whatweb", "nuclei_scan",
            "nikto_scan", "wpscan", "searchsploit", "dig_query",
            "smbclient_list", "enum4linux", "nxc_validate",
            "openssl_inspect", "ysoserial_payload",
        }
        expected_new_python = {
            "python_exec", "http_request", "tcp_send", "udp_send", "mtls_request",
            "tls_inspect", "decode_value",
        }
        expected = (
            expected_sw | expected_exploit | expected_hw
            | expected_new_offensive | expected_new_python
        )
        assert names == expected

    def test_hardware_tools_flagged(self):
        tools = load_all_tools()
        hw_tools = [t for t in tools if t.get("hardware")]
        assert len(hw_tools) == 4
        hw_names = {t["name"] for t in hw_tools}
        assert hw_names == {"hackrf_capture", "flipper_zero", "exploit_iot_kit", "proxmark3"}

    def test_hardware_tools_have_function(self):
        tools = load_all_tools()
        for t in tools:
            if t.get("hardware"):
                assert t["function"] is not None
                assert callable(t["function"])
