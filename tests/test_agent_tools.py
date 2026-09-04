"""Tests for Phase 4.1 agent tools, provider, and orchestrator."""

import json
import sys
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from src.agent.tools.recon_tools import (
    _run,
    nvd_lookup,
    RECON_TOOLS,
)
from src.agent.tools.graph_tools import GRAPH_TOOLS
from src.agent.provider import LLMProvider
from src.agent.cost_tracker import CostTracker


# ------------------------------------------------------------------
# Helper: get tool function by name from RECON_TOOLS
# ------------------------------------------------------------------

def _get_tool_fn(name: str):
    """Get a tool's callable function from RECON_TOOLS by name."""
    for t in RECON_TOOLS:
        if t["name"] == name:
            return t["function"]
    raise KeyError(f"Tool {name!r} not found in RECON_TOOLS")


# ------------------------------------------------------------------
# Recon tools (mocked subprocess)
# ------------------------------------------------------------------

class TestReconTools:
    """Test recon tools with mocked subprocess calls."""

    @patch("src.agent.tools.recon_tools._run")
    def test_nmap_scan_basic(self, mock_run):
        mock_run.return_value = {"stdout": "22/tcp open ssh\n80/tcp open http\n", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("nmap_scan")
        result = json.loads(fn(target="192.168.88.1"))
        assert result["return_code"] == 0
        assert "22/tcp" in result["stdout"]
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["nmap", "-sV", "-T4", "--max-retries=1", "192.168.88.1"]

    @patch("src.agent.tools.recon_tools._run")
    def test_nmap_scan_with_ports(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("nmap_scan")
        fn(target="192.168.88.1", ports="22,80")
        cmd = mock_run.call_args[0][0]
        assert cmd == [
            "nmap", "-sV", "-T4", "--max-retries=1",
            "-p", "22,80", "192.168.88.1",
        ]

    @patch("src.agent.tools.recon_tools._run")
    def test_ssh_audit(self, mock_run):
        mock_run.return_value = {"stdout": "(gen) banner: SSH-2.0-OpenSSH_10.0\n", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("ssh_audit")
        result = json.loads(fn(host="192.168.88.247"))
        assert result["return_code"] == 0
        cmd = mock_run.call_args[0][0]
        assert cmd == ["ssh-audit", "192.168.88.247:22"]

    @patch("src.agent.tools.recon_tools._run")
    def test_ssh_audit_custom_port(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("ssh_audit")
        fn(host="192.168.88.231", port=2222)
        cmd = mock_run.call_args[0][0]
        assert cmd == ["ssh-audit", "192.168.88.231:2222"]

    @patch("src.agent.tools.recon_tools._run")
    def test_curl_headers(self, mock_run):
        mock_run.return_value = {"stdout": "HTTP/1.1 200 OK\nServer: nginx/1.19.6\n", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("curl_headers")
        result = json.loads(fn(url="http://192.168.88.231"))
        assert result["return_code"] == 0
        assert "nginx" in result["stdout"]
        cmd = mock_run.call_args[0][0]
        assert cmd == ["curl", "-s", "-D", "-", "--max-time", "10", "-L", "http://192.168.88.231"]

    @patch("src.agent.tools.recon_tools._run")
    def test_mqtt_listen(self, mock_run):
        mock_run.return_value = {"stdout": "sensor/temp 23.5\n", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("mqtt_listen")
        result = json.loads(fn(broker="192.168.88.247"))
        assert result["return_code"] == 0
        cmd = mock_run.call_args[0][0]
        assert "-h" in cmd
        assert "192.168.88.247" in cmd
        assert "-t" in cmd
        assert "#" in cmd
        assert "-C" in cmd
        assert "10" in cmd
        assert "-W" in cmd
        assert "5" in cmd

    @patch("src.agent.tools.recon_tools._run")
    def test_mqtt_listen_custom(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": "", "return_code": 0}
        fn = _get_tool_fn("mqtt_listen")
        fn(broker="192.168.88.231", topic="sensor/#", count=5, timeout=3)
        cmd = mock_run.call_args[0][0]
        assert "-h" in cmd
        assert "192.168.88.231" in cmd
        assert "-t" in cmd
        assert "sensor/#" in cmd
        assert "-C" in cmd
        assert "5" in cmd
        assert "-W" in cmd
        assert "3" in cmd

    def test_run_timeout(self):
        """Test that _run handles timeout gracefully."""
        with patch("src.agent.tools.recon_tools.subprocess.run") as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["nmap"], timeout=120)
            result = _run(["nmap", "-sV", "192.168.88.0/24"], timeout=120)
            assert result["return_code"] == -1
            assert "timed out" in result["stderr"]

    def test_run_command_not_found(self):
        """Test that _run handles missing commands gracefully."""
        with patch("src.agent.tools.recon_tools.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError()
            result = _run(["nonexistent_tool"], timeout=10)
            assert result["return_code"] == -1
            assert "not found" in result["stderr"]

    def test_run_cancels_cooperatively_when_run_stop_is_requested(self):
        from src.agent.tools.runtime import tool_stop_context

        stop_event = threading.Event()

        def request_stop():
            time.sleep(0.1)
            stop_event.set()

        stopper = threading.Thread(target=request_stop)
        stopper.start()
        started = time.monotonic()
        with tool_stop_context(stop_event):
            result = _run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=60)
        stopper.join()

        assert result["return_code"] == -2
        assert result["cancelled"] is True
        assert time.monotonic() - started < 5

    def test_recon_tools_definitions(self):
        """Verify all recon tools have the required fields."""
        for tool in RECON_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])

    def test_nvd_lookup_in_recon_tools(self):
        """Verify nvd_lookup is registered in RECON_TOOLS."""
        names = {t["name"] for t in RECON_TOOLS}
        assert "nvd_lookup" in names

    @patch("src.agent.tools.recon_tools.query_nvd")
    def test_nvd_lookup_returns_cves(self, mock_query):
        from src.cve_lookup import CVEResult
        mock_query.return_value = [
            CVEResult(
                cve_id="CVE-2023-12345",
                description="Test vulnerability in Mosquitto",
                cvss_score=7.5,
                severity="HIGH",
                attack_vector="NETWORK",
            ),
            CVEResult(
                cve_id="CVE-2023-67890",
                description="Another vuln",
                cvss_score=5.0,
                severity="MEDIUM",
                attack_vector="LOCAL",
            ),
        ]
        result = json.loads(nvd_lookup("cpe:2.3:a:eclipse:mosquitto:2.0.11:*:*:*:*:*:*:*"))
        assert len(result) == 2
        assert result[0]["cve_id"] == "CVE-2023-12345"
        assert result[0]["cvss_score"] == 7.5
        assert result[1]["severity"] == "MEDIUM"
        mock_query.assert_called_once()

    @patch("src.agent.tools.recon_tools.query_nvd")
    def test_nvd_lookup_handles_error(self, mock_query):
        mock_query.side_effect = Exception("NVD API timeout")
        result = json.loads(nvd_lookup("bad query"))
        assert "error" in result
        assert "NVD API timeout" in result["error"]


# ------------------------------------------------------------------
# New offensive/recon tools (agent-tools-expansion PR)
# ------------------------------------------------------------------

class TestNewToolsLoaded:
    """Each new tool YAML must load and produce a callable function entry."""

    NEW_TOOL_NAMES = (
        "sqlmap", "gobuster_dir", "whatweb", "nuclei_scan",
        "nikto_scan", "wpscan", "searchsploit", "dig_query",
        "smbclient_list", "enum4linux", "nxc_validate",
        "openssl_inspect", "ysoserial_payload",
        "python_exec", "http_request", "tcp_send",
        "tls_inspect", "decode_value",
    )

    @pytest.mark.parametrize("name", NEW_TOOL_NAMES)
    def test_tool_is_registered(self, name):
        from src.agent.tools.recon_tools import RECON_TOOLS
        tool = next((t for t in RECON_TOOLS if t["name"] == name), None)
        assert tool is not None, f"{name} not registered in RECON_TOOLS"
        assert tool["function"] is not None, f"{name} has no callable function"
        assert callable(tool["function"])
        # JSON schema sanity
        schema = tool["input_schema"]
        assert schema["type"] == "object"
        assert "properties" in schema


class TestPythonExec:
    def test_runs_simple_script_and_returns_stdout(self):
        from src.agent.tools.recon_tools import python_exec
        out = json.loads(python_exec("print('hello-world')"))
        assert out["return_code"] == 0
        assert "hello-world" in out["stdout"]
        assert out["timed_out"] is False

    def test_times_out_on_long_running_script(self):
        from src.agent.tools.recon_tools import python_exec
        out = json.loads(python_exec("import time\ntime.sleep(5)", timeout=1))
        assert out["timed_out"] is True
        assert out["return_code"] == -1

    def test_captures_stderr_and_nonzero_rc(self):
        from src.agent.tools.recon_tools import python_exec
        out = json.loads(python_exec("import sys; sys.stderr.write('boom\\n'); sys.exit(2)"))
        assert out["return_code"] == 2
        assert "boom" in out["stderr"]


class TestHttpRequest:
    def test_returns_json_with_status_and_body_on_local_listener(self):
        import http.server
        import socketserver
        import threading
        from src.agent.tools.recon_tools import http_request

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("X-Test", "yes")
                self.end_headers()
                self.wfile.write(b"hello-http")

            def log_message(self, *args, **kwargs):
                pass

        try:
            server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        except PermissionError:
            pytest.skip("local socket listeners are disabled by this sandbox")
        with server:
            port = server.server_address[1]
            t = threading.Thread(target=server.handle_request, daemon=True)
            t.start()
            out = json.loads(http_request(f"http://127.0.0.1:{port}/", timeout=5))
            t.join(timeout=5)
        assert out["status_code"] == 200
        assert "hello-http" in out["body"]
        assert out["headers"].get("X-Test") == "yes"


class TestTcpSend:
    def test_round_trips_against_local_listener(self):
        import socket as _s
        import threading
        from src.agent.tools.recon_tools import tcp_send

        server = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
        except PermissionError:
            server.close()
            pytest.skip("local socket listeners are disabled by this sandbox")
        server.listen(1)
        host, port = server.getsockname()

        received_payload = {}

        def serve():
            conn, _ = server.accept()
            received_payload["bytes"] = conn.recv(64)
            conn.sendall(b"ACK")
            conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        result = json.loads(tcp_send(host=host, port=port, payload_hex="68656c6c6f", recv_bytes=16, timeout=5))
        t.join(timeout=5)
        server.close()
        assert received_payload.get("bytes") == b"hello"
        assert "ACK" in result["received_ascii"]
        assert result["received_hex"].startswith("41434b")  # "ACK"

    def test_rejects_invalid_hex(self):
        from src.agent.tools.recon_tools import tcp_send
        out = json.loads(tcp_send(host="127.0.0.1", port=1, payload_hex="zzzz"))
        assert "error" in out
        assert "invalid payload_hex" in out["error"]


class TestDecodeValue:
    def test_base64(self):
        from src.agent.tools.recon_tools import decode_value
        out = json.loads(decode_value("aGVsbG8=", "base64"))
        assert out["decoded"] == "hello"

    def test_url(self):
        from src.agent.tools.recon_tools import decode_value
        out = json.loads(decode_value("hello%20world%21", "url"))
        assert out["decoded"] == "hello world!"

    def test_hex(self):
        from src.agent.tools.recon_tools import decode_value
        out = json.loads(decode_value("68656c6c6f", "hex"))
        assert out["decoded"] == "hello"

    def test_jwt_unsigned_payload(self):
        from src.agent.tools.recon_tools import decode_value
        # JWT header {"alg":"none","typ":"JWT"} + payload {"sub":"42","admin":true}
        token = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJzdWIiOiI0MiIsImFkbWluIjp0cnVlfQ."
        )
        out = json.loads(decode_value(token, "jwt"))
        assert out["header"]["alg"] == "none"
        assert out["payload"]["sub"] == "42"
        assert out["payload"]["admin"] is True
        assert out["signature_verified"] is False

    def test_unknown_kind_returns_error(self):
        from src.agent.tools.recon_tools import decode_value
        out = json.loads(decode_value("xxx", "rot13"))
        assert "error" in out


class TestTlsInspect:
    def test_plaintext_endpoint_is_not_a_tool_error(self):
        import ssl as _ssl

        from src.agent.tools.recon_tools import tls_inspect

        context = MagicMock()
        context.wrap_socket.side_effect = _ssl.SSLError(
            "[SSL: WRONG_VERSION_NUMBER] wrong version number"
        )
        with patch(
            "src.agent.tools.recon_tools.ssl.create_default_context",
            return_value=context,
        ), patch(
            "src.agent.tools.recon_tools.socket.create_connection",
            return_value=MagicMock(),
        ):
            out = json.loads(tls_inspect(host="192.0.2.10", port=22))

        assert out["status"] == "not_tls"
        assert out["error_kind"] == "tls_handshake_failed"
        assert "error" not in out

    def test_inspect_self_signed_local_listener(self, tmp_path):
        import ssl as _ssl
        import socket as _s
        import threading
        from src.agent.tools.recon_tools import tls_inspect

        # Generate a temporary self-signed cert via openssl
        import subprocess
        cert_path = tmp_path / "test.pem"
        key_path = tmp_path / "test.key"
        rc = subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", str(key_path), "-out", str(cert_path),
                "-days", "1", "-nodes",
                "-subj", "/CN=localhost",
            ],
            capture_output=True,
        ).returncode
        if rc != 0:
            pytest.skip("openssl not available to generate test cert")

        context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        server = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
        try:
            server.bind(("127.0.0.1", 0))
        except PermissionError:
            server.close()
            pytest.skip("local socket listeners are disabled by this sandbox")
        server.listen(1)
        host, port = server.getsockname()

        def serve():
            conn, _ = server.accept()
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(16)
            except Exception:
                pass
            conn.close()

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        out = json.loads(tls_inspect(host=host, port=port, sni="localhost"))
        t.join(timeout=5)
        server.close()
        # subject is parsed via openssl x509 subprocess; the format is
        # "CN=localhost" (or "CN = localhost" depending on openssl version)
        assert "localhost" in str(out["subject"])
        assert out["cipher"]["name"]
        assert out["fingerprint_sha256"]


# ------------------------------------------------------------------
# Graph tools (mocked backend)
# ------------------------------------------------------------------

class TestGraphTools:
    """Test graph tools with mocked backend."""

    def test_graph_tools_definitions(self):
        """Verify all graph tools have the required fields."""
        for tool in GRAPH_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])

    def test_graph_tool_names(self):
        names = {t["name"] for t in GRAPH_TOOLS}
        expected = {
            "get_network_topology",
            "get_device_info",
            "get_attack_surface",
            "get_attack_paths",
            "get_risk_scores",
            "get_graph_disbalance",
        }
        assert names == expected

    @patch("src.agent.tools.graph_tools._backend")
    def test_get_network_topology(self, mock_backend):
        """Test that get_network_topology returns valid JSON."""
        from src.agent.tools.graph_tools import get_network_topology
        mock_backend.to_dict.return_value = {
            "nodes": [{"id": "test", "name": "Test"}],
            "edges": [],
        }
        # Patch _backend at module level
        with patch("src.agent.tools.graph_tools._backend", mock_backend):
            result = json.loads(get_network_topology())
            assert "nodes" in result
            assert "edges" in result

    def test_loading_lab_context_clears_discovery_and_weighted_state(
        self, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        for name in (
            "_backend", "_infra", "_cve_reports", "_risk_scores", "_attack_report",
            "_scenario_topology", "_discovery_mode", "_weighted_graph",
            "_last_disbalance_report",
        ):
            monkeypatch.setattr(graph_tools, name, getattr(graph_tools, name))
        monkeypatch.setattr(
            graph_tools, "_discovery_mode", {"target_network": "192.0.2.0/24"}
        )
        monkeypatch.setattr(
            graph_tools, "_scenario_topology", {"nodes": [{"id": "old-run"}]}
        )
        monkeypatch.setattr(graph_tools, "_weighted_graph", object())
        monkeypatch.setattr(graph_tools, "_last_disbalance_report", {"epicenter": "old-run"})

        with (
            patch.object(
                graph_tools,
                "load_yaml",
                return_value=MagicMock(devices=[], links=[]),
            ),
            patch.object(graph_tools, "build_graph") as backend,
            patch.object(graph_tools, "load_cpe_mapping", return_value={}),
            patch.object(graph_tools, "scan_all_devices", return_value=[]),
            patch.object(graph_tools, "score_all_devices", return_value=[]),
            patch.object(
                graph_tools, "analyze_attack_paths", return_value=MagicMock()
            ),
        ):
            backend.return_value.get_graph_stats.return_value = {}
            graph_tools.load_lab_context()

        assert graph_tools._discovery_mode is None
        assert graph_tools._scenario_topology is None
        assert graph_tools._weighted_graph is None
        assert graph_tools._last_disbalance_report is None

    def test_loading_discovery_context_clears_scenario_and_weighted_state(
        self, monkeypatch
    ):
        import src.agent.tools.graph_tools as graph_tools

        for name in (
            "_backend", "_infra", "_cve_reports", "_risk_scores", "_attack_report",
            "_scenario_topology", "_discovery_mode", "_weighted_graph",
            "_last_disbalance_report",
        ):
            monkeypatch.setattr(graph_tools, name, getattr(graph_tools, name))
        monkeypatch.setattr(
            graph_tools, "_scenario_topology", {"nodes": [{"id": "old-run"}]}
        )
        monkeypatch.setattr(graph_tools, "_weighted_graph", object())
        monkeypatch.setattr(graph_tools, "_last_disbalance_report", {"epicenter": "old-run"})

        graph_tools.load_discovery_context("198.51.100.0/24")

        assert graph_tools._scenario_topology is None
        assert graph_tools._weighted_graph is None
        assert graph_tools._last_disbalance_report is None
        assert graph_tools._discovery_mode == {"target_network": "198.51.100.0/24"}


# ------------------------------------------------------------------
# Provider (mocked API)
# ------------------------------------------------------------------

class TestProvider:
    """Test the LLM provider with mocked API calls."""

    def _make_anthropic_provider(self, model=None):
        """Create a provider with mocked anthropic client."""
        import anthropic
        with patch.object(anthropic, "Anthropic") as mock_cls:
            provider = LLMProvider(provider="anthropic", model=model or "claude-sonnet-4-20250514")
            provider.client = mock_cls.return_value
        return provider

    def test_anthropic_init(self):
        provider = self._make_anthropic_provider()
        assert provider.model == "claude-sonnet-4-20250514"
        assert provider.provider == "anthropic"

    def test_openrouter_init(self):
        import openai
        with patch.object(openai, "OpenAI"):
            provider = LLMProvider(provider="openrouter", model="mistral-7b")
        assert provider.model == "mistral-7b"
        assert provider.provider == "openrouter"

    def test_local_moe_init_uses_bounded_proxy_timeout_and_retry(self):
        import openai
        with patch("src.agent.provider._resolve_provider_cfg", return_value={
            "base_url": "http://proxy.invalid/v1",
            "api_key_env": "",
            "default_model": "lance-moe",
        }), patch.object(openai, "OpenAI") as openai_cls:
            provider = LLMProvider(provider="local-moe", model="lance-moe")

        assert provider._retry_limit == 2
        assert openai_cls.call_args.kwargs["timeout"] == 90.0

    def test_retry_honors_expired_deadline(self):
        from src.agent.provider import _call_with_retry

        calls = []
        with pytest.raises(TimeoutError, match="deadline exceeded"):
            _call_with_retry(
                lambda: calls.append("called"),
                max_retries=5,
                deadline=time.monotonic() - 1,
            )
        assert calls == []
        with pytest.raises(ValueError, match="Unknown provider"):
            LLMProvider(provider="invalid")

    def test_anthropic_loop_text_response(self):
        """Test that a simple text response terminates the loop."""
        provider = self._make_anthropic_provider()

        mock_text = MagicMock()
        mock_text.type = "text"
        mock_text.text = "Recon complete. No findings."

        mock_response = MagicMock()
        mock_response.content = [mock_text]

        provider.client.messages.create.return_value = mock_response

        result = provider.chat_with_tools(
            system_prompt="You are a recon agent.",
            user_message="Start recon.",
            tools=[],
            max_turns=5,
        )
        assert result == "Recon complete. No findings."

    def test_anthropic_loop_with_tool_call(self):
        """Test tool call -> result -> final response cycle."""
        provider = self._make_anthropic_provider()

        # First response: tool_use
        mock_tool_use = MagicMock()
        mock_tool_use.type = "tool_use"
        mock_tool_use.name = "test_tool"
        mock_tool_use.input = {"arg": "value"}
        mock_tool_use.id = "tool_123"

        mock_response_1 = MagicMock()
        mock_response_1.content = [mock_tool_use]

        # Second response: text
        mock_text = MagicMock()
        mock_text.type = "text"
        mock_text.text = "Done."

        mock_response_2 = MagicMock()
        mock_response_2.content = [mock_text]

        provider.client.messages.create.side_effect = [mock_response_1, mock_response_2]

        tool_called = {}

        def test_tool_fn(arg):
            tool_called["arg"] = arg
            return "tool result"

        tools = [
            {
                "name": "test_tool",
                "description": "A test tool",
                "input_schema": {
                    "type": "object",
                    "properties": {"arg": {"type": "string"}},
                    "required": ["arg"],
                },
                "function": test_tool_fn,
            }
        ]

        result = provider.chat_with_tools(
            system_prompt="test",
            user_message="go",
            tools=tools,
            max_turns=5,
        )
        assert result == "Done."
        assert tool_called["arg"] == "value"

    def test_execute_tool_error_handling(self):
        """Test that tool execution errors are returned as strings."""

        def failing_tool():
            raise RuntimeError("connection refused")

        result = LLMProvider._execute_tool("fail", {}, {"fail": failing_tool})
        assert "Error executing fail" in result
        assert "connection refused" in result


# ------------------------------------------------------------------
# Orchestrator (dry-run smoke test)
# ------------------------------------------------------------------

class TestOrchestrator:
    """Test orchestrator configuration."""

    def test_load_prompt(self):
        from src.agent.prompt_manager import load_prompt
        context = {
            "device_count": "15",
            "link_count": "16",
            "cve_count": "24",
            "top_risk": "mikrotik",
            "previous_deliverables": "None",
            "expected_deliverable": "02_recon.md",
            "target_subnet": "192.168.88.0/24",
            "scenario_context": "",
        }
        prompt = load_prompt("recon", context)
        assert "192.168.88.0/24" in prompt
        assert "15" in prompt
        assert "mikrotik" in prompt

    def test_all_tools_combined(self):
        """Verify graph + recon + deliverable tools have unique names."""
        from src.agent.tools.deliverable import DELIVERABLE_TOOLS
        all_tools = GRAPH_TOOLS + RECON_TOOLS + DELIVERABLE_TOOLS
        names = [t["name"] for t in all_tools]
        assert len(names) == len(set(names)), "Duplicate tool names found"

def test_tool_result_metadata_detects_json_error_envelopes():
    assert LLMProvider._tool_result_metadata(json.dumps({"error": "boom"})) == (True, False)
    assert LLMProvider._tool_result_metadata(json.dumps({"ok": False, "error_kind": "timeout"})) == (True, False)
    assert LLMProvider._tool_result_metadata(json.dumps({"status": "saved", "fallback_used": True})) == (False, True)
    assert LLMProvider._tool_result_metadata("plain successful output") == (False, False)


def test_anthropic_repeated_calls_are_counted_on_parent_tracker_thread():
    provider = object.__new__(LLMProvider)
    provider.provider = "anthropic"
    provider.model = "test-model"
    provider.client = MagicMock()

    responses = []
    for index in range(3):
        tool_call = MagicMock(type="tool_use", input={"target": "same"}, id=f"tc-{index}")
        tool_call.name = "probe"
        responses.append(MagicMock(content=[tool_call], usage=MagicMock(input_tokens=1, output_tokens=1)))
    responses.append(MagicMock(
        content=[MagicMock(type="text", text="done")],
        usage=MagicMock(input_tokens=1, output_tokens=1),
    ))
    provider.client.messages.create.side_effect = responses
    executions = []
    tools = [{
        "name": "probe", "description": "probe", "input_schema": {"type": "object"},
        "function": lambda **kwargs: executions.append(kwargs) or json.dumps({"ok": True}),
    }]

    with patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
        tracker = CostTracker(model="test-model")
        tracker.start_phase("phase")
        result = provider.chat_with_tools("system", "user", tools, cost_tracker=tracker)
        usage = tracker.end_phase()

    assert result == "done"
    assert len(executions) == 2
    assert usage.tool_calls == 3
    assert usage.tool_errors == 1


def test_anthropic_tool_execution_preserves_thread_local_context():
    provider = object.__new__(LLMProvider)
    provider.provider = "anthropic"
    provider.model = "test-model"
    provider.client = MagicMock()

    tool_call = MagicMock(type="tool_use", input={}, id="tc-context")
    tool_call.name = "probe_context"
    provider.client.messages.create.side_effect = [
        MagicMock(content=[tool_call], usage=MagicMock(input_tokens=1, output_tokens=1)),
        MagicMock(content=[MagicMock(type="text", text="done")], usage=MagicMock(input_tokens=1, output_tokens=1)),
    ]

    context = threading.local()
    context.vulnerability = {"vuln_id": "VULN-CTX"}
    seen_results = []
    tools = [{
        "name": "probe_context",
        "description": "probe context",
        "input_schema": {"type": "object"},
        "function": lambda **_: json.dumps(getattr(context, "vulnerability", {})),
    }]

    def stream(event):
        if event.get("type") == "tool_result":
            seen_results.append(event["result"])

    with patch("src.agent.cost_tracker.get_dynamic_pricing", return_value=None):
        result = provider.chat_with_tools(
            "system", "user", tools, stream_callback=stream, max_turns=2,
        )

    assert result == "done"
    assert seen_results == ['{"vuln_id": "VULN-CTX"}']
