"""Tests for Phase 4.1 agent tools, provider, and orchestrator."""

import json
from unittest.mock import MagicMock, patch

import pytest

from src.agent.tools.recon_tools import (
    _run,
    nmap_scan,
    ssh_audit,
    curl_headers,
    mqtt_listen,
    RECON_TOOLS,
)
from src.agent.tools.graph_tools import GRAPH_TOOLS
from src.agent.provider import LLMProvider


# ------------------------------------------------------------------
# Recon tools (mocked subprocess)
# ------------------------------------------------------------------

class TestReconTools:
    """Test recon tools with mocked subprocess calls."""

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_nmap_scan_basic(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="22/tcp open ssh\n80/tcp open http\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(nmap_scan("192.168.88.1"))
        assert result["return_code"] == 0
        assert "22/tcp" in result["stdout"]
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == ["nmap", "-sV", "192.168.88.1"]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_nmap_scan_with_ports(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        nmap_scan("192.168.88.1", ports="22,80")
        args = mock_run.call_args[0][0]
        assert args == ["nmap", "-sV", "192.168.88.1", "-p", "22,80"]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_ssh_audit(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="(gen) banner: SSH-2.0-OpenSSH_10.0\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(ssh_audit("192.168.88.247"))
        assert result["return_code"] == 0
        args = mock_run.call_args[0][0]
        assert args == ["ssh-audit", "192.168.88.247:22"]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_ssh_audit_custom_port(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        ssh_audit("192.168.88.231", port=2222)
        args = mock_run.call_args[0][0]
        assert args == ["ssh-audit", "192.168.88.231:2222"]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_curl_headers(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="HTTP/1.1 200 OK\nServer: nginx/1.19.6\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(curl_headers("http://192.168.88.231"))
        assert result["return_code"] == 0
        assert "nginx" in result["stdout"]
        args = mock_run.call_args[0][0]
        assert args == ["curl", "-sI", "--max-time", "10", "http://192.168.88.231"]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_mqtt_listen(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="sensor/temp 23.5\n",
            stderr="",
            returncode=0,
        )
        result = json.loads(mqtt_listen("192.168.88.247"))
        assert result["return_code"] == 0
        args = mock_run.call_args[0][0]
        assert args == [
            "mosquitto_sub", "-h", "192.168.88.247",
            "-t", "#", "-C", "10", "-W", "5",
        ]

    @patch("src.agent.tools.recon_tools.subprocess.run")
    def test_mqtt_listen_custom(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="", returncode=0)
        mqtt_listen("192.168.88.231", topic="sensor/#", count=5, timeout=3)
        args = mock_run.call_args[0][0]
        assert args == [
            "mosquitto_sub", "-h", "192.168.88.231",
            "-t", "sensor/#", "-C", "5", "-W", "3",
        ]

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

    def test_recon_tools_definitions(self):
        """Verify all recon tools have the required fields."""
        for tool in RECON_TOOLS:
            assert "name" in tool
            assert "description" in tool
            assert "input_schema" in tool
            assert "function" in tool
            assert callable(tool["function"])


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

    def test_invalid_provider(self):
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
        """Test tool call → result → final response cycle."""
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
