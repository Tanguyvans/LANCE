"""Tests for the traceable pivot tools (pivot_ssh_exec / pivot_http_get)."""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from src.agent.tools.recon_tools import (
    _build_pivot_command,
    _parse_jump_chain,
    _pivot_provenance,
    _redact_pivot_secrets,
    pivot_http_get,
    pivot_ssh_exec,
)

ENTRY = {"ip": "192.168.100.11", "user": "admin", "password": "entry-secret"}
RELAY = {"ip": "192.168.110.12", "user": "relay", "password": "relay-secret"}
VAULT = {"ip": "192.168.120.13", "user": "root", "password": "vault-secret"}


def _chain(*hops) -> str:
    return json.dumps(list(hops))


# ── Jump chain parsing ────────────────────────────────────────────────────────

class TestParseJumpChain:
    def test_valid_chain_defaults_port_22(self):
        chain = _parse_jump_chain(_chain(ENTRY, RELAY, VAULT))
        assert [hop["ip"] for hop in chain] == [
            "192.168.100.11", "192.168.110.12", "192.168.120.13",
        ]
        assert all(hop["port"] == 22 for hop in chain)

    def test_custom_port_accepted(self):
        chain = _parse_jump_chain(_chain({**ENTRY, "port": 2222}))
        assert chain[0]["port"] == 2222

    def test_hostname_rejected_literal_ip_required(self):
        with pytest.raises(ValueError, match="literal IP"):
            _parse_jump_chain(_chain({**ENTRY, "ip": "relay.internal"}))

    def test_invalid_user_rejected(self):
        with pytest.raises(ValueError, match="invalid user"):
            _parse_jump_chain(_chain({**ENTRY, "user": "root; rm -rf /"}))

    def test_empty_password_rejected(self):
        with pytest.raises(ValueError, match="invalid password"):
            _parse_jump_chain(_chain({**ENTRY, "password": ""}))

    def test_oversized_password_rejected(self):
        with pytest.raises(ValueError, match="invalid password"):
            _parse_jump_chain(_chain({**ENTRY, "password": "x" * 513}))

    def test_empty_chain_rejected(self):
        with pytest.raises(ValueError, match="between 1 and 8"):
            _parse_jump_chain("[]")

    def test_too_many_hops_rejected(self):
        with pytest.raises(ValueError, match="between 1 and 8"):
            _parse_jump_chain(_chain(*([ENTRY] * 9)))

    def test_non_json_rejected(self):
        with pytest.raises(ValueError, match="JSON array"):
            _parse_jump_chain("not json")


# ── Command building / provenance / redaction ─────────────────────────────────

class TestPivotInternals:
    def test_build_command_nests_full_chain(self):
        chain = _parse_jump_chain(_chain(ENTRY, RELAY, VAULT))
        cmd = _build_pivot_command(chain, "id")
        # Outermost ssh targets the first hop only.
        assert cmd[:2] == ["sshpass", "-p"]
        assert "admin@192.168.100.11" in cmd
        inner = cmd[-1]
        assert "relay@192.168.110.12" in inner
        assert "root@192.168.120.13" in inner
        assert inner.rstrip("'").endswith(" id")

    def test_provenance_ssh_chain_depth_is_hops_minus_one(self):
        chain = _parse_jump_chain(_chain(ENTRY, RELAY, VAULT))
        prov = _pivot_provenance(
            chain, transport="ssh-chain", target_ip=chain[-1]["ip"], target_port=22,
        )
        assert prov["network_pivot_depth"] == 2
        assert prov["source_vantage"] == "192.168.110.12"
        assert prov["schema_version"] == "1"
        # Provenance never carries passwords.
        assert "password" not in json.dumps(prov)

    def test_provenance_http_depth_is_full_chain_length(self):
        chain = _parse_jump_chain(_chain(ENTRY, RELAY))
        prov = _pivot_provenance(
            chain, transport="ssh-chain+http",
            target_ip="192.168.120.13", target_port=80, endpoint="/admin",
        )
        assert prov["network_pivot_depth"] == 2
        assert prov["endpoint"] == "/admin"

    def test_redact_pivot_secrets_removes_all_passwords(self):
        chain = _parse_jump_chain(_chain(ENTRY, RELAY))
        text = "entry-secret and relay-secret leaked"
        redacted = _redact_pivot_secrets(text, chain)
        assert "entry-secret" not in redacted
        assert "relay-secret" not in redacted
        assert redacted.count("[redacted]") == 2


# ── pivot_ssh_exec ────────────────────────────────────────────────────────────

class TestPivotSshExec:
    @patch("src.agent.tools.recon_tools._run")
    def test_valid_pivot_returns_success_and_provenance(self, mock_run):
        mock_run.return_value = {
            "stdout": "uid=0(root) gid=0(root)", "stderr": "", "return_code": 0,
        }
        result = json.loads(pivot_ssh_exec(_chain(ENTRY, RELAY, VAULT), "id"))
        assert result["success"] is True
        prov = result["network_provenance"]
        assert prov["network_pivot_depth"] == 2
        assert prov["target_ip"] == "192.168.120.13"
        assert [hop["ip"] for hop in prov["jump_chain"]] == [
            "192.168.100.11", "192.168.110.12", "192.168.120.13",
        ]

    @patch("src.agent.tools.recon_tools._run")
    def test_passwords_never_leak_into_output(self, mock_run):
        mock_run.return_value = {
            "stdout": "config password=relay-secret",
            "stderr": "auth for vault-secret failed once",
            "return_code": 0,
        }
        raw = pivot_ssh_exec(_chain(ENTRY, RELAY, VAULT), "cat /etc/config")
        assert "relay-secret" not in raw
        assert "vault-secret" not in raw
        assert "entry-secret" not in raw

    @patch("src.agent.tools.recon_tools._run")
    def test_failed_command_reports_failure(self, mock_run):
        mock_run.return_value = {"stdout": "", "stderr": "boom", "return_code": 1}
        result = json.loads(pivot_ssh_exec(_chain(ENTRY), "id"))
        assert result["success"] is False

    def test_invalid_chain_is_non_throwing_error(self):
        result = json.loads(pivot_ssh_exec("[]", "id"))
        assert result["success"] is False
        assert "error" in result

    def test_empty_command_rejected(self):
        result = json.loads(pivot_ssh_exec(_chain(ENTRY), "   "))
        assert result["success"] is False


# ── pivot_http_get ────────────────────────────────────────────────────────────

class TestPivotHttpGet:
    @patch("src.agent.tools.recon_tools._run")
    def test_valid_fetch_parses_status_and_body(self, mock_run):
        mock_run.return_value = {
            "stdout": "<html>admin panel</html>\n__HTTP_STATUS__:200",
            "stderr": "",
            "return_code": 0,
        }
        result = json.loads(pivot_http_get(
            _chain(ENTRY, RELAY), "http://192.168.120.13/admin",
        ))
        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["body"].strip() == "<html>admin panel</html>"
        prov = result["network_provenance"]
        assert prov["transport"] == "ssh-chain+http"
        assert prov["network_pivot_depth"] == 2
        assert prov["target_ip"] == "192.168.120.13"
        assert prov["endpoint"] == "/admin"

    @patch("src.agent.tools.recon_tools._run")
    def test_http_error_status_is_failure(self, mock_run):
        mock_run.return_value = {
            "stdout": "not found\n__HTTP_STATUS__:404", "stderr": "", "return_code": 0,
        }
        result = json.loads(pivot_http_get(_chain(ENTRY), "http://192.168.120.13/x"))
        assert result["success"] is False
        assert result["status_code"] == 404

    def test_non_ip_url_rejected(self):
        result = json.loads(pivot_http_get(_chain(ENTRY), "http://vault.internal/"))
        assert result["success"] is False

    def test_non_http_scheme_rejected(self):
        result = json.loads(pivot_http_get(_chain(ENTRY), "ftp://192.168.120.13/"))
        assert result["success"] is False
