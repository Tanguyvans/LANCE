"""Laboratory controller identity: the tailnet, not one memorised address.

A rebuilt container receives a new Tailscale address. The identity check must
accept it, and must still refuse a host that declares a different address.
"""
from __future__ import annotations

import json
import subprocess

import pytest

from src.agent.core import runtime


def _completed(payload: list[dict] | None, *, returncode: int = 0) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=returncode,
        stdout=json.dumps(payload) if payload is not None else "",
        stderr="",
    )


def _interfaces(*addresses: str) -> list[dict]:
    return [{"ifname": "tailscale0", "addr_info": [{"local": item} for item in addresses]}]


def test_any_tailscale_address_identifies_the_controller(monkeypatch):
    monkeypatch.delenv("LANCE_EXPECTED_TAILSCALE_IP", raising=False)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: _completed(_interfaces("100.74.147.10")))
    assert runtime.tailscale_identity_present() is True


def test_declared_address_pins_the_identity(monkeypatch):
    monkeypatch.setenv("LANCE_EXPECTED_TAILSCALE_IP", "100.103.253.86")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: _completed(_interfaces("100.74.147.10")))
    assert runtime.tailscale_identity_present() is False


def test_declared_address_is_accepted_when_present(monkeypatch):
    monkeypatch.setenv("LANCE_EXPECTED_TAILSCALE_IP", "100.103.253.86")
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: _completed(_interfaces("100.103.253.86")))
    assert runtime.tailscale_identity_present() is True


def test_absent_interface_is_not_a_controller(monkeypatch):
    monkeypatch.delenv("LANCE_EXPECTED_TAILSCALE_IP", raising=False)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: _completed(None, returncode=1))
    assert runtime.tailscale_identity_present() is False


def test_empty_interface_list_is_not_a_controller(monkeypatch):
    monkeypatch.delenv("LANCE_EXPECTED_TAILSCALE_IP", raising=False)
    monkeypatch.setattr(runtime.subprocess, "run", lambda *a, **k: _completed([]))
    assert runtime.tailscale_identity_present() is False


def test_missing_ip_tool_is_not_a_controller(monkeypatch):
    monkeypatch.delenv("LANCE_EXPECTED_TAILSCALE_IP", raising=False)

    def explode(*a, **k):
        raise FileNotFoundError("ip")

    monkeypatch.setattr(runtime.subprocess, "run", explode)
    assert runtime.tailscale_identity_present() is False
