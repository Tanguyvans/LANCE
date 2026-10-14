"""nmap -sV emits uncertain/tunnelled service names ("telnet?",
"ssl|http", "tor-orport?"). The scanner must resolve them to the same
matrix key as their canonical names instead of recording
"no scanner rule" — which degraded the phase-3 status of both pilot
arms on S1 (2026-10-14 runs) despite every device being analyzed.
"""
import pytest

from src.benchmark.tool_registry import service_matrix_key


@pytest.mark.parametrize("name,expected", [
    ("ssh", "ssh"),
    ("http", "http"),
    ("telnet", "telnet"),
    ("telnet?", "telnet"),
    ("mosquitto?", "mqtt"),
    ("tor-orport", "mqtt"),
    ("tor-orport?", "mqtt"),
    ("ssl/http", "https"),
    ("ssl|http", "https"),
    ("SSL|HTTP", "https"),
    ("mysql?", "mysql"),
])
def test_known_and_nmap_variant_names_resolve(name, expected):
    assert service_matrix_key(name) == expected


@pytest.mark.parametrize("name", ["unknown-svc", "unknown-svc?", "", "  "])
def test_unknown_services_still_have_no_rule(name):
    assert service_matrix_key(name) is None
