"""Tests for the local HMoE registry injection script."""
from __future__ import annotations

from src.db import inject_moe


def test_injects_auto_router_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "router-only.db"))

    inject_moe.main(["--base-url", "http://100.66.221.22:8001/v1/"])

    with inject_moe.get_conn() as conn:
        provider = conn.execute(
            "SELECT * FROM providers WHERE name = 'local-moe'"
        ).fetchone()
        models = conn.execute(
            "SELECT slug, subscription, profile_policy FROM models ORDER BY slug"
        ).fetchall()

    assert provider["base_url"] == "http://100.66.221.22:8001/v1"
    assert [row["slug"] for row in models] == ["lance-moe"]
    assert models[0]["subscription"] == 0
    assert models[0]["profile_policy"] == "compact"


def test_can_include_direct_experts(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "with-experts.db"))

    inject_moe.main(["--include-experts"])

    with inject_moe.get_conn() as conn:
        models = conn.execute(
            "SELECT slug, profile_policy FROM models ORDER BY slug"
        ).fetchall()
    assert {row["slug"] for row in models} == {
        "lance-moe",
        "expert-recon",
        "expert-vuln",
        "expert-exploit",
        "expert-secretary",
    }
    assert {row["profile_policy"] for row in models} == {"compact"}
