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


def test_reconcile_preserves_existing_endpoint_and_repairs_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "existing.db"))
    monkeypatch.delenv("LANCE_MOE_BASE_URL", raising=False)
    endpoint = "http://100.66.221.22:8001/v1"
    inject_moe.main(["--base-url", endpoint])

    with inject_moe.get_conn() as conn:
        conn.execute(
            """
            UPDATE models
            SET active_parameter_count_b = NULL, profile_policy = 'auto'
            WHERE slug = 'lance-moe'
            """
        )

    inject_moe.main([])

    with inject_moe.get_conn() as conn:
        provider = conn.execute(
            "SELECT base_url FROM providers WHERE name = 'local-moe'"
        ).fetchone()
        model = conn.execute(
            """
            SELECT active_parameter_count_b, profile_policy
            FROM models WHERE slug = 'lance-moe'
            """
        ).fetchone()

    assert provider["base_url"] == endpoint
    assert model["active_parameter_count_b"] == 3.0
    assert model["profile_policy"] == "compact"
