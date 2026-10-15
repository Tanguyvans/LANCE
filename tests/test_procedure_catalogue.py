"""The public catalogue is descriptive, versioned and reflects local tools."""
from fastapi.testclient import TestClient

from src.agent import procedures
from src.api.main import app


def test_catalogue_exposes_missing_tools_without_requiring_a_model(monkeypatch):
    monkeypatch.setattr(procedures.shutil, "which", lambda _: None)
    with TestClient(app) as client:
        response = client.get("/api/procedures")
    assert response.status_code == 200
    catalogue = response.json()
    items = {item["id"]: item for item in catalogue["procedures"]}
    assert set(items) == procedures.SCRIPT_IDS | {"rules-audit-v1"}
    assert items["smoke-v1"]["availability"] == {"available": True, "missing_dependencies": []}
    assert items["discovery-v1"]["availability"] == {"available": False, "missing_dependencies": ["nmap"]}
    assert items["rules-audit-v1"]["target_kind"] == "scenario"
    assert items["service-inventory-v1"]["max_hosts"] == 16
    assert all(len(item["fingerprint"]) == 64 and item["version"] for item in items.values())


def test_descriptors_are_detached_and_unknown_procedures_are_not_executable():
    import pytest
    before = procedures.get_procedure("discovery-v1")
    changed = procedures.get_procedure("discovery-v1")
    changed["steps"][0]["label"] = "modified"
    changed["defaults"]["max_tool_calls"] = 100
    assert procedures.get_procedure("discovery-v1") == before
    with pytest.raises(ValueError, match="Unknown procedure"):
        procedures.get_procedure("../../custom.sh")
