"""Compact artifacts and the common access projection agree on the same trace."""
from functools import partial
import json
from threading import Event, Lock
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.agent.core.executor import wrap_tool
from src.agent.evidence.capabilities import access_supported
from src.agent.phases.intrusion.compact import CompactIntrusionPhase
from src.agent.phases.intrusion.observations import project_intrusion_observations
from src.agent.phases.intrusion.run import IntrusionPhase
from src.agent.tools import recon_tools
from src.agent.validators import validate_json_valid
from src.benchmark.metric_contract import EVIDENCE_CONTRACT_VERSION


class CompactHost(IntrusionPhase, CompactIntrusionPhase):
    def __init__(self, root):
        self.run_dir = root
        self.context = {"target_subnet": "192.0.2.0/24"}

    def _uses_compact_local_moe(self):
        return True

    def _validator(self, name):
        assert name == "json_valid"
        return partial(validate_json_valid, output_dir=self.run_dir)


@pytest.mark.parametrize("http_code,expected", [("500", 0), ("302", 0), ("200", 1)])
def test_http_access_agrees_in_tool_flags_compact_artifact_and_projection(tmp_path, monkeypatch, http_code, expected):
    monkeypatch.setattr(recon_tools, "_run", Mock(side_effect=[
        {"stdout": "401", "return_code": 0}, {"stdout": http_code, "return_code": 0},
    ]))
    run = SimpleNamespace(
        run_dir=tmp_path, _artifact_log_lock=Lock(), max_tool_calls=None, _tool_call_count=0,
        tracker=Mock(), _stop_event=Event(), context={"target_subnet": "192.0.2.0/24"},
    )
    tool = wrap_tool(run, {"name": "try_credential", "function": recon_tools.try_credential}, phase=5)
    result = json.loads(tool["function"](ip="192.0.2.10", service="http", user="admin", password="fixture"))
    assert result["authenticated"] is bool(expected)
    record = json.loads((tmp_path / "tool_calls.jsonl").read_text())
    # Also replay older incorrectly optimistic flags: every consumer must
    # evaluate the observed HTTP code rather than trust this success flag.
    record["result"] = json.dumps({**result, "success": True, "authenticated": True})
    (tmp_path / "tool_calls.jsonl").write_text(json.dumps(record) + "\n", encoding="utf-8")
    assert access_supported(record) is bool(expected)
    (tmp_path / "run_meta.json").write_text(json.dumps({"evidence_contract_version": EVIDENCE_CONTRACT_VERSION}))
    (tmp_path / "05_intrusion_context.json").write_text(json.dumps({
        "entry_points": [{"device_id": "web", "device_ip": "192.0.2.10", "service": "http"}],
        "all_targets": [{"device_id": "web", "device_ip": "192.0.2.10", "primary_service": "http", "services": [80]}],
        "recovered_credentials": [{"user": "admin", "password": "fixture", "service": "http", "source_ip": "192.0.2.10"}],
    }))
    host = CompactHost(tmp_path)
    assert host._write_compact_intrusion_deliverable(note="offline regression")
    artifact = json.loads((tmp_path / "05_intrusion.json").read_text())
    assert artifact["summary"]["devices_compromised"] == expected
    projected = project_intrusion_observations(tmp_path)
    assert projected["available"] is True
    assert len(projected["accesses"]) == expected
    _covered, coverage = host._compact_intrusion_coverage()
    assert len(coverage["successful_accesses"]) == expected
