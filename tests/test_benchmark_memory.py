"""Benchmark memory boundaries, without a database, embeddings or an LLM call."""
import json
from threading import Lock
from unittest.mock import Mock

import pytest

from src.agent.core.runner import AgentRunner
from src.agent.knowledge import ingest as ingestion


@pytest.mark.parametrize("split", ["dev-public", "test-public", "eval-sealed", "lab-export"])
@pytest.mark.parametrize("name,kwargs", [
    ("search_history", {"query": "previous findings"}),
    ("search_knowledge", {"query": "previous findings", "collection": "run_history"}),
    ("search_knowledge", {"query": "previous findings"}),
    ("search_knowledge", {"query": "previous findings", "collection": "other_collection"}),
])
def test_benchmark_tool_calls_cannot_read_mutable_memory(tmp_path, split, name, kwargs):
    runner = AgentRunner()
    runner.run_dir = tmp_path
    runner.benchmark_split = split
    runner._artifact_log_lock = Lock()
    runner.max_tool_calls = None
    runner._tool_call_count = 0
    original = Mock(return_value="[]")
    wrapped = runner._wrap_tool({"name": name, "function": original}, phase=2)
    result = json.loads(wrapped["function"](**kwargs))
    assert result["error_kind"] == "benchmark_memory_disabled"
    original.assert_not_called()
    assert "benchmark_memory_disabled" in (tmp_path / "tool_calls.jsonl").read_text()


@pytest.mark.parametrize("split,collection", [
    ("unassigned", "run_history"), ("dev-public", "skills"), ("test-public", "skills"),
])
def test_methodology_and_non_benchmark_memory_remain_available(tmp_path, split, collection):
    runner = AgentRunner()
    runner.run_dir = tmp_path
    runner.benchmark_split = split
    runner._artifact_log_lock = Lock()
    runner.max_tool_calls = None
    runner._tool_call_count = 0
    original = Mock(return_value="[]")
    wrapped = runner._wrap_tool({"name": "search_knowledge", "function": original}, phase=2)
    assert wrapped["function"](query="method", collection=collection) == "[]"
    original.assert_called_once()


@pytest.mark.parametrize("metadata,scenario", [
    ({"benchmark_split": "test-public"}, {}),
    ({"benchmark_split": "dev-public"}, {}),
    ({"benchmark_split": "eval-sealed"}, {}),
    ({"benchmark_split": "lab-export"}, {}),
    ({"benchmark_split": "unassigned"}, {"scenario_id": "20", "split": "unassigned"}),
    ({}, {"scenario_id": "1"}),
    (None, {}),
])
def test_direct_ingestion_rejects_benchmark_and_unclassified_artifacts(tmp_path, monkeypatch, metadata, scenario):
    if metadata is not None:
        (tmp_path / "run_meta.json").write_text(json.dumps(metadata))
    (tmp_path / "scenario_meta.json").write_text(json.dumps(scenario))
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [{"id": "F1", "device_id": "device", "type": "no_auth"}],
    }))
    persist = Mock()
    monkeypatch.setattr(ingestion, "ingest", persist)
    assert ingestion.ingest_run_findings(tmp_path, "model") == 0
    persist.assert_not_called()


def test_non_benchmark_ingestion_is_preserved(tmp_path, monkeypatch):
    (tmp_path / "run_meta.json").write_text('{"benchmark_split": "unassigned"}')
    (tmp_path / "03_vuln_analysis.json").write_text(json.dumps({
        "vulnerabilities": [{"id": "F1", "device_id": "device", "type": "no_auth"}],
    }))
    persist = Mock(return_value=1)
    monkeypatch.setattr(ingestion, "ingest", persist)
    assert ingestion.ingest_run_findings(tmp_path, "model") == 1
    persist.assert_called_once()
