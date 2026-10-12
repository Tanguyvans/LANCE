"""Run-bound CVE sources and phase knowledge filters, without network access."""
from concurrent.futures import ThreadPoolExecutor
import builtins
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from src.agent.core import runtime
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS
from src.agent.tools import skill_tools


@pytest.fixture
def create_run(tmp_path, monkeypatch):
    monkeypatch.setattr("src.agent.cost_tracker._resolve_pricing", lambda *_a, **_k: (
        {"input": 0.0, "output": 0.0}, "offline-test", True,
    ))
    monkeypatch.setattr(runtime, "filter_unavailable_tools", lambda tools: (tools, {}))

    def create(split="unassigned"):
        return Pipeline(
            provider=SimpleNamespace(provider="ollama-umons", model="offline"),
            execution_profile="full", manage_scenario=False, output_dir=tmp_path,
            benchmark_split=split,
        )

    return create


def tool_for(run, phase, name):
    config = next(config for config in AGENTS.values() if config.phase == phase)
    return run._wrap_tool(
        next(tool for tool in skill_tools.SKILL_TOOLS if tool["name"] == name),
        phase=phase, agent=config.name,
    )["function"]


@pytest.mark.parametrize("order", [
    ("dev-public", "unassigned"), ("unassigned", "dev-public"),
])
def test_cve_source_belongs_to_the_run_in_either_creation_order(create_run, monkeypatch, order):
    calls = []

    def fetch(*args, **kwargs):
        calls.append(args)
        return []

    monkeypatch.setattr("src.agent.knowledge.store.get_or_fetch", fetch)
    runs = {split: create_run(split) for split in order}
    for split in order:
        result = json.loads(tool_for(runs[split], 3, "cve_search")(query="OpenSSH 10.0p2"))
        assert bool(result) is (split == "dev-public")
    assert len(calls) == 1


def test_phase_filters_remain_isolated_in_parallel_worker_threads(create_run, monkeypatch):
    run = create_run()
    barrier = Barrier(2)
    metadata = skill_tools.get_skills_metadata()

    def synchronized_metadata():
        barrier.wait(timeout=5)
        return metadata

    monkeypatch.setattr(skill_tools, "get_skills_metadata", synchronized_metadata)
    tools = [tool_for(run, phase, "list_skills") for phase in (2, 6)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        recon, report = list(pool.map(lambda tool: json.loads(tool()), tools))
    assert "mqtt_security" in {skill["name"] for skill in recon}
    assert "report_methodology" not in {skill["name"] for skill in recon}
    assert {skill["name"] for skill in report} == {"report_methodology"}


def test_tool_error_restores_the_standalone_knowledge_context(create_run):
    run = create_run()

    def fail():
        names = {skill["name"] for skill in json.loads(skill_tools.list_skills())}
        assert "mqtt_security" in names
        assert "firmware_analysis" not in names
        raise RuntimeError("failed tool")

    tool = run._wrap_tool({"name": "failing_tool", "function": fail}, phase=2)["function"]
    skill_tools.set_skill_filter(["firmware"])
    try:
        with pytest.raises(RuntimeError, match="failed tool"):
            tool()
        assert {skill["name"] for skill in json.loads(skill_tools.list_skills())} == {"firmware_analysis"}
    finally:
        skill_tools.set_skill_filter(None)


def test_frozen_cve_lookup_does_not_require_the_live_knowledge_store(monkeypatch):
    original_import = builtins.__import__

    def without_store(name, *args, **kwargs):
        if name == "src.agent.knowledge.store":
            raise ImportError("live knowledge dependencies are unavailable")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_store)
    skill_tools.set_cve_cache_only(True)
    try:
        result = json.loads(skill_tools.cve_search("OpenSSH 10.0p2"))
    finally:
        skill_tools.set_cve_cache_only(False)
    assert isinstance(result, list) and result
