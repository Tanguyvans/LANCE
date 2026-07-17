"""Cross-component guards that keep the sealed oracle outside the worker."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from unittest.mock import MagicMock, patch

import pytest

from src.agent.pipeline import Pipeline
from src.benchmark.contracts import ChallengeContract, ChallengeScope, RunLimits


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _reset_graph_tool_mode_after_test():
    """Pipeline discovery state is process-global; do not leak it to tests."""

    yield
    from src.agent.tools import graph_tools

    graph_tools._discovery_mode = None
    graph_tools._scenario_topology = None


def _provider():
    provider = MagicMock()
    provider.model = "test-model"
    provider.provider = "test-provider"
    provider.chat_with_tools.return_value = "Done."
    return provider


def _contract() -> ChallengeContract:
    return ChallengeContract(
        session_id="12345678-1234-4234-8234-123456789abc",
        scenario_id="20",
        benchmark_version="2.0.0",
        scope=ChallengeScope(ingress_cidrs=("10.77.20.0/24",)),
        limits=RunLimits(
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            max_cost_usd=1.0,
            max_tool_calls=10,
        ),
    )


def test_sealed_pipeline_refuses_repository_filesystem():
    with pytest.raises(RuntimeError, match="Refusing sealed evaluation"):
        Pipeline(
            provider=_provider(),
            scenario_id="20",
            execution_context=_contract(),
            benchmark_split="eval-sealed",
        )


def test_sealed_worker_forces_blind_and_never_touches_oracle_or_ansible(
    tmp_path, monkeypatch,
):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(),
        scenario_id="20",
        execution_context=_contract(),
        benchmark_split="eval-sealed",
        phases=[99],
        dry_run=True,
    )

    assert pipeline.blind is True
    assert pipeline.manage_scenario is False
    assert pipeline.auto_teardown is False
    assert pipeline.target_network == "10.77.20.0/24"
    assert pipeline.max_tool_calls == 10

    with patch.object(pipeline, "_save_ground_truth") as save_gt, \
         patch.object(pipeline, "_load_scenario_context") as load_context, \
         patch.object(pipeline, "_run_scenario_deploy") as deploy, \
         patch.object(pipeline, "_run_teardown") as teardown:
        pipeline.run()

    save_gt.assert_not_called()
    load_context.assert_not_called()
    deploy.assert_not_called()
    teardown.assert_not_called()
    assert not (pipeline.run_dir / "ground_truth.yaml").exists()


def test_public_preset_no_longer_copies_ground_truth(tmp_path, monkeypatch):
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="1", benchmark_split="dev-public",
        phases=[99], dry_run=True,
    )
    with patch.object(pipeline, "_save_ground_truth") as save_gt:
        pipeline.run()
    save_gt.assert_not_called()
    assert not (pipeline.run_dir / "ground_truth.yaml").exists()


def test_sealed_tool_groups_remove_history_and_python(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module
    from src.agent.registry import AgentConfig

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=False,
    )
    assert pipeline.tracker.allow_dynamic_pricing is False
    config = AgentConfig(
        name="sealed", phase=1, prompt_template="x", deliverable_file="x.md",
        tools=["recon", "skill"],
    )
    names = {tool["name"] for tool in pipeline._resolve_tools(config)}
    assert "python_exec" not in names
    assert "ssh_login" not in names
    assert "telnet_connect" not in names
    assert "search_history" not in names
    assert "search_knowledge" not in names
    assert "cve_search" not in names
    assert "nvd_lookup" not in names
    assert "mysql_query" not in names
    assert "redis_cmd" not in names
    assert "sqlmap" not in names
    assert "curl_headers" not in names
    assert "nmap_scan" in names
    assert "http_request" in names


def test_sealed_direct_micro_agent_surface_uses_same_positive_filter(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    cve_search = next(t for t in pipeline_module.SKILL_TOOLS if t["name"] == "cve_search")
    http_get = next(t for t in pipeline_module.RECON_TOOLS if t["name"] == "http_get")

    surface = pipeline._prepare_tool_surface([cve_search, http_get])

    assert [tool["name"] for tool in surface] == ["http_get"]
    assert surface[0]["input_schema"]["additionalProperties"] is False


def test_sealed_subprocess_tools_reject_option_and_scope_injection(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module
    from src.agent.registry import AgentConfig
    from src.agent.sealed_tool_policy import SealedToolPolicyError

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    config = AgentConfig(
        name="sealed", phase=1, prompt_template="x", deliverable_file="x.md",
        tools=["nmap_scan", "http_get"],
    )
    tools = {tool["name"]: tool["function"] for tool in pipeline._resolve_tools(config)}

    with patch("src.agent.tools.recon_tools._run") as run:
        run.return_value = {"stdout": "ok", "stderr": "", "return_code": 0}
        with pytest.raises(SealedToolPolicyError, match="injected option"):
            tools["nmap_scan"](target="10.77.20.8 --script /work/read.nse")
        with pytest.raises(SealedToolPolicyError, match="scripts is not in"):
            tools["nmap_scan"](target="10.77.20.8", scripts="/work/read.nse")
        with pytest.raises(SealedToolPolicyError, match="unknown arguments"):
            tools["nmap_scan"](target="10.77.20.8", timeout=999)
        with pytest.raises(SealedToolPolicyError, match="requires an explicit port"):
            tools["nmap_scan"](target="10.77.20.8", udp_scan=True)
        with pytest.raises(SealedToolPolicyError, match="1024-port"):
            tools["nmap_scan"](target="10.77.20.8", ports="1-65535")
        with pytest.raises(SealedToolPolicyError, match="option prefix"):
            tools["http_get"](url="--config /work/run_meta.json")
        with pytest.raises(SealedToolPolicyError, match="outside the sealed scope"):
            tools["http_get"](url="http://169.254.169.254/latest/meta-data/")
        run.assert_not_called()

        tools["nmap_scan"](
            target="10.77.20.8", ports="22,80", scripts="ssh-auth-methods",
        )
        assert run.call_args.args[0][-1] == "10.77.20.8"


def test_sealed_tool_budget_is_atomic_across_parallel_micro_agents(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    pipeline.max_tool_calls = 5
    executed = 0
    executed_lock = Lock()

    def handler(**_kwargs):
        nonlocal executed
        with executed_lock:
            executed += 1
        return "ok"

    wrapped = pipeline._wrap_tool({
        "name": "decode_value",
        "description": "test",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "function": handler,
    })["function"]

    def call_once(_index):
        try:
            return wrapped(value="61", kind="hex")
        except RuntimeError:
            return "budget-exhausted"

    with ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(call_once, range(64)))

    assert executed == 5
    assert pipeline._tool_call_count == 5
    assert results.count("ok") == 5
    assert results.count("budget-exhausted") == 59


def test_sealed_followup_hosts_are_filtered_and_normalized_to_scope(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    exploit_dir = pipeline.run_dir / "04_exploits" / "device"
    exploit_dir.mkdir(parents=True)
    (exploit_dir / "finding.json").write_text(
        '{"new_hosts_discovered": ['
        '{"ip":"10.77.20.9","open_ports":[22,"80","--script"],"discovered_via":"pivot"},'
        '{"ip":"169.254.169.254","open_ports":[80]},'
        '{"ip":"not-an-ip","open_ports":[443]}]}'
    )

    assert pipeline._collect_new_hosts() == [{
        "ip": "10.77.20.9",
        "open_ports": [22, 80],
        "discovered_via": "pivot",
    }]


def test_sealed_topology_inference_never_traceroutes_prefix_lookalikes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )
    (pipeline.run_dir / "02_recon.md").write_text(
        "in scope 10.77.20.8; prefix lookalike 10.77.200.8; metadata 169.254.169.254"
    )

    with patch("src.agent.pipeline.subprocess.run") as run:
        run.return_value.stdout = ""
        pipeline._infer_topology_links(stream_callback=None)

    assert run.call_count == 1
    assert run.call_args.args[0][-1] == "10.77.20.8"


def test_sealed_pipeline_never_persists_sqlite_or_chroma(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import src.agent.pipeline as pipeline_module

    monkeypatch.setattr(pipeline_module, "OUTPUT_DIR", tmp_path / "output")
    pipeline = Pipeline(
        provider=_provider(), scenario_id="20", execution_context=_contract(),
        benchmark_split="eval-sealed", phases=[99], dry_run=True,
    )

    ingest = MagicMock()
    fake_ingest_module = MagicMock(ingest_run_findings=ingest)
    with patch.dict(
             "sys.modules",
             {"src.agent.knowledge.ingest": fake_ingest_module},
         ), patch("src.db.database.init_db") as init_db, \
         patch("src.db.database.record_run") as record_run, \
         patch("src.db.database.record_phase_usage") as record_phase_usage:
        pipeline.run()

    init_db.assert_not_called()
    record_run.assert_not_called()
    record_phase_usage.assert_not_called()
    ingest.assert_not_called()


def test_design_docs_never_define_official_sealed_profile_rows():
    """Prevent a public architecture table from becoming a sealed oracle."""

    forbidden_row = re.compile(r"^\|\s*S(?:20|21|22|23|24|25)\s*\|", re.MULTILINE)
    offenders = [
        str(path.relative_to(ROOT))
        for path in sorted((ROOT / "benchmarks" / "docs").glob("*.md"))
        if forbidden_row.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == [], (
        "official sealed IDs may not have architecture/detail rows in public "
        f"design docs: {offenders}"
    )


def test_sealed_deployment_examples_disable_recoverable_runtime_traces():
    """Keep the operator examples aligned with the non-retention contract."""

    worker = (ROOT / "docker" / "worker.Dockerfile").read_text(encoding="utf-8")
    gateway = (
        ROOT / "deploy" / "systemd" / "iotchainbench-sealed-gateway.service"
    ).read_text(encoding="utf-8")
    proxy = (
        ROOT / "deploy" / "nginx" / "iotchainbench-sealed-gateway.conf.example"
    ).read_text(encoding="utf-8")

    assert "--log-driver=none" in worker
    assert "--ulimit core=0" in worker
    assert "memory.swap.max=0" in worker
    assert "StandardOutput=null" in gateway
    assert "StandardError=null" in gateway
    assert "LimitCORE=0" in gateway
    assert "MemorySwapMax=0" in gateway
    assert "access_log off;" in proxy
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in proxy
