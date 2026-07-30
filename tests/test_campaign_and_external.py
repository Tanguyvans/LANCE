from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from benchmarks.tools.run_campaign import CampaignRunner, _conditions, _load_manifest, _parser
from src.baselines.external_benchmarks import ExternalBenchmarkCase, run_case
from src.baselines.runner import _normalise_calls
from src.baselines.runner import run_local_baseline


ROOT = Path(__file__).resolve().parents[1]


def test_paper_campaign_expands_to_78_unique_serial_conditions():
    manifest = _load_manifest(ROOT / "benchmarks/campaigns/paper_v3_4.yaml")
    conditions = _conditions(manifest)

    assert len(conditions) == 78
    assert len({condition.id for condition in conditions}) == 78
    assert [condition.scenario for condition in conditions[:2]] == ["1", "1"]
    s20 = [condition for condition in conditions if condition.scenario == "20"]
    assert [(item.system, item.mode) for item in s20] == [
        ("lance", "blind"),
        ("cai", "blind"),
        ("vulnbot", "blind"),
        ("lance", "informed"),
    ]
    s21 = [condition for condition in conditions if condition.scenario == "21"]
    assert [(item.system, item.mode) for item in s21] == [
        ("cai", "blind"),
        ("vulnbot", "blind"),
        ("lance", "blind"),
        ("lance", "informed"),
    ]


def test_campaign_resets_and_verifies_between_every_condition(tmp_path):
    manifest_path = ROOT / "benchmarks/campaigns/paper_v3_4.yaml"
    manifest = _load_manifest(manifest_path)
    args = _parser().parse_args([
        "--manifest", str(manifest_path),
        "--dry-run",
        "--only-scenario", "20",
        "--only-system", "lance",
        "--state", str(tmp_path / "state.json"),
    ])
    runner = CampaignRunner(args, manifest)
    events = []

    with (
        patch.object(runner, "_deploy", side_effect=lambda sid: events.append(("deploy", sid))),
        patch.object(runner, "_reset", side_effect=lambda sid: events.append(("reset", sid))),
        patch.object(runner, "_run_condition", side_effect=lambda item: events.append((item.system, item.mode))),
        patch.object(runner, "_playbook", side_effect=lambda name, sid: events.append((name, sid))),
    ):
        runner.run(_conditions(manifest))

    assert events == [
        ("deploy", "20"),
        ("lance", "blind"),
        ("reset", "20"),
        ("lance", "informed"),
        ("99_teardown.yml", "20"),
    ]


def test_external_runlists_match_pinned_manifest_counts():
    manifest = yaml.safe_load(
        (ROOT / "benchmarks/external/manifest.yaml").read_text(encoding="utf-8")
    )
    for suite in ("autopenbench", "vulhub"):
        config = manifest["suites"][suite]
        runlist = ROOT / config["runlist"]
        cases = [
            line.strip() for line in runlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        assert len(cases) == config["expected_cases"]
        assert len(cases) == len(set(cases))
        assert cases == sorted(cases)


def test_native_trace_translation_is_deterministic_and_does_not_invent_known_tools():
    calls = _normalise_calls([
        {"id": "a", "tool": "shell", "args": {"command": "curl http://192.0.2.5/"}, "result": {"status_code": 200}},
        {"id": "b", "tool": "custom_magic", "args": {}, "result": "claimed"},
    ])

    assert calls[0]["tool"] == "http_request"
    assert calls[0]["evidence_ref"] == "a"
    assert calls[1]["tool"].startswith("baseline_native_")


def test_external_runner_never_exposes_expected_flag_in_prerun_files(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  app:\n    image: example.invalid/test\n", encoding="utf-8")
    case = ExternalBenchmarkCase(
        suite="vulhub",
        case_id="demo/CVE-2000-0001",
        path=tmp_path,
        name="demo",
        expected_flag="TOP-SECRET-FLAG",
        compose_file=compose,
    )

    with patch("src.baselines.external_benchmarks._select_case", return_value=case):
        run_dir = run_case(
            suite="vulhub",
            repo=tmp_path,
            case_id=case.case_id,
            agent_command="python -m src.agent_external --target {target_or_url} --output-dir {output_dir}",
            output_dir=tmp_path / "out",
            dry_run=True,
        )

    material = "\n".join(path.read_text(encoding="utf-8") for path in run_dir.iterdir() if path.is_file())
    assert "TOP-SECRET-FLAG" not in material
    planned = json.loads((run_dir / "planned.json").read_text(encoding="utf-8"))
    assert planned["agent_context_inputs"]["flag_provided"] is False


def test_external_runner_rejects_flag_placeholder(tmp_path):
    with pytest.raises(ValueError, match="controller-only"):
        run_case(
            suite="vulhub",
            repo=tmp_path,
            case_id="ignored",
            agent_command="agent --flag {flag}",
            output_dir=tmp_path / "out",
            dry_run=True,
        )


def test_real_baseline_adapter_emits_strict_v3_contract(tmp_path):
    def fake_run(command, **kwargs):
        if command[:2] == ["git", "rev-parse"]:
            return subprocess.CompletedProcess(command, 0, stdout="a" * 40 + "\n", stderr="")
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps({
            "findings": [{
                "id": "native-1",
                "ip": "192.168.100.12",
                "type": "data_exposure",
                "severity": "high",
                "service": "http",
                "port": 80,
                "protocol": "tcp",
                "endpoint": "/backup.sql",
                "status": "CONFIRMED",
                "evidence": "HTTP 200",
                "evidence_refs": ["call-1"],
            }],
            "tool_calls": [{
                "id": "call-1",
                "tool": "curl",
                "args": {"url": "http://192.168.100.12/backup.sql"},
                "result": {"status_code": 200, "body": "backup"},
            }],
        }), encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with patch("src.baselines.runner.subprocess.run", side_effect=fake_run):
        run_dir = run_local_baseline(
            tool="cai",
            scenario_id="20",
            mode="blind",
            scope="192.168.100.0/24",
            model="test-model",
            max_turns=10,
            output_root=tmp_path,
            command_template="adapter --scope {scope} --output {output}",
        )

    meta = json.loads((run_dir / "run_meta.json").read_text(encoding="utf-8"))
    score = json.loads((run_dir / "evaluator_score.json").read_text(encoding="utf-8"))
    assert meta["metric_contract_version"] == "strict-v3.4"
    assert meta["evidence_contract_version"] == "evidence-v2"
    assert meta["mode"] == "blind"
    assert meta["oracle_access"] is False
    assert score["evidence_contract_compatible"] is True
