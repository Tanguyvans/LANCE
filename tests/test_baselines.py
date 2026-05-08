import json

from src.baselines.external_benchmarks import discover_cases, run_case, write_manifest
from src.baselines.normalizer import normalize_tool_outputs, write_vuln_analysis
from src.baselines.runner import run_baseline
from src.baselines.scenarios import load_ground_truth_targets, load_scenario_targets
from src.agent_external import run_external_target
from src.benchmark.evaluator import evaluate


def test_load_scenario_targets_includes_router_and_services():
    targets = load_scenario_targets("1")

    assert targets[0].ip == "192.168.100.1"
    assert targets[0].role == "router"
    assert [t.ip for t in targets[1:]] == [
        "192.168.100.11",
        "192.168.100.12",
        "192.168.100.13",
    ]


def test_load_ground_truth_targets_returns_unique_eval_ips():
    targets = load_ground_truth_targets("3")

    assert targets[0].source == "ground_truth"
    assert len({t.ip for t in targets}) == len(targets)
    assert "192.168.100.1" in {t.ip for t in targets}


def test_normalize_tool_outputs_accepts_common_aliases(tmp_path):
    raw = tmp_path / "result.json"
    raw.write_text(
        json.dumps(
            {
                "results": [
                    {
                        "host": "192.168.100.12",
                        "category": "default_credentials",
                        "risk": "high",
                        "proof": "login succeeded",
                    }
                ]
            }
        )
    )

    findings = normalize_tool_outputs("pentgpt", [(None, raw)])

    assert findings == [
        {
            "id": "PENTGPT-001",
            "device_id": "192.168.100.12",
            "device_ip": "192.168.100.12",
            "type": "default_credentials",
            "severity": "HIGH",
            "details": "",
            "evidence": "login succeeded",
            "evidence_level": 1,
            "cve_ids": [],
            "source_tool": "pentgpt",
        }
    ]


def test_baseline_vuln_analysis_is_evaluator_compatible(tmp_path):
    run_dir = tmp_path / "baseline"
    gt = tmp_path / "gt.yaml"
    gt.write_text(
        """
scenario_id: 1
vulnerabilities:
  - id: GT-001
    title: MQTT sans auth
    device: mqtt
    ip: 192.168.100.11
    severity: high
    category: no_authentication
    hop_depth: 0
scoring:
  weights:
    critical: 4
    high: 3
    medium: 2
    low: 1
"""
    )
    write_vuln_analysis(
        "cai",
        "1",
        [
            {
                "id": "CAI-001",
                "device_id": "S1-mqtt",
                "device_ip": "192.168.100.11",
                "type": "no_auth",
                "severity": "HIGH",
                "details": "MQTT anonymous access",
                "evidence": "mosquitto_sub succeeded",
                "evidence_level": 2,
                "cve_ids": [],
            }
        ],
        run_dir,
    )

    result = evaluate(run_dir, gt)

    assert result.total_llm_findings == 1
    assert result.true_positives == 1


def test_external_xbow_discovery_reads_metadata_and_target_port(tmp_path):
    case = tmp_path / "benchmarks" / "XBEN-001-24"
    (case / "benchmark").mkdir(parents=True)
    (case / "benchmark" / "benchmark-config.json").write_text(
        json.dumps(
            {
                "name": "XBEN-001-24",
                "description": "SQL injection",
                "level": 1,
                "tags": ["sqli", "web"],
            }
        )
    )
    (case / "docker-compose.yml").write_text(
        """
services:
  app:
    image: nginx
    ports:
      - "127.0.0.1:8081:80"
"""
    )

    cases = discover_cases("xbow", tmp_path)

    assert len(cases) == 1
    assert cases[0].case_id == "XBEN-001-24"
    assert cases[0].target_url == "http://127.0.0.1:8081"
    assert cases[0].tags == ("sqli", "web")


def test_external_autopenbench_discovers_games_json_tasks(tmp_path):
    (tmp_path / "data").mkdir()
    machine = tmp_path / "benchmark" / "machines" / "in-vitro" / "recon"
    machine.mkdir(parents=True)
    (tmp_path / "data" / "games.json").write_text(
        json.dumps(
            {
                "in-vitro": {
                    "recon": [
                        {
                            "alias": "Recon easy",
                            "target": "target1",
                            "task": "Find the exposed service flag",
                            "vulnerability": "weak credentials",
                            "flag": "FLAG{autopenbench}",
                        }
                    ]
                }
            }
        )
    )
    (machine / "docker-compose.yml").write_text(
        """
services:
  target1:
    image: nginx
    ports:
      - "8082:80"
"""
    )

    cases = discover_cases("autopenbench", tmp_path)

    assert len(cases) == 1
    assert cases[0].case_id == "in-vitro_recon_target1"
    assert cases[0].task == "Find the exposed service flag"
    assert cases[0].target == "target1"
    assert cases[0].expected_flag == "FLAG{autopenbench}"
    assert cases[0].target_url == "http://127.0.0.1:8082"
    assert cases[0].runnable is True


def test_external_vulhub_discovery_uses_relative_case_id(tmp_path):
    case = tmp_path / "struts2" / "s2-045"
    case.mkdir(parents=True)
    (case / "README.md").write_text("# Apache Struts2 S2-045 Remote Code Execution\n")
    (case / "docker-compose.yml").write_text(
        """
services:
  struts2:
    image: vulhub/struts2
    ports:
      - "127.0.0.1:8083:8080"
"""
    )

    cases = discover_cases("vulhub", tmp_path)

    assert len(cases) == 1
    assert cases[0].case_id == "struts2/s2-045"
    assert cases[0].description == "Apache Struts2 S2-045 Remote Code Execution"
    assert cases[0].target_url == "http://127.0.0.1:8083"
    assert cases[0].tags == ("struts2",)


def test_external_manifest_and_dry_run(tmp_path):
    case = tmp_path / "benchmarks" / "XBEN-002-24"
    (case / "benchmark").mkdir(parents=True)
    (case / "benchmark" / "benchmark-config.json").write_text(json.dumps({"name": "XBEN-002-24"}))
    (case / "docker-compose.yml").write_text("services: {}\n")

    manifest = write_manifest("xbow", tmp_path, tmp_path / "manifest.json")
    run_dir = run_case(
        suite="xbow",
        repo=tmp_path,
        case_id="XBEN-002-24",
        agent_command="echo {suite} {case_id} {target_url} {flag} {output_dir}",
        output_dir=tmp_path / "runs",
        flag="FLAG-test",
        dry_run=True,
    )

    manifest_data = json.loads(manifest.read_text())
    result = json.loads((run_dir / "result.json").read_text())

    assert manifest_data["case_count"] == 1
    assert result["status"] == "dry_run"
    assert "FLAG-test" in result["agent_command"]


def test_external_vulhub_dry_run_has_no_build_step(tmp_path):
    case = tmp_path / "redis" / "CVE-2022-0543"
    case.mkdir(parents=True)
    (case / "docker-compose.yml").write_text("services: {redis: {image: redis, ports: ['6379:6379']}}\n")

    run_dir = run_case(
        suite="vulhub",
        repo=tmp_path,
        case_id="redis/CVE-2022-0543",
        agent_command="echo {suite} {case_id} {target_url} {flag}",
        output_dir=tmp_path / "runs",
        flag="FLAG-vulhub",
        dry_run=True,
    )

    result = json.loads((run_dir / "result.json").read_text())

    assert result["status"] == "dry_run"
    assert result["build_command"] is None
    assert "FLAG-vulhub" in result["agent_command"]


def test_external_agent_dry_run_writes_artifacts(tmp_path):
    output_dir = run_external_target(
        target="http://127.0.0.1:8080",
        output_dir=tmp_path / "external-agent",
        provider_name="minimax",
        model=None,
        max_turns=1,
        dry_run=True,
    )

    assert (output_dir / "external_agent_prompt.txt").exists()
    assert "DRY RUN" in (output_dir / "external_agent_answer.txt").read_text()


def test_parallel_baseline_dry_run_writes_all_targets(tmp_path):
    run_dir = run_baseline(
        tool="cai",
        scenario_id="1",
        baseline_host="root@example",
        max_turns=1,
        output_dir=tmp_path,
        dry_run=True,
        quiet=True,
        jobs=2,
    )

    metadata = json.loads((run_dir / "metadata.json").read_text())
    raw_files = list((run_dir / "raw").glob("*.json"))

    assert metadata["jobs"] == 2
    assert metadata["target_count"] == len(raw_files)
    assert metadata["target_count"] > 1
