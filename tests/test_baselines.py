import json

from src.baselines.external_benchmarks import (
    DEFAULT_REMOTE_JOB_DIR,
    DEFAULT_REMOTE_OUTPUT_DIR,
    DEFAULT_REMOTE_PROJECT_DIR,
    build_detached_job_payload,
    build_detached_shell_runner,
    build_detached_job_runner,
    default_external_agent_command,
    discover_cases,
    external_agent_command,
    generate_report,
    infer_context_mode_from_command,
    run_case,
    summarize_run_dir,
    write_run_proof,
    write_manifest,
    _render_agent_command,
)
from src.baselines.normalizer import normalize_tool_outputs, write_vuln_analysis
from src.baselines.runner import run_baseline
from src.baselines.scenarios import load_ground_truth_targets, load_scenario_targets
from src.baselines.service_intel import service_intel_for_port
from src.baselines.service_intel import service_intelligence_for_target
from src.agent_external import (
    _make_submit_tool,
    classify_from_submission,
    run_external_target,
)
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


def test_external_vulhub_non_http_port_keeps_protocol_context(tmp_path):
    case = tmp_path / "activemq" / "CVE-2016-3088"
    case.mkdir(parents=True)
    (case / "docker-compose.yml").write_text("services: {mq: {image: activemq, ports: ['61616:61616']}}\n")

    cases = discover_cases("vulhub", tmp_path)

    assert cases[0].target_url is None
    assert cases[0].target_endpoint == "127.0.0.1:61616"
    assert cases[0].target_service == "activemq-openwire"
    assert "not HTTP" in cases[0].service_context


def test_external_vulhub_prefers_specific_broker_port_and_keeps_all_services(tmp_path):
    case = tmp_path / "activemq" / "CVE-2016-3088"
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# ActiveMQ Arbitrary File Write\n\nUse the web console and OpenWire broker.\n"
    )
    (case / "docker-compose.yml").write_text(
        """
services:
  activemq:
    image: vulhub/activemq
    ports:
      - "8161:8161"
      - "61616:61616"
"""
    )

    cases = discover_cases("vulhub", tmp_path)

    assert cases[0].target_endpoint == "127.0.0.1:61616"
    assert cases[0].target_service == "activemq-openwire"
    assert len(cases[0].exposed_services) == 2
    assert any(item["service"] == "activemq-web" for item in cases[0].exposed_services)
    assert cases[0].case_context == ""


def test_external_fair_command_does_not_inject_repo_context(tmp_path):
    case = tmp_path / "demo" / "CVE-2099-0002"
    case.mkdir(parents=True)
    (case / "README.md").write_text("# Secret Oracle Exploit Steps\n\nUse password leaked-in-readme.\n")
    (case / "docker-compose.yml").write_text("services: {app: {image: nginx, ports: ['18080:80']}}\n")
    benchmark = discover_cases("vulhub", tmp_path)[0]

    command = _render_agent_command(
        "python -m src.agent_external --target {target_or_url} --hint 'Policy {context_policy}. CVE {vulnerability}. {service_context}. Do not use repository README.' --output-dir {output_dir}",
        benchmark,
        tmp_path / "out",
        "",
    )
    rendered = " ".join(command)

    assert "fair_network_only" in rendered
    assert "leaked-in-readme" not in rendered
    assert "Secret Oracle Exploit Steps" not in rendered


def test_external_blind_command_omits_case_id_and_cve():
    command = external_agent_command(context_mode="blind")

    assert "{case_id}" not in command
    assert "{vulnerability}" not in command
    assert infer_context_mode_from_command(command) == "blind"


def test_external_informed_command_is_labeled():
    command = external_agent_command(context_mode="informed")

    assert "{case_id}" in command
    assert "{vulnerability}" in command
    assert infer_context_mode_from_command(command) == "informed"


def test_external_compose_long_port_syntax_uses_target_service_port(tmp_path):
    case = tmp_path / "webapp" / "CVE-2099-0001"
    case.mkdir(parents=True)
    (case / "docker-compose.yml").write_text(
        """
services:
  app:
    image: example/app
    ports:
      - target: 80
        published: 18080
        protocol: tcp
"""
    )

    cases = discover_cases("vulhub", tmp_path)

    assert cases[0].target_url == "http://127.0.0.1:18080"
    assert cases[0].target_endpoint == "http://127.0.0.1:18080"
    assert cases[0].target_service == "http"
    assert "mapped to container port 80/tcp" in cases[0].service_context


def test_service_intel_falls_back_to_system_registry_for_known_ports():
    intel = service_intel_for_port(123)

    assert intel.service in {"ntp", "unknown"}
    if intel.service == "ntp":
        assert intel.source in {"nmap-services", "system-services"}


def test_service_intelligence_adds_protocol_specific_playbook():
    context = service_intelligence_for_target(
        "127.0.0.1:61616",
        "Primary exposed service: activemq-openwire. Protocol: openwire.",
    )

    assert "Service playbook" in context
    assert "do not curl this port" in context
    assert "blocked_missing_tool" in context


def test_detached_job_payload_is_remote_only_and_fair():
    payload = build_detached_job_payload(
        job_id="vulhub_20990101_000000",
        suite="vulhub",
        repo="/opt/external-benchmarks/vulhub",
        cases=["1panel/CVE-2024-39907"],
        agent_command=default_external_agent_command(),
        context_mode="blind",
    )

    assert payload["project_dir"] == str(DEFAULT_REMOTE_PROJECT_DIR)
    assert payload["remote_output_dir"] == str(DEFAULT_REMOTE_OUTPUT_DIR)
    assert payload["job_dir"].startswith(str(DEFAULT_REMOTE_JOB_DIR))
    assert payload["context_policy"] == "fair_network_only"
    assert payload["context_mode"] == "blind"
    assert payload["oracle_repo_context_injected"] is False
    assert payload["docker_cleanup"] is True
    assert payload["min_free_gb"] > 0
    assert "/Users/" not in json.dumps(payload)


def test_detached_shell_runner_uses_remote_project_and_tmux_runner_shape():
    payload = build_detached_job_payload(
        job_id="vulhub_20990101_000000",
        suite="vulhub",
        repo="/opt/external-benchmarks/vulhub",
        cases=["activemq/CVE-2015-5254"],
        agent_command=default_external_agent_command(),
    )
    shell = build_detached_shell_runner(payload)
    runner = build_detached_job_runner()

    assert "cd /opt/nato-smartcity-iot" in shell
    assert "/opt/baseline-tools/.env" in shell
    assert "src.baselines.external_benchmarks" in runner
    assert "--docker-cleanup" in runner
    assert "--min-free-gb" in runner
    assert "--remote-host" not in runner
    assert "/Users/" not in shell + runner


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
    proof = json.loads((output_dir / "proof.json").read_text())
    cost = json.loads((output_dir / "cost_summary.json").read_text())
    result = json.loads((output_dir / "external_agent_result.json").read_text())
    assert proof["outcome"] == "dry_run"
    assert proof["fair_policy"]["context_policy"] == "fair_network_only"
    assert cost["total_input_tokens"] == 0
    assert result["total_tokens"] == 0


def test_external_proof_classifies_environment_and_report_aggregates(tmp_path):
    run_dir = tmp_path / "output" / "external_benchmarks" / "vulhub" / "redis" / "CVE-2022-0543" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "redis/CVE-2022-0543",
                    "target_endpoint": "127.0.0.1:6379",
                    "target_service": "redis",
                    "vulnerability": "CVE-2022-0543",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(
        json.dumps({"status": "environment_failed", "success": False, "duration_seconds": 3.0})
    )
    (run_dir / "agent_stderr.txt").write_text("failed to register layer: no space left on device")

    summary = summarize_run_dir(run_dir)
    report = generate_report(tmp_path / "output" / "external_benchmarks")

    assert summary["outcome"] == "environment_failed"
    assert summary["blocked_by"] == "environment"
    assert report["environment_failed"] == 1
    assert "redis/CVE-2022-0543" in report["rerun_cases"]


def test_external_proof_classifies_missing_tool(tmp_path):
    run_dir = tmp_path / "output" / "external_benchmarks" / "vulhub" / "activemq" / "CVE-2015-5254" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "activemq/CVE-2015-5254",
                    "target_endpoint": "127.0.0.1:61616",
                    "target_service": "activemq-openwire",
                    "vulnerability": "CVE-2015-5254",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "external_agent_answer.txt").write_text("The service appears vulnerable, but exploitation needs a JMS client or ysoserial.")

    summary = summarize_run_dir(run_dir)

    assert summary["outcome"] == "blocked_missing_tool"
    assert summary["blocked_by"] == "missing_tool"


def test_external_proof_does_not_confirm_negative_report(tmp_path):
    run_dir = tmp_path / "output" / "external_benchmarks" / "vulhub" / "apache-cxf" / "CVE-2024-28752" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "apache-cxf/CVE-2024-28752",
                    "target_url": "http://127.0.0.1:8080",
                    "target_service": "http",
                    "vulnerability": "CVE-2024-28752",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "external_agent_answer.txt").write_text(
        "Jetty is running, but there are no CXF endpoints deployed. "
        "The vulnerable version alone is not enough and exploitation cannot be confirmed."
    )

    summary = summarize_run_dir(run_dir)

    assert summary["outcome"] == "no_finding"
    assert summary["confidence"] == "high"


def test_external_proof_does_not_preserve_stale_confirmed_outcome(tmp_path):
    run_dir = tmp_path / "output" / "external_benchmarks" / "vulhub" / "cacti" / "CVE-2022-46169" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "cacti/CVE-2022-46169",
                    "target_url": "http://127.0.0.1:8080",
                    "target_service": "http",
                    "vulnerability": "CVE-2022-46169",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "proof.json").write_text(json.dumps({"outcome": "confirmed_exploit", "confidence": "high"}))
    (run_dir / "external_agent_answer.txt").write_text(
        "The vulnerable endpoint is present, but every request returns not authorized. "
        "I cannot confirm exploitation without valid credentials."
    )

    proof = write_run_proof(run_dir)

    assert proof["outcome"] == "blocked_missing_credentials"
    assert proof["blocked_by"] == "missing_credentials"


def test_external_proof_does_not_confirm_theoretical_proof_only(tmp_path):
    run_dir = tmp_path / "output" / "external_benchmarks" / "vulhub" / "demo" / "CVE-2099-0001" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "demo/CVE-2099-0001",
                    "target_url": "http://127.0.0.1:8080",
                    "target_service": "http",
                    "vulnerability": "CVE-2099-0001",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "external_agent_answer.txt").write_text(
        "This is a proof of exploitability in theory because the version is vulnerable, "
        "but no target-derived evidence was observed."
    )

    summary = summarize_run_dir(run_dir)

    assert summary["outcome"] == "probable_vulnerability"
    assert summary["confidence"] == "medium"


def test_submit_tool_writes_structured_submission(tmp_path):
    submission_path = tmp_path / "submission.json"
    tool = _make_submit_tool(submission_path)

    assert tool["name"] == "submit_final_assessment"
    assert "label" in tool["input_schema"]["properties"]
    assert "blocked_by" in tool["input_schema"]["properties"]

    result = tool["function"](
        label="CONFIRMED",
        service="elasticsearch 1.5.1",
        evidence="GET /_search?source=... returned uid=0(root)",
        blocked_by="none",
        next_step="",
        flag="",
    )

    payload = json.loads(result)
    assert payload == {"status": "submission_recorded", "label": "CONFIRMED"}
    saved = json.loads(submission_path.read_text(encoding="utf-8"))
    assert saved["label"] == "CONFIRMED"
    assert saved["service"] == "elasticsearch 1.5.1"
    assert saved["blocked_by"] == "none"


def test_submit_tool_rejects_unknown_label(tmp_path):
    submission_path = tmp_path / "submission.json"
    tool = _make_submit_tool(submission_path)

    raw = tool["function"](
        label="MAYBE",
        service="redis",
        evidence="none",
        blocked_by="none",
    )

    parsed = json.loads(raw)
    assert "error" in parsed
    assert not submission_path.exists()


def test_submit_tool_rejects_unknown_blocked_by(tmp_path):
    submission_path = tmp_path / "submission.json"
    tool = _make_submit_tool(submission_path)

    raw = tool["function"](
        label="BLOCKED_MISSING_TOOL",
        service="activemq-openwire",
        evidence="port 61616 reachable",
        blocked_by="ysoserial",
    )

    assert "error" in json.loads(raw)
    assert not submission_path.exists()


def test_classify_from_submission_maps_labels_to_outcomes():
    metadata = {"target": "http://127.0.0.1:9200", "service_intelligence": ""}

    proof = classify_from_submission(
        {
            "label": "CONFIRMED",
            "service": "elasticsearch",
            "evidence": "Read /etc/passwd via _search",
            "blocked_by": "none",
            "flag": "",
        },
        metadata,
    )

    assert proof["outcome"] == "confirmed_exploit"
    assert proof["confidence"] == "high"
    assert proof["blocked_by"] == ""
    assert proof["submission_source"] == "structured"

    blocked = classify_from_submission(
        {
            "label": "BLOCKED_MISSING_TOOL",
            "service": "activemq-openwire",
            "evidence": "none",
            "blocked_by": "missing_tool",
        },
        metadata,
    )

    assert blocked["outcome"] == "blocked_missing_tool"
    assert blocked["blocked_by"] == "missing_tool"


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
