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
    AUTOPENBENCH_NETWORK,
    _autopenbench_standalone_compose,
    _build_command,
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
from src.baselines.fleet import (
    DistributedJob,
    HostJob,
    fleet_fetch,
    fleet_status,
    fleet_stop,
    load_cases_from_file,
    load_distributed_job,
    merge_distributed_results,
    parse_hosts_arg,
    save_distributed_job,
    shard_cases,
    start_distributed_job,
)
from src.baselines import store
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


def _make_autopenbench_repo(tmp_path):
    """Build a minimal autopenbench repo where the compose service name matches
    the case_id (as in the real upstream `games.json`)."""
    (tmp_path / "data").mkdir()
    machines = tmp_path / "benchmark" / "machines" / "in-vitro" / "access_control"
    machines.mkdir(parents=True)
    (tmp_path / "data" / "games.json").write_text(
        json.dumps(
            {
                "in-vitro": {
                    "access_control": [
                        {
                            "target": "in-vitro_access_control_vm0",
                            "task": "Escalate to root",
                            "vulnerability": "sudoers",
                            "flag": "FLAG{apb}",
                        },
                        {
                            "target": "in-vitro_access_control_vm1",
                            "task": "Other VM",
                            "vulnerability": "setuid",
                            "flag": "FLAG{other}",
                        },
                    ]
                }
            }
        )
    )
    # build/volume paths are anchored at benchmark/machines/ (upstream layout).
    (machines / "docker-compose.yml").write_text(
        """
services:
  in-vitro_access_control_vm0:
    build: ./in-vitro/access_control/vm0
    image: in-vitro_access_control_vm0
    container_name: in-vitro_access_control_vm0
    cap_add:
      - NET_ADMIN
    networks:
      net-main_network:
        ipv4_address: 192.168.1.0
    volumes:
      - ./in-vitro/access_control/vm0/flag:/root/flag
  in-vitro_access_control_vm1:
    build: ./in-vitro/access_control/vm1
    networks:
      net-main_network:
        ipv4_address: 192.168.1.1
networks:
  net-main_network:
    ipam:
      config:
        - subnet: 192.168.0.0/16
"""
    )
    return tmp_path


def test_autopenbench_standalone_compose_single_service(tmp_path):
    import yaml
    from pathlib import Path

    repo = _make_autopenbench_repo(tmp_path)
    cases = {c.case_id: c for c in discover_cases("autopenbench", repo)}
    case = cases["in-vitro_access_control_vm0"]
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    compose_path = _autopenbench_standalone_compose(case, run_dir)
    data = yaml.safe_load(compose_path.read_text())

    # only the targeted VM, none of its siblings
    assert list(data["services"]) == ["in-vitro_access_control_vm0"]
    svc = data["services"]["in-vitro_access_control_vm0"]
    # rehomed onto a dedicated network, static 192.168.x IP dropped
    assert svc["networks"] == [AUTOPENBENCH_NETWORK]
    # no pinned subnet -> Docker auto-allocates (172.x), avoids pool overlaps
    assert "ipam" not in (data["networks"][AUTOPENBENCH_NETWORK] or {})
    assert "192.168" not in compose_path.read_text()
    # service definition copied verbatim otherwise (cap_add preserved)
    assert svc["cap_add"] == ["NET_ADMIN"]
    assert svc["container_name"] == "nato-apb-in-vitro_access_control_vm0"
    # relative build context / volumes made absolute, anchored at machines/
    assert Path(svc["build"]).is_absolute()
    assert svc["build"].endswith("/benchmark/machines/in-vitro/access_control/vm0")
    assert svc["volumes"][0].startswith(str(repo))
    assert svc["volumes"][0].endswith("/benchmark/machines/in-vitro/access_control/vm0/flag:/root/flag")


def test_autopenbench_build_command_targets_generated_compose(tmp_path):
    repo = _make_autopenbench_repo(tmp_path)
    case = {c.case_id: c for c in discover_cases("autopenbench", repo)}["in-vitro_access_control_vm0"]
    generated = tmp_path / "autopenbench-compose.yml"

    cmd = _build_command(case, "", compose_file=generated)

    # The generated compose already holds only the target + deps, so build is
    # unscoped (builds everything in that minimal file).
    assert cmd is not None
    assert cmd[-1] == "build"
    assert str(generated) in cmd


def test_autopenbench_standalone_compose_includes_depends_on(tmp_path):
    """A machine with a paired database must keep its depends_on service."""
    import yaml

    (tmp_path / "data").mkdir()
    machines = tmp_path / "benchmark" / "machines" / "in-vitro" / "web_security"
    machines.mkdir(parents=True)
    (tmp_path / "data" / "games.json").write_text(
        json.dumps(
            {
                "in-vitro": {
                    "web_security": [
                        {"target": "in-vitro_web_security_vm3", "task": "t", "vulnerability": "sqli", "flag": "F"}
                    ]
                }
            }
        )
    )
    (machines / "docker-compose.yml").write_text(
        """
services:
  in-vitro_web_security_vm3:
    build: ./in-vitro/web_security/vm3
    depends_on:
      - in-vitro_web_security_vm3_database
    networks:
      net-main_network:
        ipv4_address: 192.168.2.3
  in-vitro_web_security_vm3_database:
    build: ./in-vitro/web_security/vm3_database
    networks:
      net-main_network:
        ipv4_address: 192.168.2.4
networks:
  net-main_network:
    ipam:
      config:
        - subnet: 192.168.0.0/16
"""
    )
    case = {c.case_id: c for c in discover_cases("autopenbench", tmp_path)}["in-vitro_web_security_vm3"]
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    compose_path = _autopenbench_standalone_compose(case, run_dir)
    data = yaml.safe_load(compose_path.read_text())

    # both the target and its database service are present
    assert set(data["services"]) == {
        "in-vitro_web_security_vm3",
        "in-vitro_web_security_vm3_database",
    }
    target = data["services"]["in-vitro_web_security_vm3"]
    db = data["services"]["in-vitro_web_security_vm3_database"]
    # depends_on preserved, both on the safe network
    assert target["depends_on"] == ["in-vitro_web_security_vm3_database"]
    assert target["networks"] == ["nato_apb_net"]
    assert db["networks"] == ["nato_apb_net"]
    # only the target keeps the stable container name used for IP resolution
    assert target["container_name"] == "nato-apb-in-vitro_web_security_vm3"
    assert "container_name" not in db
    assert "192.168" not in compose_path.read_text()


def test_autopenbench_run_case_dry_run_uses_generated_compose(tmp_path):
    repo = _make_autopenbench_repo(tmp_path)

    run_dir = run_case(
        suite="autopenbench",
        repo=repo,
        case_id="in-vitro_access_control_vm0",
        agent_command="echo {suite} {case_id} {target_or_url} {flag}",
        output_dir=tmp_path / "runs",
        dry_run=True,
    )

    result = json.loads((run_dir / "result.json").read_text())
    assert result["status"] == "dry_run"
    compose_file = result["compose_file"]
    assert compose_file.endswith("autopenbench-compose.yml")
    assert (run_dir / "autopenbench-compose.yml").exists()
    # commands point at the generated compose, not the upstream multi-VM file
    assert compose_file in result["build_command"]
    assert compose_file in result["up_command"]
    assert compose_file in result["down_command"]
    assert result["up_command"][-1] == "--wait"


def test_render_agent_command_target_override(tmp_path):
    repo = _make_autopenbench_repo(tmp_path)
    case = {c.case_id: c for c in discover_cases("autopenbench", repo)}["in-vitro_access_control_vm0"]

    overridden = _render_agent_command(
        "run --target {target_or_url} --alt {target}", case, tmp_path, "FLAG{apb}",
        target_override="10.210.0.5",
    )
    assert "10.210.0.5" in overridden
    assert "in-vitro_access_control_vm0" not in overridden

    # without an override the autopenbench case has no port -> service name fallback
    plain = _render_agent_command("run --target {target_or_url}", case, tmp_path, "FLAG{apb}")
    assert "in-vitro_access_control_vm0" in plain


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


def test_shard_cases_round_robin_distributes_evenly():
    cases = [f"c{i}" for i in range(10)]
    hosts = ["h1", "h2", "h3"]

    shards = shard_cases(cases, hosts, strategy="round-robin")

    assert shards["h1"] == ["c0", "c3", "c6", "c9"]
    assert shards["h2"] == ["c1", "c4", "c7"]
    assert shards["h3"] == ["c2", "c5", "c8"]
    assert sum(len(v) for v in shards.values()) == len(cases)


def test_shard_cases_empty_hosts_raises():
    import pytest

    with pytest.raises(ValueError):
        shard_cases(["c1"], [], strategy="round-robin")


def test_shard_cases_load_aware_balances_better_than_round_robin(tmp_path):
    cases = ["slow1", "slow2", "fast1", "fast2", "fast3", "fast4"]
    durations = {"slow1": 1000.0, "slow2": 1000.0, "fast1": 10.0, "fast2": 10.0, "fast3": 10.0, "fast4": 10.0}
    path = tmp_path / "durations.json"
    path.write_text(json.dumps(durations), encoding="utf-8")
    hosts = ["h1", "h2"]

    rr = shard_cases(cases, hosts, strategy="round-robin")
    la = shard_cases(cases, hosts, strategy="load-aware", durations_path=path)

    def max_load(shards):
        return max(sum(durations[c] for c in shard) for shard in shards.values())

    assert max_load(la) <= max_load(rr)
    # Load-aware should split the two slow cases across hosts.
    assert {"slow1", "slow2"} != set(la["h1"])
    assert {"slow1", "slow2"} != set(la["h2"])


def test_shard_cases_load_aware_falls_back_when_no_durations(tmp_path):
    cases = ["c0", "c1", "c2", "c3"]
    hosts = ["h1", "h2"]

    la = shard_cases(cases, hosts, strategy="load-aware", durations_path=tmp_path / "missing.json")
    rr = shard_cases(cases, hosts, strategy="round-robin")

    assert la == rr


def test_start_distributed_job_dispatches_per_host(tmp_path, monkeypatch):
    cases = ["c0", "c1", "c2", "c3", "c4"]
    hosts = ["root@h1", "root@h2"]
    seen_calls: list[dict] = []

    def fake_starter(*, baseline_host, suite, cases, **kwargs):
        seen_calls.append({"host": baseline_host, "suite": suite, "cases": list(cases)})
        return {
            "job_id": f"{suite}-{baseline_host}",
            "session": f"sess-{baseline_host}",
            "job_dir": f"/tmp/{suite}-{baseline_host}",
        }

    job = start_distributed_job(
        hosts=hosts,
        suite="vulhub",
        cases=cases,
        repo=tmp_path / "repo",
        output_dir=tmp_path / "distributed",
        sync_project=False,
        starter=fake_starter,
    )

    assert len(seen_calls) == 2
    assert {c["host"] for c in seen_calls} == set(hosts)
    by_host = {c["host"]: c["cases"] for c in seen_calls}
    assert by_host["root@h1"] == ["c0", "c2", "c4"]
    assert by_host["root@h2"] == ["c1", "c3"]
    assert job.cases_total == 5
    assert all(hj.job_id for hj in job.host_jobs)
    persisted = json.loads((job.local_dir / "distributed_job.json").read_text())
    assert persisted["distributed_job_id"] == job.distributed_job_id
    assert len(persisted["host_jobs"]) == 2


def test_start_distributed_job_dry_run_does_not_call_starter(tmp_path):
    def boom(**kwargs):
        raise AssertionError("dry_run must not invoke starter")

    job = start_distributed_job(
        hosts=["root@h1", "root@h2"],
        suite="vulhub",
        cases=["c0", "c1"],
        repo=tmp_path / "repo",
        output_dir=tmp_path / "distributed",
        dry_run=True,
        starter=boom,
    )

    assert all(hj.status == "dry_run" for hj in job.host_jobs)


def test_start_distributed_job_records_starter_failure(tmp_path):
    def fail_one(*, baseline_host, **kwargs):
        if baseline_host == "root@h2":
            raise RuntimeError("ssh refused")
        return {"job_id": "ok", "session": "s", "job_dir": "/tmp/ok"}

    job = start_distributed_job(
        hosts=["root@h1", "root@h2"],
        suite="vulhub",
        cases=["c0", "c1"],
        repo=tmp_path / "repo",
        output_dir=tmp_path / "distributed",
        starter=fail_one,
    )

    statuses = {hj.baseline_host: hj.status for hj in job.host_jobs}
    assert statuses["root@h1"] == "running"
    assert statuses["root@h2"] == "failed"


def test_fleet_status_aggregates_outcomes(tmp_path):
    job = DistributedJob(
        distributed_job_id="dist-vulhub-test",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0", "c2"], job_id="j1", status="running"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="j2", status="running"),
        ],
        local_dir=tmp_path / "distributed" / "dist-vulhub-test",
        cases_total=3,
    )
    save_distributed_job(job)

    def fake_status(host, job_id):
        if host == "root@h1":
            return {
                "status": "running",
                "completed": 1,
                "useful_findings": 1,
                "outcome_counts": {"confirmed_exploit": 1, "max_turns": 1},
                "estimated_cost_usd": 0.12,
                "total_tokens": 1000,
            }
        return {
            "status": "completed",
            "completed": 1,
            "useful_findings": 0,
            "outcome_counts": {"no_finding": 1},
            "estimated_cost_usd": 0.05,
            "total_tokens": 500,
        }

    fleet = fleet_status(job.distributed_job_id, output_dir=tmp_path / "distributed", status_fn=fake_status)

    assert fleet.aggregate["cases_total"] == 3
    assert fleet.aggregate["cases_completed"] == 2
    assert fleet.aggregate["outcome_counts"] == {"confirmed_exploit": 1, "max_turns": 1, "no_finding": 1}
    assert fleet.aggregate["estimated_cost_usd"] == 0.17
    assert fleet.aggregate["total_tokens"] == 1500


def test_fleet_status_tolerates_unreachable_host(tmp_path):
    job = DistributedJob(
        distributed_job_id="dist-vulhub-unreachable",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0"], job_id="j1", status="running"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="j2", status="running"),
        ],
        local_dir=tmp_path / "distributed" / "dist-vulhub-unreachable",
        cases_total=2,
    )
    save_distributed_job(job)

    def flaky(host, job_id):
        if host == "root@h2":
            raise RuntimeError("ssh timeout")
        return {"status": "running", "completed": 1, "outcome_counts": {"confirmed_exploit": 1}}

    fleet = fleet_status(job.distributed_job_id, output_dir=tmp_path / "distributed", status_fn=flaky)

    statuses = {hj.baseline_host: hj.status for hj in fleet.hosts}
    assert statuses["root@h1"] == "running"
    assert statuses["root@h2"] == "unreachable"
    assert fleet.aggregate["cases_completed"] == 1
    assert fleet.aggregate["outcome_counts"] == {"confirmed_exploit": 1}


def test_fleet_stop_calls_stop_per_host(tmp_path):
    job = DistributedJob(
        distributed_job_id="dist-vulhub-stop",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0"], job_id="j1", status="running"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="j2", status="running"),
        ],
        local_dir=tmp_path / "distributed" / "dist-vulhub-stop",
        cases_total=2,
    )
    save_distributed_job(job)
    stopped: list[tuple[str, str]] = []

    def fake_stop(host, job_id):
        stopped.append((host, job_id))

    outcomes = fleet_stop(job.distributed_job_id, output_dir=tmp_path / "distributed", stop_fn=fake_stop)

    assert {h for h, _ in stopped} == {"root@h1", "root@h2"}
    assert outcomes == {"root@h1": "stopped", "root@h2": "stopped"}
    reloaded = load_distributed_job(job.distributed_job_id, output_dir=tmp_path / "distributed")
    assert all(hj.status == "stopped" for hj in reloaded.host_jobs)


def test_merge_distributed_results_aggregates_host_summaries(tmp_path):
    output_dir = tmp_path / "distributed"
    base_results = tmp_path / "results"
    job = DistributedJob(
        distributed_job_id="dist-vulhub-merge",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0", "c2"], job_id="job-h1", status="completed"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="job-h2", status="completed"),
        ],
        local_dir=output_dir / "dist-vulhub-merge",
        cases_total=3,
    )
    save_distributed_job(job)

    h1_summary = {
        "items": [
            {"case_id": "c0", "outcome": "confirmed_exploit"},
            {"case_id": "c2", "outcome": "max_turns"},
        ],
        "status_counts": {"completed": 2},
        "outcome_counts": {"confirmed_exploit": 1, "max_turns": 1},
        "useful_findings": 1,
        "estimated_cost_usd": 0.12,
        "total_tokens": 1000,
    }
    h2_summary = {
        "items": [{"case_id": "c1", "outcome": "no_finding"}],
        "status_counts": {"completed": 1},
        "outcome_counts": {"no_finding": 1},
        "useful_findings": 0,
        "estimated_cost_usd": 0.05,
        "total_tokens": 500,
    }
    (base_results / "jobs" / "job-h1").mkdir(parents=True)
    (base_results / "jobs" / "job-h1" / "summary.json").write_text(json.dumps(h1_summary), encoding="utf-8")
    (base_results / "jobs" / "job-h2").mkdir(parents=True)
    (base_results / "jobs" / "job-h2" / "summary.json").write_text(json.dumps(h2_summary), encoding="utf-8")

    target = merge_distributed_results(
        job.distributed_job_id,
        output_dir=output_dir,
        base_results_dir=base_results,
    )

    merged = json.loads(target.read_text())
    assert merged["totals"]["cases_total"] == 3
    assert merged["totals"]["cases_completed"] == 3
    assert merged["totals"]["outcome_counts"] == {"confirmed_exploit": 1, "max_turns": 1, "no_finding": 1}
    assert merged["totals"]["useful_findings"] == 1
    assert merged["totals"]["estimated_cost_usd"] == 0.17
    assert {item["source_host"] for item in merged["items"]} == {"root@h1", "root@h2"}
    assert len(merged["items"]) == 3


def test_fleet_fetch_partial_failure_writes_manifest_and_merges(tmp_path):
    output_dir = tmp_path / "distributed"
    base_results = tmp_path / "results"
    job = DistributedJob(
        distributed_job_id="dist-vulhub-partial",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0"], job_id="job-h1", status="completed"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="job-h2", status="completed"),
        ],
        local_dir=output_dir / "dist-vulhub-partial",
        cases_total=2,
    )
    save_distributed_job(job)
    (base_results / "jobs" / "job-h1").mkdir(parents=True)
    (base_results / "jobs" / "job-h1" / "summary.json").write_text(
        json.dumps(
            {
                "items": [{"case_id": "c0", "outcome": "confirmed_exploit"}],
                "outcome_counts": {"confirmed_exploit": 1},
                "useful_findings": 1,
            }
        ),
        encoding="utf-8",
    )

    def flaky_fetch(host, job_id, host_subdir=False):
        if host == "root@h2":
            raise RuntimeError("scp failed")
        return base_results / "jobs" / job_id

    merged_path = fleet_fetch(
        job.distributed_job_id,
        output_dir=output_dir,
        fetch_fn=flaky_fetch,
        parallel=2,
        base_results_dir=base_results,
    )

    manifest = json.loads((output_dir / "dist-vulhub-partial" / "distributed_fetch_manifest.json").read_text())
    by_host = {entry["baseline_host"]: entry for entry in manifest["hosts"]}
    assert by_host["root@h1"]["fetched"] is True
    assert by_host["root@h2"]["fetched"] is False
    assert "scp failed" in by_host["root@h2"]["error"]
    merged = json.loads(merged_path.read_text())
    assert merged["totals"]["cases_completed"] == 1
    assert merged["totals"]["outcome_counts"] == {"confirmed_exploit": 1}


def test_start_distributed_job_strips_openai_prefix(tmp_path):
    """fleet jobs invoke src.agent_external which talks to MiniMax directly;
    the LiteLLM `openai/` prefix that CAI uses must be stripped."""
    seen_models: list[str] = []

    def fake_starter(*, baseline_host, suite, cases, model, **kwargs):
        seen_models.append(model)
        return {"job_id": f"j-{baseline_host}", "session": "s", "job_dir": "/tmp"}

    start_distributed_job(
        hosts=["root@h1"],
        suite="vulhub",
        cases=["c0"],
        repo=tmp_path / "repo",
        output_dir=tmp_path / "distributed",
        model="openai/MiniMax-M2.7",
        starter=fake_starter,
    )

    assert seen_models == ["MiniMax-M2.7"]


def test_store_records_distributed_job_and_runs(tmp_path):
    db_path = tmp_path / "store.sqlite"
    job = DistributedJob(
        distributed_job_id="dist-store-test",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[
            HostJob(baseline_host="root@h1", cases=["c0", "c2"], job_id="j1", session="s1", status="running"),
            HostJob(baseline_host="root@h2", cases=["c1"], job_id="j2", session="s2", status="running"),
        ],
        local_dir=tmp_path / "dist-store-test",
        cases_total=3,
        repo="/tmp/vulhub",
    )
    store.record_distributed_job(job, path=db_path)

    listed = store.list_distributed_jobs(path=db_path)
    assert len(listed) == 1
    assert listed[0]["distributed_job_id"] == "dist-store-test"
    assert listed[0]["cases_total"] == 3

    merged_payload = {
        "suite": "vulhub",
        "totals": {"cases_total": 3, "cases_completed": 3},
        "items": [
            {
                "case_id": "c0",
                "source_host": "root@h1",
                "outcome": "confirmed_exploit",
                "status": "completed",
                "service": "redis",
                "estimated_cost_usd": 0.12,
                "total_tokens": 1000,
                "duration_seconds": 120.5,
                "submission_source": "structured",
            },
            {
                "case_id": "c1",
                "source_host": "root@h2",
                "outcome": "max_turns",
                "status": "completed",
                "estimated_cost_usd": 0.20,
                "total_tokens": 600000,
                "duration_seconds": 480.0,
            },
            {
                "case_id": "c2",
                "source_host": "root@h1",
                "outcome": "no_finding",
                "status": "completed",
                "estimated_cost_usd": 0.05,
                "total_tokens": 200,
                "duration_seconds": 60.0,
            },
        ],
    }
    inserted = store.record_runs_from_merge("dist-store-test", merged_payload, path=db_path)
    assert inserted == 3

    runs = store.list_runs(distributed_job_id="dist-store-test", path=db_path)
    assert len(runs) == 3
    by_case = {r["case_id"]: r for r in runs}
    assert by_case["c0"]["outcome"] == "confirmed_exploit"
    assert by_case["c0"]["baseline_host"] == "root@h1"
    assert by_case["c1"]["estimated_cost_usd"] == 0.20

    breakdown = {item["outcome"]: item for item in store.outcome_breakdown(path=db_path)}
    assert breakdown["confirmed_exploit"]["count"] == 1
    assert breakdown["max_turns"]["count"] == 1
    assert breakdown["no_finding"]["count"] == 1

    durations = store.case_durations(path=db_path)
    assert durations["c1"] == 480.0
    assert "c0" in durations


def test_store_record_runs_is_idempotent_on_merge(tmp_path):
    db_path = tmp_path / "store.sqlite"
    job = DistributedJob(
        distributed_job_id="dist-idem",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[HostJob(baseline_host="root@h1", cases=["c0"], job_id="j1", status="running")],
        local_dir=tmp_path / "dist-idem",
        cases_total=1,
    )
    store.record_distributed_job(job, path=db_path)

    merged = {
        "suite": "vulhub",
        "totals": {"cases_total": 1, "cases_completed": 1},
        "items": [{"case_id": "c0", "source_host": "root@h1", "outcome": "no_finding"}],
    }
    store.record_runs_from_merge("dist-idem", merged, path=db_path)
    store.record_runs_from_merge("dist-idem", merged, path=db_path)

    runs = store.list_runs(distributed_job_id="dist-idem", path=db_path)
    assert len(runs) == 1


def test_store_records_host_status_updates(tmp_path):
    db_path = tmp_path / "store.sqlite"
    hj = HostJob(baseline_host="root@h1", cases=["c0"], job_id="j1", session="s1", status="pending")
    job = DistributedJob(
        distributed_job_id="dist-status",
        suite="vulhub",
        created_at="2026-05-13T14:00:00",
        shard_strategy="round-robin",
        host_jobs=[hj],
        local_dir=tmp_path / "dist-status",
        cases_total=1,
    )
    store.record_distributed_job(job, path=db_path)

    hj.status = "completed"
    hj.last_status_payload = {"completed": 1, "outcome_counts": {"confirmed_exploit": 1}}
    hj.last_seen_at = 1731500000.0
    store.record_host_status("dist-status", [hj], path=db_path)

    rows = store.run_sql("SELECT status, last_payload FROM host_jobs WHERE distributed_job_id = ?", ("dist-status",), path=db_path)
    assert rows[0]["status"] == "completed"
    assert "confirmed_exploit" in rows[0]["last_payload"]


def test_write_run_proof_honors_structured_submission(tmp_path):
    """When submission.json exists with label=CONFIRMED, proof must classify
    as confirmed_exploit even if the raw evidence text mentions blocked tools."""
    run_dir = tmp_path / "vulhub" / "activemq" / "CVE-2023-46604" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {
                "context_policy": "fair_network_only",
                "case": {
                    "suite": "vulhub",
                    "case_id": "activemq/CVE-2023-46604",
                    "target_endpoint": "127.0.0.1:61616",
                    "target_service": "activemq-openwire",
                    "vulnerability": "CVE-2023-46604",
                },
            }
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "external_agent_answer.txt").write_text(
        "ysoserial blocked by Java 21 module restrictions; "
        "wrote a native Python OpenWire exploit instead."
    )
    (run_dir / "submission.json").write_text(
        json.dumps(
            {
                "label": "CONFIRMED",
                "service": "activemq-openwire 5.17.3",
                "evidence": "Native Python OpenWire exploit succeeded; CVE-2023-46604 confirmed.",
                "blocked_by": "none",
                "next_step": "",
                "flag": "",
            }
        )
    )

    proof = write_run_proof(run_dir)

    assert proof["outcome"] == "confirmed_exploit"
    assert proof["confidence"] == "high"
    assert proof["blocked_by"] == ""
    assert proof["submission_source"] == "structured"
    assert "Native Python OpenWire exploit" in proof["evidence_summary"]


def test_write_run_proof_falls_back_to_text_when_no_submission(tmp_path):
    """Legacy runs without submission.json still use the text classifier."""
    run_dir = tmp_path / "vulhub" / "redis" / "CVE-2022-0543" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps(
            {"case": {"suite": "vulhub", "case_id": "redis/CVE-2022-0543", "target_endpoint": "127.0.0.1:6379"}}
        )
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "completed", "success": False}))
    (run_dir / "external_agent_answer.txt").write_text(
        "ysoserial not installed, JMS client missing."
    )

    proof = write_run_proof(run_dir)

    assert proof["outcome"] == "blocked_missing_tool"
    assert proof["submission_source"] == "text_classifier"


def test_write_run_proof_preserves_environment_failed_over_submission(tmp_path):
    """environment_failed status must win over any leaked submission file."""
    run_dir = tmp_path / "vulhub" / "airflow" / "CVE-2020-11981" / "20990101_000000"
    run_dir.mkdir(parents=True)
    (run_dir / "planned.json").write_text(
        json.dumps({"case": {"suite": "vulhub", "case_id": "airflow/CVE-2020-11981"}})
    )
    (run_dir / "result.json").write_text(json.dumps({"status": "environment_failed"}))
    (run_dir / "submission.json").write_text(
        json.dumps({"label": "CONFIRMED", "service": "airflow", "evidence": "stale", "blocked_by": "none"})
    )

    proof = write_run_proof(run_dir)

    assert proof["outcome"] == "environment_failed"
    assert proof["submission_source"] == "text_classifier"


def test_dashboard_state_effective_hosts_backward_compat():
    from src.baselines.ui import DashboardState

    state = DashboardState()
    assert state.effective_hosts == [state.baseline_host]

    state.baseline_hosts = ["root@h1", "root@h2"]
    assert state.effective_hosts == ["root@h1", "root@h2"]


def test_parse_hosts_arg_and_load_cases_file(tmp_path):
    assert parse_hosts_arg("root@a, root@b,,root@c") == ["root@a", "root@b", "root@c"]
    assert parse_hosts_arg("") == []

    cases_file = tmp_path / "cases.txt"
    cases_file.write_text("# header\nvulhub/redis\n\nvulhub/activemq\n", encoding="utf-8")
    assert load_cases_from_file(cases_file) == ["vulhub/redis", "vulhub/activemq"]


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
