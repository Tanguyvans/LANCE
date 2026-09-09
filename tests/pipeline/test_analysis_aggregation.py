"""Phase 3: aggregation, CVE validation, and canonical projections."""
import json
import pytest
from src.agent.pipeline import Pipeline
from src.agent.registry import AGENTS


@pytest.mark.parametrize("scenario_id", ["14", "16", "22"])
@pytest.mark.parametrize("label", ["vulnerable", "hardened", "near_miss"])
def test_aggregation_does_not_read_or_filter_on_oracle_labels(
    mock_provider, output_dir, monkeypatch, scenario_id, label,
):
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    pipeline.scenario_id = scenario_id
    monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: json.dumps([{
        "id": "ssh-1", "ip": "192.0.2.10", "role": "ssh_server", "security_profile": label,
    }]))
    def forbidden(*_args):
        raise AssertionError("Aggregation must not reopen scenario definitions")
    monkeypatch.setattr("src.agent.core.runtime.resolve_scenario_path", forbidden)
    monkeypatch.setattr("src.agent.core.runtime.resolve_topology_path", forbidden)
    (pipeline.run_dir / "03_device_ssh-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "id": "F1", "device_id": "ssh-1", "device_ip": "192.0.2.10",
            "type": "weak_cipher", "severity": "HIGH", "service": "ssh", "port": 22,
            "details": "SSH advertises aes128-cbc", "evidence": "aes128-cbc enabled",
        }],
    }))
    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
    output = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    assert len(output["vulnerabilities"]) == 1
    assert output["vulnerabilities"][0]["type"] == "weak_cipher"


def test_full_aggregation_keeps_model_queue_and_semantic_filter_raw(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.core.runtime.get_attack_surface",
        lambda: json.dumps([{
            "id": "web-1", "ip": "192.0.2.30", "role": "web_server",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider)
    (pipeline.run_dir / "03_device_web-1.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "device_id": "web-1", "device_ip": "192.0.2.30",
                "type": "info_disclosure", "severity": "LOW",
                "service": "http", "port": 80,
                "details": "Server version disclosure (nginx)",
                "evidence": "Server: nginx",
                "exploitation_status": "confirmed",
            },
            {
                "device_id": "web-1", "device_ip": "192.0.2.30",
                "type": "weak_cipher", "severity": "LOW",
                "service": "http", "port": 80,
                "details": "HTTP uses weak ciphers", "evidence": "80/tcp open http",
            },
        ]
    }))
    (pipeline.run_dir / "03_scans").mkdir()
    (pipeline.run_dir / "03_scans" / "web-1.json").write_text(json.dumps({
        "http": [{
            "tool": "curl_headers",
            "kwargs": {"url": "http://192.0.2.30/"},
            "result": json.dumps({
                "stdout": "HTTP/1.1 200 OK\nServer: nginx/1.22.1",
                "return_code": 0,
            }),
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    raw = json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text())
    assert {finding["type"] for finding in canonical["vulnerabilities"]} == {
        "info_disclosure",
    }
    info = next(
        finding for finding in canonical["vulnerabilities"]
        if finding["type"] == "info_disclosure"
    )
    assert info["canonical_source"] == "model"
    assert any(
        candidate["decision_reason"] == "weak_cipher requires SSH/TLS evidence, not plain HTTP"
        for candidate in raw["candidates"]
    )
    assert raw["candidate_count"] == 2
    assert raw["schema_version"] == "2"
    assert {c["candidate_finding"]["type"] for c in raw["candidates"]} == {
        "info_disclosure", "weak_cipher",
    }


def test_full_aggregation_accepts_catalog_validated_terrapin_without_nvd_cpe(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.core.runtime.get_attack_surface",
        lambda: json.dumps([{
            "id": "gw-1", "ip": "192.0.2.31", "role": "iot_gateway",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_gw-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "device_id": "gw-1", "device_ip": "192.0.2.31",
            "type": "known_cve", "severity": "HIGH",
            "service": "ssh", "port": 22, "product": "Dropbear sshd",
            "version": "2020.81", "cve_ids": ["CVE-2023-48795"],
            "details": "Dropbear 2020.81 is vulnerable to CVE-2023-48795 Terrapin",
            "evidence": "ssh_audit detected CVE-2023-48795 on Dropbear 2020.81",
            "cve_validation": {
                "query": "CVE-2023-48795 Dropbear",
                "observed_product": "Dropbear sshd",
                "observed_version": "2020.81",
            },
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    finding = canonical["vulnerabilities"][0]
    assert finding["type"] == "known_cve"
    assert finding["cve_claim_status"] == "validated_catalog"
    assert finding["accepted_for_scoring"] is True


def test_full_aggregation_keeps_unverified_cve_for_phase4(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.core.runtime.get_attack_surface",
        lambda: json.dumps([{
            "id": "ssh-1", "ip": "192.0.2.33", "role": "ssh_server",
        }]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_ssh-1.json").write_text(json.dumps({
        "vulnerabilities": [{
            "device_id": "ssh-1", "device_ip": "192.0.2.33",
            "type": "known_cve", "severity": "HIGH", "service": "ssh", "port": 22,
            "product": "OpenSSH", "version": "10.0p2",
            "cve_ids": ["CVE-2023-48795"],
            "details": "OpenSSH 10.0p2 is vulnerable to CVE-2023-48795",
            "evidence": "ssh_audit detected CVE-2023-48795 on OpenSSH 10.0p2",
            "cve_validation": {
                "observed_product": "OpenSSH",
                "observed_version": "10.0p2",
            },
        }]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    assert len(canonical["vulnerabilities"]) == 1
    assert canonical["vulnerabilities"][0]["cve_claim_status"] == "unverified"
    assert canonical["vulnerabilities"][0]["accepted_for_scoring"] is False


def test_full_canonical_projection_preserves_distinct_surfaces_and_raw(
    mock_provider, output_dir, monkeypatch
):
    monkeypatch.setattr(
        "src.agent.core.runtime.get_attack_surface",
        lambda: json.dumps([
            {"id": "mqtt-1", "ip": "192.0.2.45", "role": "mqtt_broker"},
            {"id": "web-1", "ip": "192.0.2.46", "role": "web_server"},
            {"id": "ssh-1", "ip": "192.0.2.47", "role": "ssh_server"},
            {"id": "ssh-2", "ip": "192.0.2.48", "role": "ssh_server"},
        ]),
    )
    pipeline = Pipeline(provider=mock_provider, execution_profile="full")
    (pipeline.run_dir / "03_device_mixed.json").write_text(json.dumps({
        "vulnerabilities": [
            {
                "id": "M1", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "no_auth", "severity": "HIGH", "service": "mqtt",
                "port": 1883, "product": "Mosquitto",
                "details": "Anonymous MQTT subscribe succeeded",
            },
            {
                "id": "M2", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "data_exposure", "severity": "MEDIUM", "service": "mqtt",
                "port": 1883, "endpoint": "smartcity/admin/credentials",
                "details": "Credentials exposed on MQTT topic",
            },
            {
                "id": "M3", "device_id": "mqtt-1", "device_ip": "192.0.2.45",
                "type": "data_exposure", "severity": "MEDIUM", "service": "mqtt",
                "port": 1883, "endpoint": "smartcity/config/network",
                "details": "Network secrets exposed on MQTT topic",
            },
            {
                "id": "W1", "device_id": "ssh-1", "device_ip": "192.0.2.47",
                "type": "weak_cipher", "severity": "LOW", "service": "ssh",
                "port": 22, "details": "SSH uses weak SHA-1 MAC",
            },
            {
                "id": "W2", "device_id": "ssh-2", "device_ip": "192.0.2.48",
                "type": "weak_cipher", "severity": "LOW", "service": "ssh",
                "port": 22, "details": "SSH uses weak CBC cipher",
            },
            {
                "id": "L1", "device_id": "web-1", "device_ip": "192.0.2.46",
                "type": "directory_listing", "severity": "MEDIUM", "service": "http",
                "port": 80, "endpoint": "/backup/",
                "details": "Directory listing enabled on /backup/ and /config/",
            },
            {
                "id": "L2", "device_id": "web-1", "device_ip": "192.0.2.46",
                "type": "data_exposure", "severity": "MEDIUM", "service": "http",
                "port": 80, "endpoint": "/config/app.config",
                "details": "Config contains database password and API key",
            },
        ]
    }))

    pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
    canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
    raw = json.loads((pipeline.run_dir / "03_vuln_analysis_raw.json").read_text())
    findings = canonical["vulnerabilities"]

    assert len(findings) == 7
    assert sum(f["type"] == "weak_cipher" for f in findings) == 2
    assert sum(f["type"] == "data_exposure" and f["device_ip"] == "192.0.2.45" for f in findings) == 2
    assert sum(f["type"] == "directory_listing" for f in findings) == 1
    assert sum(f["type"] == "data_exposure" and f["device_ip"] == "192.0.2.46" for f in findings) == 1
    assert raw["candidate_count"] == 7
    assert raw["canonical_count"] == 7


class TestInformationPreservingArchitecture:
    def test_local_moe_phase3_cve_validation_logs_and_feeds_aggregation(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: "[]")
        monkeypatch.setattr(
            "src.agent.core.runtime.cve_search",
            lambda query, top_k=5: json.dumps([{
                "id": "CVE-2023-48795",
                "severity": "HIGH",
                "description": "Terrapin affects this OpenSSH range",
                "compatibility": {
                    "status": "compatible",
                    "reason": "OpenSSH 9.2 is in the affected range",
                },
            }]),
        )
        pipeline = Pipeline(provider=mock_provider)
        device = {
            "id": "ssh-1",
            "ip": "192.0.2.10",
            "services": [{"name": "ssh", "port": 22, "protocol": "tcp"}],
        }
        scanner_results = {
            "ssh-1": {
                "scan_results": {
                    "ssh": [{
                        "tool": "nmap_scan",
                        "kwargs": {"target": "192.0.2.10", "ports": "22"},
                        "result": json.dumps({
                            "stdout": "22/tcp open ssh OpenSSH 9.2 Debian-2",
                            "stderr": "",
                            "return_code": 0,
                        }),
                    }],
                },
                "findings": [],
            },
        }

        pipeline._run_phase3_local_cve_validation(scanner_results, [device])

        validation = json.loads((pipeline.run_dir / "03_cve_validation.json").read_text())
        assert validation["queries"] == 1
        assert validation["compatible_cves"] == 1
        assert validation["records"][0]["query"] == "OpenSSH 9.2"
        tool_log = (pipeline.run_dir / "tool_calls.jsonl").read_text()
        assert '"tool": "cve_search"' in tool_log
        fallback = json.loads((pipeline.run_dir / "03_device_ssh-1.json").read_text())
        finding = fallback["vulnerabilities"][0]
        assert finding["type"] == "known_cve"
        assert finding["cve_ids"] == ["CVE-2023-48795"]
        assert finding["cve_validation"]["query"] == "OpenSSH 9.2"

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])
        canonical = json.loads((pipeline.run_dir / "03_vuln_analysis.json").read_text())
        assert len(canonical["vulnerabilities"]) == 1
        assert canonical["vulnerabilities"][0]["cve_claim_status"] == "validated"

    def test_local_moe_phase3_cve_validation_requires_explicit_version(
        self, mock_provider, output_dir, monkeypatch
    ):
        calls = []
        monkeypatch.setattr(
            "src.agent.core.runtime.cve_search",
            lambda query, top_k=5: calls.append(query) or "[]",
        )
        pipeline = Pipeline(provider=mock_provider)
        device = {
            "id": "router-1",
            "ip": "192.0.2.1",
            "services": [
                {"name": "ssh", "port": 22, "protocol": "tcp"},
                {"name": "http", "port": 80, "protocol": "tcp"},
            ],
        }
        scanner_results = {
            "router-1": {
                "scan_results": {
                    "ssh": [{
                        "tool": "nmap_scan",
                        "kwargs": {"ports": "22"},
                        "result": json.dumps({"stdout": "22/tcp open ssh Dropbear sshd (protocol 2.0)"}),
                    }],
                    "http": [{
                        "tool": "curl_headers",
                        "kwargs": {"url": "http://192.0.2.1/"},
                        "result": json.dumps({"stdout": "HTTP/1.1 200 OK\nServer: nginx"}),
                    }],
                },
                "findings": [],
            },
        }

        pipeline._run_phase3_local_cve_validation(scanner_results, [device])

        validation = json.loads((pipeline.run_dir / "03_cve_validation.json").read_text())
        assert validation["queries"] == 0
        assert calls == []
        fallback = json.loads((pipeline.run_dir / "03_device_router-1.json").read_text())
        assert fallback["vulnerabilities"] == []

    def test_aggregation_preserves_raw_candidates_and_uses_evidence_quality(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider)

        common = {
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "known_cve",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "endpoint": "",
            "product": "OpenSSH",
            "version": "9.2",
            "cve_ids": ["CVE-2023-48795"],
            "exploitation_status": "suspected",
            "cve_validation": {"query": "OpenSSH 9.2"},
        }
        low = {**common, "id": "A", "severity": "LOW", "details": "short", "evidence": ""}
        high = {
            **common,
            "id": "B",
            "severity": "HIGH",
            "details": "short",
            "evidence": "ssh-audit observed the affected product and version",
            "cve_validation": {
                "compatibility_status": "compatible",
                "query": "OpenSSH 9.2",
                "compatibility_reason": "affected range",
                "observed_product": "OpenSSH",
                "observed_version": "9.2",
            },
        }
        noise = {
            **common,
            "id": "C",
            "type": "entry_point",
            "severity": "INFO",
            "details": "topology metadata",
        }
        (pipeline.run_dir / "03_device_a.json").write_text(json.dumps({
            "vulnerabilities": [low, noise],
        }))
        (pipeline.run_dir / "03_device_b.json").write_text(json.dumps({
            "vulnerabilities": [high],
        }))
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            json.dumps({
                "tool": "cve_search",
                "args": {"query": "OpenSSH 9.2"},
                "result": json.dumps([{
                    "id": "CVE-2023-48795",
                    "compatibility": {
                        "status": "compatible",
                        "reason": "affected range",
                    },
                }]),
                "evidence_ref": "tc-compatible",
            }) + "\n"
        )

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        raw = json.loads(
            (pipeline.run_dir / "03_vuln_analysis_raw.json").read_text()
        )
        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        assert raw["candidate_count"] == 3
        assert len(raw["candidates"]) == 3
        assert canonical["summary"]["raw_candidates"] == 3
        assert len(canonical["vulnerabilities"]) == 1
        selected = canonical["vulnerabilities"][0]
        assert selected["severity"] == "HIGH"
        assert selected["cve_claim_status"] == "validated"
        assert len(selected["_provenance"]["candidate_ids"]) == 2
        assert any(
            candidate["decision"] == "excluded_from_canonical"
            for candidate in raw["candidates"]
        )

    def test_compact_observations_require_phase2_support_without_blocking_verification(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")

        ssh_finding = {
            "id": "ssh-observation",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "info_disclosure",
            "severity": "LOW",
            "service": "ssh",
            "port": 22,
            "protocol": "tcp",
            "details": "SSH banner discloses a custom service message",
            "evidence": "SSH service returns: 'Not allowed at this time'",
            "exploitation_status": "confirmed",
        }
        generic_ssh_finding = {
            **ssh_finding,
            "id": "generic-ssh-observation",
            "device_id": "device-b",
            "device_ip": "192.0.2.21",
            "details": "SSH banner discloses software version",
            "evidence": "22/tcp open ssh OpenSSH 9.2",
        }
        generic_http_finding = {
            **ssh_finding,
            "id": "generic-http-observation",
            "device_id": "device-c",
            "device_ip": "192.0.2.22",
            "service": "http",
            "port": 80,
            "details": "Server version disclosure (nginx)",
            "evidence": "Server: nginx",
        }
        header_finding = {
            "id": "header-observation",
            "device_id": "device-a",
            "device_ip": "192.0.2.20",
            "type": "missing_header",
            "severity": "LOW",
            "service": "http",
            "port": 80,
            "protocol": "tcp",
            "details": "Security headers are missing",
            "evidence": "X-Frame-Options is absent",
            "exploitation_status": "confirmed",
        }
        directory_finding = {
            **header_finding,
            "id": "directory-observation",
            "type": "directory_listing",
            "details": "Directory listing enabled on /backup/",
            "evidence": "'Index of' found at /backup/",
        }
        (pipeline.run_dir / "03_device_device-a.json").write_text(json.dumps({
            "vulnerabilities": [ssh_finding, header_finding, directory_finding],
        }))
        (pipeline.run_dir / "03_device_device-b.json").write_text(json.dumps({
            "vulnerabilities": [generic_ssh_finding],
        }))
        (pipeline.run_dir / "03_device_device-c.json").write_text(json.dumps({
            "vulnerabilities": [generic_http_finding],
        }))
        (pipeline.run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.20", "ports": "22"},
            "result": json.dumps({
                "stdout": "22/tcp open ssh OpenSSH 9.2",
                "return_code": 0,
            }),
        }) + "\n" + json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.21", "ports": "22"},
            "result": json.dumps({
                "stdout": "22/tcp open ssh OpenSSH 9.2",
                "return_code": 0,
            }),
        }) + "\n" + json.dumps({
            "tool": "nmap_scan",
            "phase": 2,
            "args": {"target": "192.0.2.22", "ports": "80"},
            "result": json.dumps({
                "stdout": "80/tcp open http nginx",
                "return_code": 0,
            }),
        }) + "\n")

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        observations = json.loads(
            (pipeline.run_dir / "03_config_observations.json").read_text()
        )
        assert len(canonical["vulnerabilities"]) == 5
        assert sum(item["type"] == "info_disclosure" for item in canonical["vulnerabilities"]) == 3
        assert "compact_detection_only" not in canonical["vulnerabilities"][0]
        assert observations["observations"] == []

        pipeline._run_exploit_agents(AGENTS["exploitation"])
        aggregate = json.loads(
            (pipeline.run_dir / "04_exploitation.json").read_text()
        )
        assert pipeline._phase4_schedule["scheduled_count"] == 5
        assert pipeline._phase4_schedule["skipped_count"] == 0
        assert aggregate["summary"]["skipped_count"] == 0
        assert len(aggregate["tests"]) == 5
        assert all(test["status"] in {"ERROR", "FAILED"} for test in aggregate["tests"])  # mock provider produced no proof

    def test_log_regression_unverified_cves_remain_schedulable_and_raw(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: "[]")
        pipeline = Pipeline(provider=mock_provider)
        claims = [
            ("router", "Dropbear sshd (protocol 2.0)", "CVE-2023-48795"),
            ("mqtt", "Mosquitto 2.0.21", "CVE-2024-99999"),
            ("web", "nginx 1.22", "CVE-2023-48795"),
            ("ssh", "ssh version 22", "CVE-2001-0572"),
        ]
        for index, (device_id, query, cve_id) in enumerate(claims, 1):
            finding = {
                "id": f"claim-{index}",
                "device_id": device_id,
                "device_ip": f"192.168.100.{index + 9}",
                "type": "known_cve",
                "severity": "HIGH",
                "service": "ssh",
                "port": 22,
                "protocol": "tcp",
                "endpoint": "",
                "product": query.split()[0],
                "version": query.split()[-1],
                "details": "model claim",
                "evidence": "banner only",
                "cve_ids": [cve_id],
                "exploitation_status": "suspected",
                "cve_validation": {"query": query},
            }
            (pipeline.run_dir / f"03_device_{device_id}.json").write_text(
                json.dumps({"vulnerabilities": [finding]})
            )

        searches = [
            {
                "tool": "cve_search",
                "args": {"query": "Dropbear sshd (protocol 2.0)"},
                "result": json.dumps([{
                    "id": "CVE-2025-14282",
                    "compatibility": {"status": "compatible", "reason": "different CVE"},
                }]),
                "evidence_ref": "tc-dropbear",
            },
            {
                "tool": "cve_search",
                "args": {"query": "Mosquitto 2.0.21"},
                "result": "[]",
                "evidence_ref": "tc-mqtt",
            },
            {
                "tool": "cve_search",
                "args": {"query": "nginx 1.22"},
                "result": json.dumps([{
                    "id": "CVE-2018-16843",
                    "compatibility": {"status": "incompatible", "reason": "fixed before 1.22"},
                }]),
                "evidence_ref": "tc-nginx",
            },
            {
                "tool": "cve_search",
                "args": {"query": "ssh version 22"},
                "result": json.dumps([{
                    "id": "CVE-2001-0572",
                    "compatibility": {"status": "incompatible", "reason": "version mismatch"},
                }]),
                "evidence_ref": "tc-ssh",
            },
        ]
        (pipeline.run_dir / "tool_calls.jsonl").write_text(
            "\n".join(json.dumps(record) for record in searches) + "\n"
        )

        pipeline._aggregate_device_vulns(AGENTS["vuln_analysis"])

        canonical = json.loads(
            (pipeline.run_dir / "03_vuln_analysis.json").read_text()
        )
        raw = json.loads(
            (pipeline.run_dir / "03_vuln_analysis_raw.json").read_text()
        )
        assert len(canonical["vulnerabilities"]) == 3
        assert canonical["summary"]["raw_candidates"] == 4
        assert len(raw["candidates"]) == 4
        assert sum(candidate["decision"] == "excluded_from_canonical" for candidate in raw["candidates"]) == 1
        reasons = " ".join(
            candidate["decision_reason"] for candidate in raw["candidates"]
        )
        assert "explicitly incompatible" in reasons
