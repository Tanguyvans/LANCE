"""Phase 5: intrusion context and atomic evidence chains."""
import json
from src.agent.pipeline import Pipeline


class TestPrepare3BDatasets:
    def test_phase5_examples_remain_single_atomic_evidence_chain(self):
        from training.prepare_3b_datasets import build_chunks

        class Tokenizer:
            def apply_chat_template(
                self, messages, tools=None, tokenize=False, add_generation_prompt=False
            ):
                return "\n".join(str(message.get("content", "")) for message in messages)

            def encode(self, text, add_special_tokens=False):
                return text.split()

        row = {
            "metadata": {"phase": 5},
            "tools": [],
            "messages": [
                {"role": "system", "content": "intrusion system"},
                {"role": "user", "content": "use tool evidence"},
                {"role": "assistant", "content": "try credential"},
                {"role": "tool", "content": "try_credential success false"},
                {"role": "assistant", "content": "final no compromise"},
            ],
        }

        chunks, stats = build_chunks(Tokenizer(), row, max_length=100, distractors=0)

        assert stats["chunks"] == 1
        assert len(chunks) == 1
        assert chunks[0]["metadata"]["evidence_chain_atomic"] is True
        contents = [message.get("content") for message in chunks[0]["messages"]]
        assert "try_credential success false" in contents
        assert "final no compromise" in contents


class TestPhase5Context:
    """Tests for _generate_intrusion_context."""

    def test_generates_intrusion_context(self, mock_provider, output_dir, monkeypatch):
        """Phase 5 context should extract confirmed exploits and entry points."""
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        # Write Phase 4 exploitation results with CONFIRMED entries
        exploit_data = {
            "summary": {"total_tested": 3, "confirmed": 2, "not_exploitable": 1, "errors": 0},
            "tests": [
                {"vuln_id": "VULN-001", "status": "CONFIRMED", "device_id": "router",
                 "device_ip": "10.0.0.1", "evidence": "SSH login root:password succeeded"},
                {"vuln_id": "VULN-002", "status": "FAILED", "device_id": "router",
                 "device_ip": "10.0.0.1", "evidence": ""},
                {"vuln_id": "VULN-003", "status": "CONFIRMED", "device_id": "sensor",
                 "device_ip": "10.0.0.2", "evidence": "redis-cli KEYS * returned 5 keys"},
            ],
        }
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_data))

        pipeline._generate_intrusion_context()

        ctx_path = run_dir / "05_intrusion_context.json"
        assert ctx_path.exists()
        ctx = json.loads(ctx_path.read_text())

        # Check required keys
        assert "generated_for" in ctx
        assert ctx["generated_for"] == "phase5_intrusion"
        assert "entry_points" in ctx
        assert "all_targets" in ctx
        assert "confirmed_exploits" in ctx
        assert "recovered_credentials" in ctx
        assert ctx["confirmed_exploits"] == 2

    def test_full_context_keeps_path_data_and_filters_non_footholds(
        self, mock_provider, output_dir, monkeypatch
    ):
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        run_dir = pipeline.run_dir
        monkeypatch.setattr(
            "src.agent.core.runtime.get_attack_surface",
            lambda: json.dumps({
                "nodes": [
                    {
                        "id": "opcua", "ip": "192.168.100.20",
                        "role": "ot_opcua_server",
                        "services": [{"name": "opcua", "port": 4840, "protocol": "tcp"}],
                    },
                    {
                        "id": "metadata", "ip": "192.168.100.21",
                        "role": "cloud_metadata_server",
                        "services": [{"name": "http", "port": 80, "protocol": "tcp"}],
                    },
                ],
            }),
        )
        (run_dir / "03_vuln_analysis.json").write_text(json.dumps({
            "attack_chain_hints": [{
                "src_ip": "192.168.100.20", "dst_ip": "192.168.100.21",
            }],
            "vulnerabilities": [{
                "id": "SCANNER-OPCUA", "device_id": "opcua",
                "device_ip": "192.168.100.20", "type": "no_auth",
                "service": "opcua", "port": 4840,
                "canonical_source": "scanner_full",
                "exploitation_status": "confirmed",
                "evidence": "deterministic OPC-UA contract",
            }],
        }))
        (run_dir / "04_exploitation.json").write_text(json.dumps({
            "summary": {"confirmed": 1},
            "tests": [{
                "vuln_id": "INFO-METADATA", "device_id": "metadata",
                "device_ip": "192.168.100.21", "type": "info_disclosure",
                "status": "CONFIRMED", "evidence_level": 3,
                "evidence": "HTTP banner",
            }],
        }))

        pipeline._generate_intrusion_context()
        context = json.loads((run_dir / "05_intrusion_context.json").read_text())

        assert [entry["device_ip"] for entry in context["entry_points"]] == [
            "192.168.100.20"
        ]
        assert context["entry_points"][0]["evidence_source"] == "phase3_scanner_contract"
        assert context["entry_points"][0]["phase4_verified"] is False
        target = next(item for item in context["all_targets"] if item["device_ip"] == "192.168.100.20")
        assert target["primary_service"] == "opcua"
        assert target["service_details"] == [{"name": "opcua", "port": 4840, "protocol": "tcp"}]
        assert context["attack_chains"] == [{
            "src_ip": "192.168.100.20", "dst_ip": "192.168.100.21",
        }]

    def test_handles_missing_phase4(self, mock_provider, output_dir, monkeypatch):
        """Context should still generate if Phase 4 was skipped."""
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        pipeline._generate_intrusion_context()

        ctx_path = run_dir / "05_intrusion_context.json"
        assert ctx_path.exists()
        ctx = json.loads(ctx_path.read_text())
        assert ctx["confirmed_exploits"] == 0
        assert ctx["entry_points"] == []
        assert ctx["recovered_credentials"] == []

    def test_handles_list_format_phase4(self, mock_provider, output_dir, monkeypatch):
        """Context should handle Phase 4 output as a plain list."""
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir

        exploit_list = [
            {"vuln_id": "VULN-001", "status": "CONFIRMED", "device_id": "gw",
             "device_ip": "10.0.0.5", "evidence": "login ok"},
        ]
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_list))

        pipeline._generate_intrusion_context()

        ctx = json.loads((run_dir / "05_intrusion_context.json").read_text())
        assert ctx["confirmed_exploits"] == 1

    def test_mqtt_confirmed_exploit_feeds_recovered_credentials(
        self, mock_provider, output_dir, monkeypatch
    ):
        monkeypatch.setattr("src.agent.core.runtime.get_attack_surface", lambda: '{"nodes": []}')
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        exploit_data = {
            "summary": {"total_tested": 1, "confirmed": 1, "not_exploitable": 0, "errors": 0},
            "tests": [{
                "vuln_id": "VULN-002",
                "status": "CONFIRMED",
                "device_id": "s1-mqtt",
                "device_ip": "192.168.100.11",
                "vuln_type": "data_exposure",
                "service": "mqtt",
                "port": 1883,
                "evidence": "mqtt_listen captured sensitive MQTT messages",
                "data_extracted": [
                    "smartcity/admin/credentials {\"db_user\":\"root\",\"db_pass\":\"P@ssw0rd123\"}"
                ],
            }],
        }
        (run_dir / "04_exploitation.json").write_text(json.dumps(exploit_data))

        pipeline._generate_intrusion_context()

        ctx = json.loads((run_dir / "05_intrusion_context.json").read_text())
        assert ctx["confirmed_exploits"] == 1
        assert ctx["recovered_credentials"] == [{
            "user": "root",
            "password": "P@ssw0rd123",
            "source_ip": "192.168.100.11",
            "source_device": "s1-mqtt",
        }]
