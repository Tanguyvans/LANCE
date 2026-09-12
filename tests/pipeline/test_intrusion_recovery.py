"""Phase 5: fallback, credential recovery, and evidence synthesis."""
import json
from src.agent.pipeline import Pipeline
from src.agent.phases.intrusion.evidence import has_observable_actions
from src.agent.registry import AGENTS


class TestPhase5Context:
    """Tests for _generate_intrusion_context."""

    def test_local_moe_intrusion_rewrites_hallucinated_compromise(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.168.100.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "all_targets": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "recovered_credentials": [{
                "user": "root",
                "password": "P@ssw0rd123",
                "service": "mqtt",
                "source_ip": "192.168.100.11",
                "source_device": "s1-mqtt",
            }],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "tool": "try_credential",
            "args": {
                "ip": "192.168.100.1",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
            "result": json.dumps({
                "success": False,
                "service": "ssh",
                "port": 22,
                "stderr": "Permission denied",
            }),
        }) + "\n")
        with (run_dir / "tool_calls.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({
                "phase": 4,
                "vuln_id": "VULN-004",
                "tool": "try_credential",
                "args": {
                    "ip": "192.168.100.1",
                    "service": "ssh",
                    "user": "operator",
                    "password": "operator",
                },
                "result": json.dumps({
                    "success": True,
                    "service": "ssh",
                    "port": 22,
                    "stdout": "uid=1000(operator)",
                }),
            }) + "\n")
        (run_dir / "05_intrusion.json").write_text(json.dumps({
            "summary": {
                "devices_attempted": 1,
                "devices_compromised": 1,
                "credentials_harvested": 1,
                "crown_jewels_reached": [],
                "total_hops": 1,
            },
            "credential_pool": [],
            "compromised_devices": [{
                "device_id": "s1-router",
                "device_ip": "192.168.100.1",
                "access_method": "hallucinated",
            }],
            "chains": [],
        }))

        results = {"intrusion": "completed"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert results["intrusion"] == "failed:phase5_contract_incomplete"
        assert final["status"] == "incomplete"
        assert final["summary"]["devices_compromised"] == 0
        assert final["summary"]["devices_attempted"] == 1
        assert final["compromised_devices"] == []
        assert final["credential_pool"] == [{
            "user": "root",
            "password": "P@ssw0rd123",
            "service": "mqtt",
            "source_ip": "192.168.100.11",
            "source_device": "s1-mqtt",
        }]

    def test_compact_intrusion_controller_finalizes_after_fallback(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{
                "device_id": "mqtt",
                "device_ip": "192.0.2.11",
                "service": "mqtt",
                "port": 1883,
                "vuln_type": "no_auth",
            }],
            "all_targets": [{
                "device_id": "mqtt",
                "device_ip": "192.0.2.11",
                "role": "mqtt_broker",
                "services": [1883],
            }],
            "recovered_credentials": [],
        }))

        def read_deliverable(**kwargs):
            return json.dumps({
                "filename": kwargs["filename"],
                "content": (run_dir / kwargs["filename"]).read_text(),
            })

        def mqtt_listen(**_kwargs):
            return json.dumps({"return_code": 0, "stdout": "message"})

        base_tools = [
            {"name": "read_deliverable", "description": "read", "input_schema": {},
             "function": read_deliverable},
            {"name": "mqtt_listen", "description": "mqtt", "input_schema": {},
             "function": mqtt_listen},
        ]
        monkeypatch.setattr(
            pipeline,
            "_resolve_tools",
            lambda _config: [
                pipeline._wrap_tool(tool, phase=5, agent="intrusion")
                for tool in base_tools
            ],
        )
        runtime_tools = pipeline._apply_compact_intrusion_tool_contract(
            [
                pipeline._wrap_tool(tool, phase=5, agent="intrusion")
                for tool in base_tools
            ],
            phase=5,
            agent="intrusion",
        )
        pipeline._compact_intrusion_runtime_tools = runtime_tools

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])
        assert executed == 1
        assert pipeline._invoke_compact_intrusion_completion(runtime_tools) is True

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert final["status"] == "completed"
        assert final["completion_source"] == "complete_intrusion_campaign"

    def test_compact_intrusion_fallback_prioritizes_missing_credential_targets(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [
                {"device_id": "s1-router", "device_ip": "192.168.100.1", "role": "router"},
                {"device_id": "s1-mqtt", "device_ip": "192.168.100.11", "role": "mqtt_broker"},
                {"device_id": "s1-web", "device_ip": "192.168.100.12", "role": "web_server"},
                {"device_id": "s1-ssh", "device_ip": "192.168.100.13", "role": "ssh_server"},
            ],
            "recovered_credentials": [
                {"user": "admin", "password": "admin", "source_ip": "192.168.100.13"},
                {"user": "root", "password": "P@ssw0rd123", "source_ip": "192.168.100.11"},
                {"user": "root", "password": "root", "source_ip": "192.168.100.13"},
            ],
        }))
        calls = []

        def try_credential(**kwargs):
            calls.append(kwargs)
            return json.dumps({"success": False, "authenticated": False})

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [{
            "name": "try_credential",
            "description": "try",
            "input_schema": {},
            "function": try_credential,
        }])
        monkeypatch.setattr(
            pipeline,
            "_compact_intrusion_coverage",
            lambda: (False, {
                "missing_entry_points": [],
                "missing_credentials": [
                    "admin@192.168.100.12",
                    "admin@192.168.100.13",
                ],
                "missing_credential_keys": [
                    ["192.168.100.12", "admin", "admin"],
                    ["192.168.100.13", "admin", "admin"],
                ],
                "missing_targets": [],
            }),
        )

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])

        assert executed == 2
        assert calls == [
            {
                "ip": "192.168.100.12",
                "service": "http",
                "user": "admin",
                "password": "admin",
            },
            {
                "ip": "192.168.100.13",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
        ]

    def test_compact_intrusion_fallback_probes_ssh_entry_before_credentials(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {
                    "device_id": "s1-ssh",
                    "device_ip": "192.0.2.10",
                    "service": "ssh",
                    "port": 22,
                },
            ],
            "all_targets": [
                {
                    "device_id": "s1-ssh",
                    "device_ip": "192.0.2.10",
                    "role": "ssh_server",
                    "services": [22],
                },
            ],
            "recovered_credentials": [
                {
                    "user": "admin",
                    "password": "admin",
                    "source_ip": "192.0.2.10",
                },
            ],
        }))
        calls = []

        def ssh_login(**kwargs):
            calls.append(("ssh_login", kwargs))
            return json.dumps({"return_code": 0, "stdout": "uid=1000(admin)"})

        def try_credential(**kwargs):
            calls.append(("try_credential", kwargs))
            return json.dumps({"success": False, "authenticated": False})

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [
            {"name": "ssh_login", "description": "ssh", "input_schema": {}, "function": ssh_login},
            {"name": "try_credential", "description": "try", "input_schema": {}, "function": try_credential},
        ])

        executed = pipeline._run_compact_intrusion_fallback(AGENTS["intrusion"])

        assert executed == 2
        assert calls[0][0] == "ssh_login"
        assert "admin@192.0.2.10" in calls[0][1]["command_string"]
        assert calls[1][0] == "try_credential"

    def test_compact_post_access_harvest_runs_after_authenticated_ssh(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        calls = []

        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "tool": "try_credential",
            "args": {
                "ip": "192.0.2.10",
                "service": "ssh",
                "user": "admin",
                "password": "admin",
            },
            "result": json.dumps({
                "success": True,
                "authenticated": True,
                "service": "ssh",
                "stdout": "__ok__",
            }),
        }) + "\n")

        def ssh_exec(**kwargs):
            calls.append(kwargs)
            return json.dumps({
                "success": True,
                "return_code": 0,
                "stdout": 'uid=1000(admin) {"db_user":"root","db_pass":"secret"}',
            })

        monkeypatch.setattr(pipeline, "_resolve_tools", lambda _config: [{
            "name": "ssh_exec",
            "description": "ssh",
            "input_schema": {},
            "function": ssh_exec,
        }])

        executed = pipeline._run_compact_intrusion_post_access(AGENTS["intrusion"])

        assert executed == 1
        assert calls[0]["ip"] == "192.0.2.10"
        assert calls[0]["user"] == "admin"
        assert "config.json" in calls[0]["command"]

    def test_compact_intrusion_synthesis_preserves_harvest_without_inventing_pivots(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        pipeline.context = {"target_subnet": "192.0.2.0/24"}
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [
                {"device_id": "s1-router", "device_ip": "192.0.2.1", "service": "telnet"},
                {"device_id": "s1-ssh", "device_ip": "192.0.2.10", "service": "ssh"},
            ],
            "all_targets": [
                {"device_id": "s1-router", "device_ip": "192.0.2.1", "role": "router", "services": [22, 23]},
                {"device_id": "s1-ssh", "device_ip": "192.0.2.10", "role": "ssh_server", "services": [22]},
            ],
            "recovered_credentials": [
                {"user": "root", "password": "root", "source_ip": "192.0.2.1", "source_device": "s1-router"},
                {"user": "admin", "password": "admin", "source_ip": "192.0.2.10", "source_device": "s1-ssh"},
            ],
            "attack_chains": [{
                "chain": "s1-router -> s1-ssh",
                "src_device": "s1-router",
                "src_ip": "192.0.2.1",
                "dst_device": "s1-ssh",
                "dst_ip": "192.0.2.10",
                "pivot_vuln": "VULN-006",
                "target_vuln_ids": ["VULN-010"],
            }],
        }))
        records = [
            {
                "phase": 5,
                "tool": "try_credential",
                "args": {
                    "ip": "192.0.2.1", "service": "ssh",
                    "user": "root", "password": "root",
                },
                "result": json.dumps({
                    "success": True, "authenticated": True,
                    "service": "ssh", "stdout": "__ok__",
                }),
            },
            {
                "phase": 5,
                "tool": "ssh_exec",
                "args": {
                    "ip": "192.0.2.1", "user": "root",
                    "password": "root", "command": "id",
                },
                "result": json.dumps({
                    "success": True, "return_code": 0,
                    "stdout": 'uid=0(root) {"db_user":"dbadmin","db_pass":"db-secret"}',
                }),
            },
            {
                "phase": 5,
                "tool": "ssh_login",
                "args": {
                    "command_string": "sshpass -p admin ssh admin@192.0.2.10 'id'",
                },
                "result": json.dumps({
                    "return_code": 0, "stdout": "uid=1000(admin)",
                }),
            },
        ]
        (run_dir / "tool_calls.jsonl").write_text(
            "".join(json.dumps(record) + "\n" for record in records)
        )

        data = pipeline._synthesize_intrusion_from_tools()

        assert data["summary"]["credentials_harvested"] == 3
        assert any(
            credential["password"] == "db-secret"
            for credential in data["credential_pool"]
        )
        assert data["compromised_devices"][0]["credentials_found"][0]["password"] == "db-secret"
        # Independent accesses and model-declared ``attack_chains`` are not
        # causal pivot evidence; retain the useful harvest but do not invent
        # a transition.
        assert data["chains"] == []
        assert data["summary"]["total_hops"] == 0

    def test_compact_post_access_recovery_is_disabled_for_full_profile(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        assert pipeline._run_compact_intrusion_post_access(AGENTS["intrusion"]) == 0

    def test_intrusion_synthesis_blocks_context_only_trace(
        self, mock_provider, output_dir, monkeypatch
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "all_targets": [{"device_id": "s1-router", "device_ip": "192.168.100.1"}],
            "recovered_credentials": [],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "agent": "intrusion",
            "tool": "read_deliverable",
            "args": {"filename": "05_intrusion_context.json"},
            "result": json.dumps({"content": "{}"}),
        }) + "\n")

        monkeypatch.setattr(pipeline, "_run_compact_intrusion_fallback", lambda *_args, **_kwargs: 0)
        results = {"intrusion": "failed:empty"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        final = json.loads((run_dir / "05_intrusion.json").read_text())
        assert results["intrusion"] == "blocked:phase5_no_observable_actions"
        assert final["status"] == "blocked"
        assert final["summary"]["devices_attempted"] == 0
        assert final["summary"]["devices_compromised"] == 0

    def test_intrusion_synthesis_counts_noncredential_actions(
        self, mock_provider, output_dir
    ):
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        (run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "all_targets": [{"device_id": "s1-web", "device_ip": "192.168.100.12"}],
        }))
        (run_dir / "tool_calls.jsonl").write_text(json.dumps({
            "phase": 5,
            "agent": "intrusion",
            "tool": "http_get",
            "args": {"url": "http://192.168.100.12/admin"},
            "result": json.dumps({"status_code": 200}),
        }) + "\n")

        data = pipeline._synthesize_intrusion_from_tools()

        assert data["summary"]["devices_attempted"] == 1
        assert has_observable_actions(data) is True

    def test_non_local_intrusion_keeps_valid_model_deliverable(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "openrouter"
        mock_provider.model = "large-model"
        pipeline = Pipeline(provider=mock_provider)
        run_dir = pipeline.run_dir
        model_output = {
            "summary": {"devices_compromised": 1},
            "compromised_devices": [{"device_ip": "192.0.2.10"}],
        }
        (run_dir / "05_intrusion.json").write_text(json.dumps(model_output))

        results = {"intrusion": "completed"}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        assert json.loads((run_dir / "05_intrusion.json").read_text()) == model_output
        assert results["intrusion"] == "completed"

    def test_local_moe_intrusion_runs_as_tool_memo_without_save_requirement(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))

        status = pipeline._run_agent(AGENTS["intrusion"])

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        tool_names = {tool["name"] for tool in kwargs["tools"]}
        assert status.startswith("failed:")
        assert "try_credential" in tool_names
        assert "ssh_exec" in tool_names
        assert "ssh_login" in tool_names
        if "mqtt_listen" in pipeline.runtime_unavailable_tools:
            assert "mqtt_listen" not in tool_names
        else:
            assert "mqtt_listen" in tool_names
        assert "http_get" in tool_names
        assert "curl_headers" in tool_names
        assert "complete_intrusion_campaign" in tool_names
        assert "save_deliverable" not in tool_names
        assert kwargs["required_tool"] == "complete_intrusion_campaign"
        assert kwargs["terminate_after_tool"] == "complete_intrusion_campaign"
        assert kwargs["terminate_on_unavailable_tools"] is None
        assert kwargs["strict_required_tool"] is True
        assert kwargs["force_tool_on_stall"] is True
        assert kwargs["reopen_intrusion_tools_on_contract_error"] is True
        assert kwargs["recover_required_tool_on_stall"] is True
        assert "Complete compact campaign" in kwargs["system_prompt"]
        assert "commits 05_intrusion.json" in kwargs["system_prompt"]

    def test_compact_intrusion_defers_failed_phase_event_until_reconciliation(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "lance-moe"
        pipeline = Pipeline(provider=mock_provider, execution_profile="compact")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))
        events = []

        status = pipeline._run_agent(AGENTS["intrusion"], events.append)

        assert status.startswith("failed:")
        assert not [event for event in events if event.get("type") == "phase_done"]

    def test_full_local_moe_intrusion_uses_standard_full_contract(
        self, mock_provider, output_dir
    ):
        mock_provider.provider = "local-moe"
        mock_provider.model = "future-full-local-model"
        pipeline = Pipeline(provider=mock_provider, execution_profile="full")
        (pipeline.run_dir / "05_intrusion_context.json").write_text(json.dumps({
            "entry_points": [],
            "all_targets": [],
            "recovered_credentials": [],
        }))

        status = pipeline._run_agent(AGENTS["intrusion"])

        kwargs = mock_provider.chat_with_tools.call_args.kwargs
        tool_names = {tool["name"] for tool in kwargs["tools"]}
        assert status.startswith("failed:")
        assert pipeline._uses_local_moe() is True
        assert pipeline._uses_compact_local_moe() is False
        assert "save_deliverable" in tool_names
        assert kwargs["required_tool"] == "save_deliverable"
        assert kwargs["terminate_after_tool"] == "save_deliverable"
        assert kwargs["terminate_on_unavailable_tools"] is None
        assert kwargs["strict_required_tool"] is False
        assert kwargs["reopen_intrusion_tools_on_contract_error"] is False
        assert kwargs["force_tool_on_stall"] is False
        assert kwargs["recover_required_tool_on_stall"] is False
        assert "ssh_login" not in {tool["name"] for tool in kwargs["tools"]}
        assert kwargs["max_turns"] == 80
        assert kwargs["max_tokens"] == 16384

        model_output = {
            "summary": {"devices_compromised": 1},
            "compromised_devices": [{"device_ip": "192.0.2.10"}],
        }
        def save_model_output(**request):
            save = next(tool for tool in request["tools"] if tool["name"] == "save_deliverable")
            save["function"](filename="05_intrusion.json", content=json.dumps(model_output))
            return "Done."

        mock_provider.chat_with_tools.side_effect = save_model_output
        results = {"intrusion": pipeline._run_agent(AGENTS["intrusion"])}
        pipeline._ensure_intrusion_deliverable(AGENTS["intrusion"], results)

        assert json.loads(
            (pipeline.run_dir / "05_intrusion.json").read_text()
        ) == model_output
        assert results["intrusion"] == "completed"
