"""Agent visibility of laboratory setup/verification internals.

Regression tests for the incident where a phase-1 agent discovered
``ansible_04_inject_vulns.log``, ``ansible_06_verify.log`` and
``scenario_meta.json`` via ``list_deliverables`` and read their contents via
``read_deliverable``. Laboratory internals stay on disk for operator and API
diagnosis but must be unreachable through every agent-facing artifact route.

Nothing here edits existing tests; this file only adds coverage.
"""
import json

from src.agent.artifacts import (
    is_private_agent_artifact,
    is_private_agent_artifact_path,
)
from src.agent.core.runner import AgentRunner
from src.agent.tools.deliverable import (
    aggregate_device_results,
    list_deliverables,
    read_deliverable,
    save_deliverable,
)


LAB_FILES = {
    "ansible_04_inject_vulns.log": "TASK [inject weak cipher] ... expected vuln canary-9f2",
    "ansible_06_verify.log": "VERIFY ok weak_cipher canary-9f2",
    "ansible_03_deploy_scenario.log": "deploy canary",
    "ansible_99_teardown.log": "teardown canary",
    "scenario_meta.json": json.dumps({"scenario_id": 2, "split": "dev-public"}),
    "run_meta.json": json.dumps({"model": "canary-model"}),
    "run_error.json": json.dumps({"error": "canary"}),
    "evaluation.json": json.dumps({"score": 1}),
    "evaluation_summary.json": json.dumps({"score": 1}),
}

LEGIT_FILES = {
    "01_graph_analysis.md": "# graph canary-legit",
    "03_device_s2-web.json": json.dumps({
        "device_id": "s2-web",
        "vulnerabilities": [{"id": "VULN-001", "device_id": "s2-web"}],
    }),
    "05_intrusion_context.json": json.dumps({"targets": []}),
}


def _seed(run_dir, files):
    for name, content in files.items():
        (run_dir / name).write_text(content, encoding="utf-8")


def _runner_listing(run_dir):
    runner = AgentRunner.__new__(AgentRunner)
    runner.run_dir = run_dir
    return AgentRunner._list_previous_deliverables(runner)


class TestLabInternalsHiddenFromAgents:
    def test_incident_files_unreadable_unlistable_unwritable(self, tmp_path):
        _seed(tmp_path, LAB_FILES)
        _seed(tmp_path, LEGIT_FILES)

        listed = json.loads(list_deliverables(output_dir=tmp_path))["deliverables"]
        for name in LAB_FILES:
            assert name not in listed

        for name, content in LAB_FILES.items():
            read_response = read_deliverable(name, output_dir=tmp_path)
            assert "error" in json.loads(read_response)
            assert content not in read_response

            save_response = json.loads(
                save_deliverable(name, "tampered", output_dir=tmp_path)
            )
            assert "error" in save_response
            assert (tmp_path / name).read_text(encoding="utf-8") == content

        # The prompt-side listing uses the same boundary as the tools.
        prompt_listing = _runner_listing(tmp_path)
        for name in LAB_FILES:
            assert name not in prompt_listing

    def test_legitimate_deliverables_preserved(self, tmp_path):
        _seed(tmp_path, LAB_FILES)
        _seed(tmp_path, LEGIT_FILES)

        listed = json.loads(list_deliverables(output_dir=tmp_path))["deliverables"]
        for name in LEGIT_FILES:
            assert name in listed
            assert (
                json.loads(read_deliverable(name, output_dir=tmp_path))["content"]
                == LEGIT_FILES[name]
            )
        for name in LEGIT_FILES:
            assert name in _runner_listing(tmp_path)

    def test_ansible_rule_is_generic_not_playbook_specific(self, tmp_path):
        # Future playbook logs are covered without enumerating playbook names.
        (tmp_path / "ansible_42_future_playbook.log").write_text("canary-future")
        assert is_private_agent_artifact("ansible_42_future_playbook.log")
        assert "error" in json.loads(
            read_deliverable("ansible_42_future_playbook.log", output_dir=tmp_path)
        )
        assert json.loads(list_deliverables(output_dir=tmp_path))["deliverables"] == []

    def test_rule_stays_narrow(self, tmp_path):
        # Files that merely resemble lab logs remain agent-visible.
        assert not is_private_agent_artifact("ansible_notes.md")
        assert not is_private_agent_artifact("my_ansible_backup.log")
        assert not is_private_agent_artifact("01_graph_analysis.md")
        (tmp_path / "ansible_notes.md").write_text("visible")
        assert json.loads(
            read_deliverable("ansible_notes.md", output_dir=tmp_path)
        )["content"] == "visible"


class TestAliasAndTraversalBypass:
    def test_symlink_alias_cannot_expose_lab_files(self, tmp_path):
        _seed(tmp_path, LAB_FILES)
        (tmp_path / "alias.md").symlink_to(tmp_path / "scenario_meta.json")
        (tmp_path / "log-alias.md").symlink_to(
            tmp_path / "ansible_04_inject_vulns.log"
        )

        for alias in ("alias.md", "log-alias.md"):
            assert is_private_agent_artifact_path(tmp_path / alias)
            read_response = read_deliverable(alias, output_dir=tmp_path)
            assert "error" in json.loads(read_response)
            assert "canary" not in read_response
            assert "scenario_id" not in read_response
            assert "error" in json.loads(
                save_deliverable(alias, "tampered", output_dir=tmp_path)
            )
        listed = json.loads(list_deliverables(output_dir=tmp_path))["deliverables"]
        assert "alias.md" not in listed
        assert "log-alias.md" not in listed

    def test_traversal_and_absolute_paths_rejected(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (tmp_path / "ansible_04_inject_vulns.log").write_text("outside-canary")
        target = tmp_path / "ansible_04_inject_vulns.log"

        for attempt in ("../ansible_04_inject_vulns.log", str(target)):
            read_response = read_deliverable(attempt, output_dir=run_dir)
            assert "error" in json.loads(read_response)
            assert "outside-canary" not in read_response

    def test_escaping_symlink_stays_hidden(self, tmp_path):
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        outside = tmp_path / "outside-secret.log"
        outside.write_text("outside-symlink-canary")
        (run_dir / "link.log").symlink_to(outside)

        read_response = read_deliverable("link.log", output_dir=run_dir)
        assert "error" in json.loads(read_response)
        assert "outside-symlink-canary" not in read_response
        assert json.loads(list_deliverables(output_dir=run_dir))["deliverables"] == []


class TestAggregateCannotBypass:
    def test_wildcard_patterns_skip_lab_files_silently(self, tmp_path):
        _seed(tmp_path, LAB_FILES)
        _seed(tmp_path, LEGIT_FILES)

        wide = json.loads(aggregate_device_results("*.json", output_dir=tmp_path))
        assert wide["vulnerabilities"] != []
        assert "scenario_id" not in json.dumps(wide)
        assert "canary-model" not in json.dumps(wide)

        logs = json.loads(
            aggregate_device_results("ansible_*.log", output_dir=tmp_path)
        )
        assert logs == {"vulnerabilities": []}
        assert "canary" not in json.dumps(logs)


class TestOperatorAccessRetained:
    def test_operator_run_file_allowlist_untouched(self):
        from src.api.routes.runs import _PRIVATE_RUN_FILES

        # Operator/API diagnosis keeps direct file access: these internals
        # must NOT be added to the operator-side private set.
        assert "scenario_meta.json" not in _PRIVATE_RUN_FILES
        assert "run_meta.json" not in _PRIVATE_RUN_FILES
        assert not any(
            name.startswith("ansible_") and name.endswith(".log")
            for name in _PRIVATE_RUN_FILES
        )
