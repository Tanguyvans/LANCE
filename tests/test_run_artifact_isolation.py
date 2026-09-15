"""Run-local files and validators; no model, network or scenario execution."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json
from threading import Barrier
from types import SimpleNamespace

import pytest

from src.agent.pipeline import Pipeline
from src.agent.registry import AgentConfig
from src.agent.tools import deliverable
from src.agent import validators


@pytest.fixture
def create_run(tmp_path, monkeypatch):
    class FixedDateTime:
        @staticmethod
        def now():
            return datetime(2026, 9, 15, 12, 0, 0)

    monkeypatch.setattr("src.agent.pipeline.datetime", FixedDateTime)
    monkeypatch.setattr("src.agent.cost_tracker._resolve_pricing", lambda *_a, **_k: (
        {"input": 0.0, "output": 0.0}, "offline-test", True,
    ))
    monkeypatch.setattr("src.agent.core.runtime.filter_unavailable_tools", lambda tools: (tools, {}))

    def create():
        return Pipeline(
            provider=SimpleNamespace(provider="ollama-umons", model="offline"),
            execution_profile="full", manage_scenario=False, output_dir=tmp_path,
        )

    return create


def tools_for(run, filename="result.json"):
    config = AgentConfig(
        name="artifact_test", phase=3, prompt_template="unused",
        tools=["deliverable"], deliverable_file=filename, validator="json_valid",
    )
    tools = run._apply_deliverable_transaction(run._resolve_tools(config), config)
    return {tool["name"]: tool["function"] for tool in tools}


def test_same_second_creates_distinct_run_directories_without_reusing_files(create_run):
    first = create_run()
    (first.run_dir / "sentinel").write_text("first run")
    second = create_run()
    assert first.run_dir != second.run_dir
    assert first.run_dir.name == "2026-09-15_120000"
    assert second.run_dir.name.startswith(first.run_dir.name + "_")
    assert (first.run_dir / "sentinel").read_text() == "first run"
    assert not (second.run_dir / "sentinel").exists()


def test_constructing_second_run_cannot_redirect_first_tools_or_validator(create_run):
    first = create_run()
    first_tools = tools_for(first)
    first_validator = first._validator("json_valid")
    second = create_run()
    second_tools = tools_for(second)
    for tools, owner in ((second_tools, "second"), (first_tools, "first")):
        receipt = json.loads(tools["save_deliverable"](content=json.dumps({"owner": owner})))
        assert receipt["validated"] is True
        assert receipt["status"] == "saved"

    assert json.loads(first_tools["read_deliverable"](filename="result.json"))["content"] == '{"owner": "first"}'
    assert json.loads(second_tools["read_deliverable"](filename="result.json"))["content"] == '{"owner": "second"}'
    (first.run_dir / "first-only.md").write_text("first")
    assert "first-only.md" in json.loads(first_tools["list_deliverables"]())["deliverables"]
    assert "first-only.md" not in json.loads(second_tools["list_deliverables"]())["deliverables"]
    assert first_validator("result.json") == (True, "OK")
    (first.run_dir / "result.json").write_text("invalid JSON")
    assert first_validator("result.json")[0] is False
    assert second._validator("json_valid")("result.json") == (True, "OK")
    for run in (first, second):
        ledger = [json.loads(line) for line in (run.run_dir / "tool_calls.jsonl").read_text().splitlines()]
        saves = [e for e in ledger if e["tool"] == "save_deliverable"]
        assert len(saves) == 1
        assert json.loads(saves[0]["result"])["path"] == str(run.run_dir / "result.json")
        assert saves[0]["execution_origin"] == "runner"


def test_aggregation_is_bound_to_its_run(create_run):
    first, second = create_run(), create_run()
    for run, owner in ((first, "first"), (second, "second")):
        (run.run_dir / "03_device_test.json").write_text(json.dumps({
            "vulnerabilities": [{"owner": owner}],
        }))
    for run, owner in ((first, "first"), (second, "second")):
        assert json.loads(tools_for(run)["aggregate_device_results"]()) == {
            "vulnerabilities": [{"owner": owner}],
        }


def test_parallel_runs_write_same_filename_without_cross_contamination(create_run):
    runs = [create_run(), create_run()]
    barrier = Barrier(2)

    def submit(item):
        index, run = item
        save = tools_for(run)["save_deliverable"]
        barrier.wait(timeout=5)
        return json.loads(save(content=json.dumps({"run": index})))

    with ThreadPoolExecutor(max_workers=2) as workers:
        receipts = list(workers.map(submit, enumerate(runs)))
    for index, (run, receipt) in enumerate(zip(runs, receipts)):
        assert receipt["validated"] is True
        assert json.loads((run.run_dir / "result.json").read_text()) == {"run": index}
        assert json.loads((run.run_dir / receipt["attempt_ref"]).read_text()) == {"run": index}


def test_parallel_phase_transactions_keep_expected_filenames(create_run):
    run = create_run()
    barrier = Barrier(2)

    def submit(filename):
        save = tools_for(run, filename)["save_deliverable"]
        barrier.wait(timeout=5)
        return json.loads(save(content=json.dumps({"file": filename})))

    with ThreadPoolExecutor(max_workers=2) as workers:
        receipts = list(workers.map(submit, ["first.json", "second.json"]))
    for filename, receipt in zip(["first.json", "second.json"], receipts):
        assert receipt["validated"] is True
        assert json.loads((run.run_dir / filename).read_text()) == {"file": filename}
        assert (run.run_dir / receipt["attempt_ref"]).is_file()
    attempts = [json.loads(line) for line in (run.run_dir / "deliverable_attempts.jsonl").read_text().splitlines()]
    assert {entry["filename"] for entry in attempts} == {"first.json", "second.json"}
    assert all(entry["valid"] for entry in attempts)


def test_rejected_attempt_cannot_reuse_another_runs_valid_deliverable(create_run):
    first, second = create_run(), create_run()
    assert json.loads(tools_for(second)["save_deliverable"](content='{"valid":true}'))["validated"]
    rejected = json.loads(tools_for(first)["save_deliverable"](content="not JSON"))
    assert rejected["ok"] is False
    assert rejected["error_kind"] == "deliverable_validation"
    assert not (first.run_dir / "result.json").exists()
    assert (first.run_dir / rejected["attempt_ref"]).read_text() == "not JSON"
    assert (second.run_dir / "result.json").read_text() == '{"valid":true}'


def test_model_cannot_override_bound_output_directory(create_run):
    first, second = create_run(), create_run()
    read = tools_for(first)["read_deliverable"]
    (second.run_dir / "private.md").write_text("other run")
    with pytest.raises(TypeError):
        read(filename="private.md", output_dir=str(second.run_dir))
    save = tools_for(first)["save_deliverable"]
    with pytest.raises(TypeError):
        save(content='{"valid":true}', output_dir=str(second.run_dir))
    assert not (second.run_dir / "result.json").exists()


@pytest.mark.parametrize("path_kind", ["absolute", "parent", "symlink"])
def test_tools_and_validators_reject_paths_into_other_run(create_run, path_kind):
    first, second = create_run(), create_run()
    target = second.run_dir / "private.json"
    target.write_text('{"private":true}')
    if path_kind == "absolute":
        filename = str(target)
    elif path_kind == "parent":
        filename = f"../{second.run_dir.name}/private.json"
    else:
        (first.run_dir / "alias.json").symlink_to(target)
        filename = "alias.json"
    assert first._validator("json_valid")(filename)[0] is False
    assert "error" in json.loads(tools_for(first)["read_deliverable"](filename=filename))
    catalog_save = next(t for t in deliverable.DELIVERABLE_TOOLS if t["name"] == "save_deliverable")
    save = first._wrap_tool(catalog_save)["function"]
    assert "error" in json.loads(save(filename=filename, content="overwritten"))
    assert target.read_text() == '{"private":true}'


def test_attempt_directory_symlink_cannot_write_into_other_run(create_run):
    first, second = create_run(), create_run()
    (first.run_dir / ".attempts").symlink_to(second.run_dir, target_is_directory=True)
    with pytest.raises(ValueError, match="escapes"):
        tools_for(first)["save_deliverable"](content='{"valid":true}')
    assert list(second.run_dir.iterdir()) == []


def test_report_validation_reads_phase4_from_same_run(create_run):
    first, second = create_run(), create_run()
    report = "\n".join(f"## {n}. Section\n" + "Explanation. " * 20 for n in range(1, 11))
    for run, errors in ((first, 1), (second, 0)):
        (run.run_dir / "06_report.md").write_text(report)
        (run.run_dir / "04_exploitation.json").write_text(json.dumps({
            "summary": {"total_tested": 1, "confirmed": 1 - errors, "errors": errors},
        }))
    assert not first._validator("final_report_markdown")("06_report.md")[0]
    assert second._validator("final_report_markdown")("06_report.md")[0]


def test_report_validation_rejects_cross_run_phase4_symlink(create_run):
    first, second = create_run(), create_run()
    report = "\n".join(f"## {n}. Section\n" + "Explanation. " * 20 for n in range(1, 11))
    (first.run_dir / "06_report.md").write_text(report)
    (second.run_dir / "04_exploitation.json").write_text('{"summary":{}}')
    (first.run_dir / "04_exploitation.json").symlink_to(second.run_dir / "04_exploitation.json")
    valid, reason = first._validator("final_report_markdown")("06_report.md")
    assert valid is False
    assert "inside its run directory" in reason


def test_no_mutable_output_or_expected_filename_globals():
    assert not hasattr(deliverable, "OUTPUT_DIR")
    assert not hasattr(deliverable, "_EXPECTED_DELIVERABLE")
    assert not hasattr(validators, "OUTPUT_DIR")
    assert not hasattr(deliverable, "set_output_dir")
    assert not hasattr(deliverable, "set_expected_deliverable")
