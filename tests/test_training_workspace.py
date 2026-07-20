from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.training_workspace import (
    apply_plan,
    build_pull_adapter_plan,
    build_pull_plan,
    build_push_plan,
    load_manifest,
    safe_relative_path,
)


def _manifest(**overrides) -> dict:
    manifest = {
        "schema_version": "1.0",
        "push_files": ["training/train_qlora_3b.py"],
        "pull_report_globs": [
            "output/preflight_3b_report.json",
            "output/adapters/lance-qlora_moe_3b/*/adapter_config.json",
        ],
        "pull_adapter_experts": ["recon", "vuln", "exploit", "secretary"],
        "pull_adapter_files": [
            "adapter_config.json", "adapter_model.safetensors", "tokenizer_config.json",
        ],
        "blocked_roots": [".git", "data", "env", "output", "wandb"],
        "max_report_size_bytes": 1024,
        "max_total_report_size_bytes": 4096,
        "max_adapter_file_size_bytes": 1024,
        "max_total_adapter_size_bytes": 8192,
    }
    manifest.update(overrides)
    return manifest


def test_rejects_blocked_and_parent_paths() -> None:
    blocked = _manifest()["blocked_roots"]
    with pytest.raises(ValueError, match="Blocked workspace root"):
        safe_relative_path("data/private.jsonl", blocked)
    with pytest.raises(ValueError, match="Unsafe relative path"):
        safe_relative_path("../outside", blocked)


def test_push_is_allowlisted_and_non_destructive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    remote = tmp_path / "remote"
    training = source / "training"
    training.mkdir(parents=True)
    remote.mkdir()
    (training / "train_qlora_3b.py").write_text("canonical\n")
    unrelated = remote / "data" / "dataset.jsonl"
    unrelated.parent.mkdir()
    unrelated.write_text("keep me\n")

    plan = build_push_plan(source, remote, _manifest())
    assert [str(item.relative_path) for item in plan] == [
        "training/train_qlora_3b.py"
    ]
    assert plan[0].status == "create"
    assert apply_plan(plan) == 1
    assert (remote / "training" / "train_qlora_3b.py").read_text() == "canonical\n"
    assert unrelated.read_text() == "keep me\n"


def test_pull_reports_never_collects_weights(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    reports = tmp_path / "reports"
    adapter = remote / "output" / "adapters" / "lance-qlora_moe_3b" / "recon"
    adapter.mkdir(parents=True)
    (adapter / "adapter_config.json").write_text('{"base_model":"3b"}\n')
    (adapter / "adapter_model.safetensors").write_bytes(b"weights")

    plan = build_pull_plan(remote, reports, _manifest())
    assert [item.relative_path.name for item in plan] == ["adapter_config.json"]
    assert all(item.source.suffix == ".json" for item in plan)


def test_pull_rejects_oversized_report(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    report = remote / "output" / "preflight_3b_report.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"payload": "x" * 2000}))

    with pytest.raises(ValueError, match="Report exceeds"):
        build_pull_plan(remote, tmp_path / "reports", _manifest())


def test_manifest_requires_boundary_fields(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version":"1.0"}')
    with pytest.raises(ValueError, match="Sync manifest is missing"):
        load_manifest(path)



def test_pull_adapters_collects_only_explicit_final_files(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    local = tmp_path / "local"
    for expert in ("recon", "vuln", "exploit", "secretary"):
        adapter = remote / "output" / "adapters" / "lance-qlora_moe_3b" / expert
        adapter.mkdir(parents=True)
        (adapter / "adapter_config.json").write_text('{"base_model":"3b"}\n')
        (adapter / "adapter_model.safetensors").write_bytes(b"weights")
        (adapter / "tokenizer_config.json").write_text("{}\n")
        checkpoint = adapter / "checkpoint-1"
        checkpoint.mkdir()
        (checkpoint / "trainer_state.json").write_text("{}\n")

    plan = build_pull_adapter_plan(remote, local, _manifest())

    assert len(plan) == 12
    assert {item.relative_path.parts[0] for item in plan} == {
        "recon", "vuln", "exploit", "secretary",
    }
    assert all("checkpoint-1" not in item.relative_path.parts for item in plan)
    assert apply_plan(plan) == 12
    assert (local / "recon" / "adapter_model.safetensors").read_bytes() == b"weights"


def test_pull_adapters_fails_closed_when_an_expert_is_incomplete(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    adapter = remote / "output" / "adapters" / "lance-qlora_moe_3b" / "recon"
    adapter.mkdir(parents=True)
    (adapter / "adapter_config.json").write_text("{}\n")

    with pytest.raises(ValueError, match="Source must be a regular file"):
        build_pull_adapter_plan(
            remote,
            tmp_path / "local",
            _manifest(pull_adapter_experts=["recon"]),
        )


def test_pull_adapters_rejects_nested_or_oversized_entries(tmp_path: Path) -> None:
    remote = tmp_path / "remote"
    with pytest.raises(ValueError, match="Invalid adapter filename"):
        build_pull_adapter_plan(
            remote,
            tmp_path / "local",
            _manifest(pull_adapter_experts=["recon"], pull_adapter_files=["checkpoint-1/model.bin"]),
        )
