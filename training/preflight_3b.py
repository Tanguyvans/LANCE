#!/usr/bin/env python3
"""Validate Qwen2.5-3B training inputs and runtime without training a model."""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import inspect
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPERTS = ("secretary", "recon", "vuln", "exploit")
REQUIRED_SFT_PARAMETERS = {
    "assistant_only_loss", "bf16", "dataset_num_proc", "eval_strategy",
    "gradient_checkpointing_kwargs", "max_length", "packing",
    "prediction_loss_only", "tf32",
}


def project_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        config = yaml.safe_load(handle)
    if not isinstance(config, dict):
        raise ValueError(f"Configuration must be a mapping: {path}")
    for section in ("model", "training", "data"):
        if not isinstance(config.get(section), dict):
            raise ValueError(f"Missing configuration section: {section}")
    return config


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_jsonl(path: Path, *, expert: str, prepared_model: str | None) -> dict[str, Any]:
    count = 0
    truncated = 0
    errors: list[str] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append(f"line {line_number}: invalid JSON ({exc})")
                continue
            if not isinstance(row, dict):
                errors.append(f"line {line_number}: row is not an object")
                continue
            messages = row.get("messages")
            if not isinstance(messages, list) or not messages:
                errors.append(f"line {line_number}: missing messages")
                continue
            if not any(isinstance(item, dict) and item.get("role") == "assistant" for item in messages):
                errors.append(f"line {line_number}: no assistant message")
            metadata = row.get("metadata")
            if prepared_model:
                if not isinstance(metadata, dict):
                    errors.append(f"line {line_number}: missing metadata")
                else:
                    if metadata.get("expert") != expert:
                        errors.append(f"line {line_number}: metadata expert mismatch")
                    if metadata.get("prepared_for") != prepared_model:
                        errors.append(f"line {line_number}: prepared_for mismatch")
                    truncated += int(bool(metadata.get("content_truncated")))
                    if "eval-sealed" in json.dumps(metadata, sort_keys=True).lower():
                        errors.append(f"line {line_number}: sealed evaluation data is forbidden")
            if len(errors) >= 20:
                break
    if not count:
        errors.append("dataset is empty")
    return {
        "path": str(path), "rows": count, "content_truncated_rows": truncated,
        "size_bytes": path.stat().st_size, "sha256": sha256_file(path), "errors": errors,
    }


def validate_adapter_output(path: Path, *, expected_model: str) -> dict[str, Any]:
    errors: list[str] = []
    required = ("adapter_config.json", "adapter_model.safetensors", "tokenizer_config.json")
    missing = [name for name in required if not (path / name).is_file()]
    if missing:
        errors.append("missing files: " + ", ".join(missing))
    adapter_config: dict[str, Any] = {}
    config_path = path / "adapter_config.json"
    if config_path.is_file():
        try:
            adapter_config = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid adapter_config.json: {exc}")
        else:
            actual_model = adapter_config.get("base_model_name_or_path")
            if actual_model != expected_model:
                errors.append(
                    f"base model mismatch: expected {expected_model}, got {actual_model}"
                )
    weights = path / "adapter_model.safetensors"
    if weights.is_file() and weights.stat().st_size == 0:
        errors.append("adapter_model.safetensors is empty")
    return {
        "path": str(path),
        "base_model": adapter_config.get("base_model_name_or_path"),
        "weights_size_bytes": weights.stat().st_size if weights.is_file() else 0,
        "errors": errors,
    }


def package_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in ("torch", "transformers", "trl", "peft", "bitsandbytes", "datasets", "accelerate", "fastapi", "uvicorn"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = "MISSING"
    return versions


def runtime_checks() -> tuple[dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    versions = package_versions()
    missing = [name for name, version in versions.items() if version == "MISSING"]
    if missing:
        errors.append(f"Missing training packages: {', '.join(missing)}")
    import torch
    from trl import SFTConfig
    absent = sorted(REQUIRED_SFT_PARAMETERS - set(inspect.signature(SFTConfig).parameters))
    if absent:
        errors.append("Installed TRL is incompatible; SFTConfig lacks: " + ", ".join(absent))
    cuda_available = torch.cuda.is_available()
    bf16_supported = cuda_available and torch.cuda.is_bf16_supported()
    if not cuda_available:
        errors.append("CUDA is not available")
    elif not bf16_supported:
        errors.append("The CUDA GPU does not support BF16")
    gpu: dict[str, Any] = {
        "cuda_available": cuda_available, "cuda_version": torch.version.cuda,
        "bf16_supported": bf16_supported,
    }
    if cuda_available:
        props = torch.cuda.get_device_properties(0)
        gpu.update({"name": props.name, "total_memory_bytes": props.total_memory})
    active_processes: list[str] = []
    nvidia_smi = shutil.which("nvidia-smi")
    if nvidia_smi:
        query = subprocess.run(
            [nvidia_smi, "--query-compute-apps=pid,process_name,used_memory", "--format=csv,noheader"],
            check=False, capture_output=True, text=True,
        )
        if query.returncode == 0:
            active_processes = [line.strip() for line in query.stdout.splitlines() if line.strip()]
            if active_processes:
                warnings.append("GPU compute processes are active; stop them before training")
    gpu["active_compute_processes"] = active_processes
    return {"packages": versions, "gpu": gpu}, errors, warnings


def run_dataset_validation(config_path: Path, experts: list[str]) -> list[str]:
    command_path = PROJECT_ROOT / "training" / "train_qlora_3b.py"
    outputs: list[str] = []
    for expert in experts:
        command = [sys.executable, str(command_path), "--expert", expert, "--config", str(config_path), "--validate-only"]
        environment = os.environ.copy()
        environment.update({"PYTHONPATH": "", "PYTHONDONTWRITEBYTECODE": "1"})
        result = subprocess.run(
            command, cwd=PROJECT_ROOT, env=environment, check=False,
            capture_output=True, text=True,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"{expert} --validate-only failed:\n{detail}")
        output = result.stdout.strip().splitlines()
        outputs.append(output[-1] if output else f"{expert}: validated")
    return outputs


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Preflight Qwen2.5-3B; never trains a model")
    parser.add_argument("--config", type=Path, default=PROJECT_ROOT / "training/configs/qlora_qwen2_5_3b.yaml")
    parser.add_argument("--experts", nargs="+", choices=EXPERTS, default=list(EXPERTS))
    parser.add_argument("--min-free-gb", type=float, default=40.0)
    parser.add_argument("--strict-gpu-idle", action="store_true")
    parser.add_argument("--allow-existing-output", action="store_true")
    parser.add_argument("--require-adapters", action="store_true")
    parser.add_argument("--skip-runtime-validation", action="store_true")
    parser.add_argument("--report", type=Path, default=PROJECT_ROOT / "output/preflight_3b_report.json")
    args = parser.parse_args()

    print("PRE-FLIGHT ONLY: no model weights will be loaded and no training will run.")
    config_path = project_path(args.config)
    config = load_config(config_path)
    errors: list[str] = []
    warnings: list[str] = []
    datasets: dict[str, Any] = {}
    adapters: dict[str, Any] = {}
    model_id = str(config["model"]["name_or_path"])
    data = config["data"]
    training = config["training"]
    template_path = project_path(data["chat_template_path"])
    if not template_path.is_file():
        errors.append(f"Missing chat template: {template_path}")
    else:
        template = template_path.read_text(encoding="utf-8")
        if "{%- generation %}" not in template or "{%- endgeneration %}" not in template:
            errors.append("Chat template lacks TRL generation masks")
    output_root = project_path(training["output_root"])
    for expert in args.experts:
        dataset_path = project_path(data["dataset_template"].format(expert=expert))
        if not dataset_path.is_file():
            errors.append(f"Missing prepared dataset: {dataset_path}")
            continue
        result = validate_jsonl(dataset_path, expert=expert, prepared_model=model_id)
        datasets[expert] = {"dataset": result}
        errors.extend(f"{expert}: {message}" for message in result["errors"])
        repeat = int(data.get("feedback_repeat_by_expert", {}).get(expert, data.get("feedback_repeat", 0)))
        feedback_template = data.get("feedback_dataset_template")
        if repeat and feedback_template:
            feedback_path = project_path(feedback_template.format(expert=expert))
            if not feedback_path.is_file():
                errors.append(f"Missing accepted feedback: {feedback_path}")
            else:
                feedback = validate_jsonl(feedback_path, expert=expert, prepared_model=None)
                datasets[expert].update({"feedback": feedback, "feedback_repeat": repeat})
                errors.extend(f"{expert} feedback: {message}" for message in feedback["errors"])
        expert_output = output_root / expert
        if args.require_adapters:
            if not expert_output.is_dir():
                errors.append(f"Missing adapter output for {expert}: {expert_output}")
            else:
                adapter = validate_adapter_output(expert_output, expected_model=model_id)
                adapters[expert] = adapter
                errors.extend(f"{expert} adapter: {message}" for message in adapter["errors"])
        elif not args.allow_existing_output and expert_output.exists() and any(expert_output.iterdir()):
            errors.append(f"Existing output for {expert}: {expert_output}; resume it explicitly or choose a new output directory")
    disk = shutil.disk_usage(PROJECT_ROOT)
    free_gb = disk.free / 1024**3
    if free_gb < args.min_free_gb:
        errors.append(f"Only {free_gb:.1f} GiB free; at least {args.min_free_gb:.1f} GiB required")
    runtime, runtime_errors, runtime_warnings = runtime_checks()
    errors.extend(runtime_errors)
    warnings.extend(runtime_warnings)
    if args.strict_gpu_idle and runtime["gpu"]["active_compute_processes"]:
        errors.append("GPU is not idle (--strict-gpu-idle)")
    validation_outputs: list[str] = []
    if not errors and not args.skip_runtime_validation:
        try:
            validation_outputs = run_dataset_validation(config_path, args.experts)
        except RuntimeError as exc:
            errors.append(str(exc))
    report = {
        "schema_version": "1.0", "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "preflight-only", "status": "failed" if errors else "ready",
        "project_root": str(PROJECT_ROOT), "config": str(config_path),
        "config_sha256": sha256_file(config_path), "model": model_id,
        "experts": args.experts, "datasets": datasets, "adapters": adapters, "disk_free_bytes": disk.free,
        "runtime": runtime, "validate_only_results": validation_outputs,
        "warnings": warnings, "errors": errors,
    }
    write_report(project_path(args.report), report)
    for output in validation_outputs:
        print(output)
    for warning in warnings:
        print(f"WARNING: {warning}")
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    print(f"Report: {project_path(args.report)}")
    print("READY" if not errors else "NOT READY")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
