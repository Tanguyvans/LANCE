#!/usr/bin/env python3
"""Train one LANCE Qwen2.5-3B MoE expert with memory-safe QLoRA defaults."""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path

import torch
import yaml
from datasets import concatenate_datasets, load_dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

EXPERTS = ("secretary", "recon", "vuln", "exploit")
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def project_path(value: str | Path) -> Path:
    """Resolve configured paths consistently from the LANCE project root."""
    path = Path(value).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def estimate_total_update_steps(
    train_examples: int,
    *,
    per_device_batch_size: int,
    gradient_accumulation_steps: int,
    num_train_epochs: float,
) -> int:
    """Estimate Trainer update steps for single-GPU QLoRA runs."""
    examples_per_update = max(1, per_device_batch_size) * max(
        1, gradient_accumulation_steps
    )
    updates_per_epoch = max(1, math.ceil(train_examples / examples_per_update))
    return max(1, math.ceil(updates_per_epoch * num_train_epochs))


def effective_step_interval(configured_steps: int, total_update_steps: int) -> int:
    """Keep step-based actions reachable on short training runs."""
    configured_steps = max(1, int(configured_steps or 1))
    total_update_steps = max(1, int(total_update_steps or 1))
    return min(configured_steps, total_update_steps)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train one LANCE Qwen2.5-3B QLoRA expert")
    parser.add_argument("--expert", choices=EXPERTS, required=True)
    parser.add_argument(
        "--config",
        default=str(Path(__file__).with_name("configs") / "qlora_qwen2_5_3b.yaml"),
    )
    parser.add_argument("--dataset-path")
    parser.add_argument("--feedback-dataset-path")
    parser.add_argument("--feedback-repeat", type=int)
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--output-dir")
    parser.add_argument("--max-seq-length", type=int)
    parser.add_argument("--resume-from-checkpoint", nargs="?", const=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = project_path(args.config)
    config = load_config(str(config_path))
    training = config["training"]
    model_config = config["model"]

    expert_lengths = training.get("expert_max_seq_length", {})
    max_seq_length = int(
        args.max_seq_length
        or expert_lengths.get(args.expert)
        or training["max_seq_length"]
    )
    dataset_path = project_path(
        args.dataset_path
        or config["data"]["dataset_template"].format(expert=args.expert)
    )
    output_path = project_path(
        args.output_dir or Path(training["output_root"]) / args.expert
    )
    if not args.validate_only:
        if args.resume_from_checkpoint:
            checkpoint_path = (
                output_path
                if args.resume_from_checkpoint is True
                else project_path(args.resume_from_checkpoint)
            )
            if not checkpoint_path.exists():
                raise FileNotFoundError(f"Resume checkpoint not found: {checkpoint_path}")
        elif output_path.exists() and any(output_path.iterdir()):
            raise FileExistsError(
                f"Output directory is not empty: {output_path}. "
                "Use --resume-from-checkpoint after an interrupted run, or "
                "choose a new --output-dir. Existing adapters are never overwritten."
            )
    if not dataset_path.is_file():
        raise FileNotFoundError(
            f"Prepared 3B dataset not found: {dataset_path}. "
            "Run training/prepare_3b_datasets.py first."
        )

    model_id = model_config["name_or_path"]

    dataset = load_dataset("json", data_files=str(dataset_path), split="train")
    validation_split = float(config["data"].get("validation_split", 0.02))
    if not 0.0 < validation_split < 1.0:
        raise ValueError("data.validation_split must be between 0 and 1")
    split = dataset.train_test_split(
        test_size=validation_split,
        seed=int(training.get("seed", 42)),
    )
    feedback_value = (
        args.feedback_dataset_path
        or config["data"].get("feedback_dataset_template", "").format(
            expert=args.expert
        )
    )
    feedback_path = project_path(feedback_value) if feedback_value else None
    feedback_repeat_by_expert = config["data"].get("feedback_repeat_by_expert", {})
    feedback_repeat = int(
        args.feedback_repeat
        if args.feedback_repeat is not None
        else feedback_repeat_by_expert.get(
            args.expert,
            config["data"].get("feedback_repeat", 0),
        )
    )
    feedback_count = 0
    if feedback_repeat < 0:
        raise ValueError("data.feedback_repeat must be >= 0")
    if feedback_path is not None and feedback_repeat:
        if not feedback_path.is_file():
            raise FileNotFoundError(f"Accepted feedback dataset not found: {feedback_path}")
        feedback = load_dataset(
            "json",
            data_files=str(feedback_path),
            split="train",
            features=dataset.features,
        )
        feedback_count = len(feedback)
        if not feedback_count:
            raise ValueError("Accepted feedback dataset is empty")
        split["train"] = concatenate_datasets(
            [split["train"], *[feedback for _ in range(feedback_repeat)]]
        ).shuffle(seed=int(training.get("seed", 42)))

    if args.validate_only:
        print(
            f"Validated {args.expert}: {len(split['train'])} train / "
            f"{len(split['test'])} eval examples, context={max_seq_length}, "
            f"feedback={feedback_count}x{feedback_repeat}"
        )
        return

    tokenizer = AutoTokenizer.from_pretrained(model_id)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"
    tokenizer.model_max_length = max_seq_length
    chat_template_path = config["data"].get("chat_template_path")
    if chat_template_path:
        tokenizer.chat_template = project_path(chat_template_path).read_text(
            encoding="utf-8"
        )

    compute_dtype = getattr(torch, config["bitsandbytes"]["bnb_4bit_compute_dtype"])
    quantization_config = BitsAndBytesConfig(
        load_in_4bit=config["bitsandbytes"]["load_in_4bit"],
        bnb_4bit_quant_type=config["bitsandbytes"]["bnb_4bit_quant_type"],
        bnb_4bit_use_double_quant=config["bitsandbytes"]["bnb_4bit_use_double_quant"],
        bnb_4bit_compute_dtype=compute_dtype,
    )

    if torch.cuda.is_available():
        torch.backends.cuda.matmul.allow_tf32 = True
        device_map = {"": torch.cuda.current_device()}
    else:
        raise RuntimeError("Qwen2.5-3B QLoRA training requires a CUDA GPU")

    print(f"Loading {model_id} in 4-bit for expert {args.expert}...")
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=quantization_config,
        attn_implementation=model_config.get("attn_implementation", "sdpa"),
        dtype=compute_dtype,
        device_map=device_map,
        low_cpu_mem_usage=True,
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=training.get("gradient_checkpointing", True),
        gradient_checkpointing_kwargs={
            "use_reentrant": training.get("gradient_checkpointing_use_reentrant", False)
        },
    )

    lora_config = LoraConfig(
        r=config["lora"]["r"],
        lora_alpha=config["lora"]["lora_alpha"],
        lora_dropout=config["lora"]["lora_dropout"],
        bias=config["lora"]["bias"],
        task_type=config["lora"]["task_type"],
        target_modules=config["lora"]["target_modules"],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    total_update_steps = estimate_total_update_steps(
        len(split["train"]),
        per_device_batch_size=int(training["per_device_train_batch_size"]),
        gradient_accumulation_steps=int(training["gradient_accumulation_steps"]),
        num_train_epochs=float(training["num_train_epochs"]),
    )
    eval_strategy = training["eval_strategy"]
    eval_steps = int(training.get("eval_steps", 1) or 1)
    if eval_strategy == "steps" and len(split["test"]):
        eval_steps = effective_step_interval(eval_steps, total_update_steps)
    save_steps = effective_step_interval(
        int(training.get("save_steps", 1) or 1), total_update_steps
    )

    sft_config = SFTConfig(
        output_dir=str(output_path),
        num_train_epochs=training["num_train_epochs"],
        per_device_train_batch_size=training["per_device_train_batch_size"],
        per_device_eval_batch_size=training["per_device_eval_batch_size"],
        gradient_accumulation_steps=training["gradient_accumulation_steps"],
        learning_rate=training["learning_rate"],
        weight_decay=training["weight_decay"],
        max_grad_norm=training["max_grad_norm"],
        warmup_ratio=training["warmup_ratio"],
        lr_scheduler_type=training["lr_scheduler_type"],
        logging_steps=training["logging_steps"],
        save_strategy=training["save_strategy"],
        save_steps=save_steps,
        eval_strategy=eval_strategy,
        eval_steps=eval_steps,
        prediction_loss_only=training["prediction_loss_only"],
        save_total_limit=training["save_total_limit"],
        seed=training["seed"],
        optim=training["optim"],
        report_to=training.get("report_to", "none"),
        bf16=True,
        fp16=False,
        tf32=True,
        gradient_checkpointing=training.get("gradient_checkpointing", True),
        gradient_checkpointing_kwargs={
            "use_reentrant": training.get("gradient_checkpointing_use_reentrant", False)
        },
        max_length=max_seq_length,
        packing=training.get("packing", False),
        assistant_only_loss=training.get("assistant_only_loss", True),
        dataset_num_proc=training.get("dataset_num_proc", 1),
        dataloader_num_workers=training.get("dataloader_num_workers", 0),
    )
    trainer = SFTTrainer(
        model=model,
        train_dataset=split["train"],
        eval_dataset=split["test"],
        processing_class=tokenizer,
        args=sft_config,
    )

    print(
        f"Training {args.expert}: {len(split['train'])} train / "
        f"{len(split['test'])} eval examples, context={max_seq_length}, "
        f"feedback={feedback_count}x{feedback_repeat}, "
        f"updates={total_update_steps}, eval_steps={eval_steps}"
    )
    trainer.train(resume_from_checkpoint=args.resume_from_checkpoint)
    trainer.model.save_pretrained(output_path)
    tokenizer.save_pretrained(output_path)
    print(f"Training complete. Adapter saved to {output_path}")


if __name__ == "__main__":
    main()
