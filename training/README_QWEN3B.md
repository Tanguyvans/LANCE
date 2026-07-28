# Qwen2.5-3B expert training

This profile trains the four LANCE LoRA experts sequentially on a 16 GB NVIDIA GPU.
It keeps the existing 0.5B/v2 training files unchanged.

## Workspace boundary

`/home/tanguy/LANCE` is the only Git source of truth. Before running a training
command in `/home/leo/LANCE`, preview and apply the allowlisted source sync:

```bash
cd /home/tanguy/LANCE
python3 scripts/training_workspace.py status
python3 scripts/training_workspace.py push
python3 scripts/training_workspace.py push --apply
```

The Leo workspace contains datasets, environments and model outputs, but is
never used to commit or push code. See `docs/TRAINING_WORKSPACES.md`.

## Prepared datasets

The generated `data/finetuning/<expert>/<expert>_moe_dataset_3b.jsonl` files
are bounded conversational windows:

- `recon`: 6144 tokens
- `vuln`: 4096 tokens
- `exploit`: 6144 tokens
- `secretary`: 6144 tokens

Each window keeps assistant tool calls paired with their tool results. The tool catalog is reduced to every tool used in the window plus two distractors. Oversized tool results and, only as a final fallback, the middle of very long system prompts are compacted. The beginning and end of system prompts are retained.

Regenerate all datasets:

```bash
cd /home/leo/LANCE
PYTHONPATH= env/bin/python training/prepare_3b_datasets.py
```

Regenerate one expert:

```bash
PYTHONPATH= env/bin/python training/prepare_3b_datasets.py --experts recon
```

## Preflight

Before using GPU time, validate package compatibility, CUDA/BF16 support, free disk
space, chat-template masks, every prepared dataset, feedback paths, and output
safety:

```bash
cd /home/leo/LANCE
PYTHONDONTWRITEBYTECODE=1 env/bin/python training/preflight_3b.py --strict-gpu-idle
```

The command never loads model weights and never starts training. It writes a
machine-readable report to `output/preflight_3b_report.json`. Existing expert
output directories are rejected by default; resume explicitly or choose a new
output directory instead of overwriting adapters.

After all four runs, validate that every adapter is complete and declares the
Qwen2.5-3B base model, still without loading model weights:

```bash
PYTHONDONTWRITEBYTECODE=1 env/bin/python training/preflight_3b.py \
  --require-adapters --allow-existing-output
```

## Training

Stop GPU inference services before training so the trainer has the full RTX 4080 available:

```bash
systemctl --user stop lance-hmoe.service
```

Train one expert:

```bash
cd /home/leo/LANCE
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  PYTHONPATH= env/bin/python training/train_qlora_3b.py --expert recon
```

Available experts are `secretary`, `recon`, `vuln`, and `exploit`. This refreshed
run writes adapters to `output/adapters/lance-qlora_moe_3b_20260724/<expert>` so
the previous `lance-qlora_moe_3b` adapters remain untouched.

Recon and Vuln train for two epochs. Secretary and Exploit train for one epoch
to keep their runs within the planned training window. Evaluation runs before
training and after each epoch; the final adapter is restored from the checkpoint
with the lowest `eval_loss` rather than blindly keeping the last epoch.

Resume the latest checkpoint:

```bash
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  PYTHONPATH= env/bin/python training/train_qlora_3b.py \
  --expert recon --resume-from-checkpoint
```

If a 6144-token expert still runs out of memory, retry it with:

```bash
PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  PYTHONPATH= env/bin/python training/train_qlora_3b.py \
  --expert recon --max-seq-length 4096
```

Restart the inference service after training only after its base model and adapter path have been updated for the 3B outputs.


Collect small JSON reports back into Tanguy's ignored `output/` tree:

```bash
cd /home/tanguy/LANCE
python3 scripts/training_workspace.py pull-reports
python3 scripts/training_workspace.py pull-reports --apply
```

`pull-reports` never collects adapter weights, checkpoints, datasets, `wandb/`
or Python environments. Once all four final adapters are validated, preview and
collect only their allowlisted runtime files with:

```bash
python3 scripts/training_workspace.py pull-adapters
python3 scripts/training_workspace.py pull-adapters --apply
```

The command writes to `output/adapters/lance-qlora_moe_3b_20260724/`; it excludes
every checkpoint and trainer-state file.
