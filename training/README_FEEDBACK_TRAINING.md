# Reviewed error feedback — Qwen2.5 3B

The accepted feedback dataset is:

```text
data/finetuning/vuln/vuln_feedback_accepted_20260716.jsonl
```

Its immutable review export is stored in:

```text
data/finetuning/vuln/reviewed_feedback/leo-training-2026-07-16/
```

The Qwen2.5 3B training configuration injects the accepted traces into the
`vuln` training split eight times. Feedback is added only after the original
dataset has been split, so no reviewed feedback trace enters the evaluation
split.

Validate dataset composition without loading the model or requiring CUDA:

```bash
env/bin/python training/train_qlora_3b.py \
  --expert vuln \
  --validate-only
```

Train the vulnerability expert with feedback:

```bash
env/bin/python training/train_qlora_3b.py --expert vuln
```

Disable feedback for a baseline run:

```bash
env/bin/python training/train_qlora_3b.py \
  --expert vuln \
  --feedback-repeat 0
```

The feedback factor can be overridden with `--feedback-repeat N`. Keep the
review export and SFT dataset versioned together so a future run remains
reproducible.
