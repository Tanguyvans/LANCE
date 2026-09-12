# LANCE — LLM Agent for Network Compromise Evaluation

Artifact for the ACSAC 2026 paper submission. Contains two contributions:

- **IoTChainBench** — 29 public network-scale IoT scenarios with per-vulnerability ground truth: S1–S19 for development and S20–S29 reserved for testing. Historical independence of the test set is not yet verified. See the [scenario catalogue](benchmarks/catalog.yaml) and [evaluation protocol](benchmarks/docs/EVALUATION_PROTOCOL.md).
- **LANCE** — a six-phase LLM agent harness for multi-hop IoT penetration testing.

## Quick Start

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt
cp .env.example .env        # add a provider key (+ VOYAGE_API_KEY for the knowledge store)

python3 -m src.agent --dry-run --verbose          # validate without LLM calls or infra
python3 -m src.agent --provider openrouter \
        --model openrouter/auto                   # full run via OpenRouter
```

`--dry-run` works offline. A full run needs an available LLM provider (a Codex
session or provider key), `VOYAGE_API_KEY` for embeddings, and live targets
deployed via the Ansible playbooks — see [`benchmarks/README.md`](benchmarks/README.md).

### Model providers

- **Codex subscription:** install the Codex CLI and run `codex login`. LANCE reuses
  that local ChatGPT session through `codex app-server`; no OpenAI API key or OAuth
  token is copied into the project. Start with `--provider codex` and omit
  `--model` to use the currently recommended model for the account.
- **OpenRouter:** set `OPENROUTER_API_KEY` in `.env`. The dashboard fetches the
  current tool-capable text models and prices from OpenRouter, caches them for one
  hour, and provides a manual refresh button.

On the provisioned headless `nato-master`, Codex CLI is installed automatically
by the deployment playbook and update workflow. Authenticate the root-owned
service session once, then restart the dashboard:

```bash
ssh root@<MASTER_TAILSCALE_IP>
/root/.local/bin/codex login --device-auth
systemctl restart nato-fastapi
```

The Docker image does not include a Codex login session. Use OpenRouter in the
container, or provide both a Codex CLI installation and its authenticated state to
the container explicitly. For a non-Docker service whose `PATH` is restricted,
set `LANCE_CODEX_CLI_PATH` to the absolute Codex executable path.

## Local HMoE and OpenWebUI

The four QLoRA experts can be served behind one OpenAI-compatible API and exposed as
five model IDs in OpenWebUI. See the [local HMoE deployment guide](docs/lance_hmoe_openwebui.md)
for the systemd service, permissions, model registration, and troubleshooting steps.

Training code is versioned only in this workspace and synchronized through a
strict allowlist to the execution-only GPU workspace. See the
[training workspace guide](docs/TRAINING_WORKSPACES.md).

## Key Directories

| Path | Description |
|------|-------------|
| `src/agent/` | LANCE pipeline (6 phases, prompts, tools) |
| `src/benchmark/evaluator.py` | Scorer: Recall / Precision / F1 / CVSS-weighted |
| `benchmarks/scenarios/{dev,test}/` | Scenario definitions grouped by purpose |
| `benchmarks/ground_truth/{dev,test}/` | Matching ground truths; shared scoring contract at the parent level |
| `benchmarks/ansible/` | Proxmox deployment and injection playbooks |
| `tests/` | Automated regression tests |
| `tests/pipeline/` | Pipeline tests grouped by phase and responsibility |

## Dashboard

Live run view (topology, per-phase events) and cross-model benchmark comparison:

Scenario preparation, injection, verification and automatic cleanup report the
playbook, attempt number, timestamps, duration and exit code. Failed operations
show their diagnostic output in keyboard-accessible details; the final message
distinguishes failure, partial completion and cancellation from success.
Ansible output is collected when each command finishes, not streamed line by line.
Full logs are stored in `output/agent/<run>/ansible_*.log`, including automatic
cleanup: retries are appended and partial output is retained on timeouts.
These logs describe failures; they do not automatically repair SSH or Proxmox.

For exceptions escaping the pipeline, `run_error.json` records the active phase,
exception class, sanitized message, causal chain and bounded stack locations
(without source lines or local variables). The same diagnostic is retained in
`run_meta.json` under `run_error`; the sidecar is attempted before cleanup so a
later metadata-write failure does not necessarily lose the original cause.
Both writes are best-effort. These diagnostics do not retry a phase, generate a
fallback report, change the execution profile or turn an unsuccessful run into
a success. Older runs without this diagnostic remain readable.

Full-profile intrusion now enters a save-only closing step when the model stops
without its required deliverable. It permits at most three closing requests
within the existing turn limit, with no further target actions; stop and cost
limits still apply. A rejected or missing final submission leaves an explicitly
incomplete diagnostic synthesis, not a successful campaign. The final phase
event is emitted once after reconciliation and retains the measured usage.
An accepted save is a format/lifecycle check; access and pivot credit still
depend on the existing evidence evaluation, not on the model's declarations.

![Dashboard — live run](docs/images/dashboard-main.png)
![Dashboard — benchmark comparison](docs/images/dashboard-benchmark.png)

## Results

| System | F1 | CVSS-weighted |
|--------|----|--------------|
| LANCE — informed | **0.935** | **86.4%** |
| LANCE — blind | 0.887 | 73.8% |
| CAI adapter | 0.315 | — |
| VulnBot adapter | 0.323 | — |

Full per-scenario breakdown in the paper.
