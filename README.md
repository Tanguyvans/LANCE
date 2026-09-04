# LANCE — LLM Agent for Network Compromise Evaluation

Artifact for the ACSAC 2026 paper submission. Contains two contributions:

- **IoTChainBench** — 12 reproducible network-scale IoT scenarios with per-vulnerability ground truth (209 vulnerabilities, 5 topological patterns).
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
| `benchmarks/scenarios/` | IoTChainBench scenario definitions |
| `benchmarks/ground_truth/` | Per-vulnerability ground truth YAMLs |
| `benchmarks/ansible/` | Proxmox deployment and injection playbooks |
| `tests/` | 900+ automated tests |

## Dashboard

Live run view (topology, per-phase events) and cross-model benchmark comparison:

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
