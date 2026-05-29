# LANCE — LLM Agent for Network Compromise Evaluation

Artifact for the ACSAC 2026 paper submission. Contains two contributions:

- **IoTChainBench** — 12 reproducible network-scale IoT scenarios with per-vulnerability ground truth (209 vulnerabilities, 5 topological patterns).
- **LANCE** — a six-phase LLM agent harness for multi-hop IoT penetration testing.

## Quick Start

Requires **Python 3.10+**.

```bash
pip install -r requirements.txt
cp .env.example .env        # add OPENROUTER_API_KEY (+ VOYAGE_API_KEY for the knowledge store)

python3 -m src.agent --dry-run --verbose          # validate without LLM calls or infra
python3 -m src.agent --provider openrouter \
        --model google/gemini-2.5-flash-preview   # full run
```

`--dry-run` works offline. A full run needs an LLM key, `VOYAGE_API_KEY` (embeddings), and
live targets deployed via the Ansible playbooks — see [`benchmarks/README.md`](benchmarks/README.md).

## Key Directories

| Path | Description |
|------|-------------|
| `src/agent/` | LANCE pipeline (6 phases, prompts, tools) |
| `src/benchmark/evaluator.py` | Scorer: Recall / Precision / F1 / CVSS-weighted |
| `benchmarks/scenarios/` | IoTChainBench scenario definitions |
| `benchmarks/ground_truth/` | Per-vulnerability ground truth YAMLs |
| `benchmarks/ansible/` | Proxmox deployment and injection playbooks |
| `tests/` | 280+ unit tests |

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
