# LANCE — LLM Agent for Network Compromise Evaluation

LANCE is a six-phase LLM agent pipeline for authorized IoT security testing.
It evaluates vulnerability detection, supporting evidence, intrusion paths and
resource consumption separately.

The accompanying **IoTChainBench** contains 29 public scenarios with
per-vulnerability ground truth: S1–S19 for development and S20–S29 reserved for
testing. Historical independence of the test set is not yet verified. See the
[scenario guide](docs/benchmark/v1/scenarios.md).

## Quick Start

Use **Python 3.12**, the version validated by the test workflow.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m src.agent --help
```

Before running a scenario, configure an available model provider and an isolated,
authorized laboratory using the [execution guide](docs/benchmark/v1/execution.md)
and [Ansible setup](benchmarks/ansible/README.md). Runs can deploy vulnerable
services, consume model budget and remove scenario machines during cleanup.

Dashboard actions require an administrator key; see
[administrator access](docs/provider-auth.md).

## Dashboard

Follow the topology and each phase live, then compare benchmark runs:

- **Audit:** potential findings, retained hypotheses and evidence-checked declarations.
- **Intrusion:** corroborated accesses and verified paths, with explicit limits on pivot evidence, separate from audit scores.
- **Execution:** completed, partial, failed or stopped runs, with diagnostic logs.
- **Consumption:** tokens, elapsed time and cost, including failed attempts.

A completed run does not mean every vulnerability was confirmed. Comparisons
keep development and test scenarios separate and flag incompatible results.

![Dashboard — live run](docs/images/dashboard-main.png)
![Dashboard — benchmark comparison](docs/images/dashboard-benchmark.png)

## Key Directories

| Path | Description |
|------|-------------|
| `src/agent/` | Pipeline phases, prompts and tools |
| `src/benchmark/` | Audit evaluation (precision, recall, F1) and separate intrusion evaluation |
| `benchmarks/` | Scenarios, ground truths and laboratory deployment |
| `model_training/` | Model and expert training, configurations and dedicated tests |
| `tests/` | Application, pipeline and evaluator regression tests |
| `docs/` | Guides, evaluation contracts and historical documentation |

Run the code test suite with `python -m pytest -q` (including
`model_training/tests/`). Code tests are distinct from the benchmark's held-out
evaluation scenarios.

## Documentation

- [Documentation index](docs/README.md)
- [Benchmark, scenarios and evaluation](docs/benchmark/v1/README.md)
- [Pipeline structure](src/agent/phases/README.md)
- [Run artifacts](docs/run-artifacts.md)
- [Model training](model_training/README.md)
