# LANCE — LLM Agent for Network Compromise Evaluation

Artifact for the ACSAC 2026 paper submission. Contains two contributions:

- **IoTChainBench** — 29 public network-scale IoT scenarios with per-vulnerability ground truth: S1–S19 for development and S20–S29 reserved for testing. Historical independence of the test set is not yet verified. See the [scenario catalogue](benchmarks/catalog.yaml) and [benchmark V1 documentation](docs/benchmark/v1/README.md).
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

Start with the [documentation index](docs/README.md) and the
[benchmark V1 reference](docs/benchmark/v1/README.md) (French).
For the code structure, see the [phase guide](src/agent/phases/README.md) and the
[run-local artifact contract](docs/run-artifacts.md) (French).

| Path | Description |
|------|-------------|
| `src/agent/` | LANCE pipeline (6 phases, prompts, tools) |
| `src/benchmark/evaluator.py` | Scorer: Recall / Precision / F1 / CVSS-weighted |
| `benchmarks/scenarios/{dev,test}/` | Scenario definitions grouped by purpose |
| `benchmarks/ground_truth/{dev,test}/` | Matching ground truths; shared scoring contract at the parent level |
| `benchmarks/ansible/` | Proxmox deployment and injection playbooks |
| `model_training/` | Model and QLoRA/MoE expert training, configurations and dedicated tests |
| `tests/` | Automated application, pipeline and evaluator regression tests |
| `tests/pipeline/` | Pipeline tests grouped by phase and responsibility |

For model training, start with [model_training/README.md](model_training/README.md).
Run the complete code test suite with `python -m pytest -q` (both `tests/` and
`model_training/tests/`). These automated code tests are distinct from the
benchmark's held-out evaluation scenarios.

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

The live end-of-run summary displays audit precision, recall, F1 and VP/FP/FN
from the final confirmed stage of the evaluation funnel. Legacy metrics remain
available for compatibility but are not mixed into this summary. Intrusion is
shown separately using evaluated target compromises, verified paths and verified
network hops; unavailable evidence is not displayed as zero. Execution completion
is not a claim of intrusion success: device-analysis failures, inconclusive or
errored checks and unavailable evaluation are surfaced as explicit reservations.
These messages do not change lifecycle status, scoring or proof requirements.

MQTT listener calls explicitly pass their TCP port (1883 by default) to the
process. Invalid ports and unknown MQTT arguments are rejected before launch.
The tool ledger preserves the requested arguments alongside the result's
`execution_attestation` (effective host, TCP port and topic); this metadata does
not prove a successful connection and adds no credential copy. MQTT/TCP on port
9001 is still not MQTT-over-WebSocket. This execution fix does not change proof
criteria or retrofit older traces: a historical unsupported port argument is
not evidence that the requested port was contacted.

The `evidence-v9` contract separates MQTT-over-WebSocket transport exposure from
application access: an observed WebSocket upgrade can support `network_exposure`,
but cannot confirm anonymous MQTT access or message disclosure. The current HTTP
tools do not capture MQTT exchanges over WebSocket, and `mqtt_listen` uses TCP;
without suitable application evidence these claims remain inconclusive. The
same rule applies in full and compact profiles. Historical `evidence-v8` scores
remain historical and are not silently reclassified or pooled with the new
contract; precision/recall/F1 formulas are unchanged.

The `evidence-v10` contract additionally binds MQTT wildcard observations to the
actual message topics. New listener calls use Mosquitto's escaped JSON output
(`-F %j`); the execution attestation records `output_format: mosquitto-json-v1`.
The raw stdout remains unchanged in the ledger. Only messages covered by both
the subscription and the claimed topic can support that claim, and disclosure
checks inspect their payloads, not unrelated messages or topic names. Target,
port, references and the MQTT/TCP versus WebSocket boundary still apply.
Historical unframed `-v` output is not sufficient to widen an exact subscription
match to another claimed topic: payload newlines make such attribution ambiguous.
Older scores remain distinguishable by their evidence contract; this change
does not rewrite historical runs or group duplicate findings.

New Phase 6 outputs record `phase6_report_contract: report-v2`. The report
distinguishes Phase 4-supported declarations from accepted benchmark proofs,
ground-truth positives, and code execution. Its evidence column uses the
Phase 4 observation and explicit tool references; reference lookup is labelled
as traceability, not semantic proof validation. Severity totals and priority
indices count declarations, not unique vulnerabilities or benchmark scores.
`06_report_groups.json` preserves the IDs and input positions of possible
duplicates for review only; it never changes the verification queue or VP/FP/FN.
A provider completion ending with `length` leaves an explicit
`partial:memo_truncated` report, with no promoted analyst note. Source evidence
and measured consumption are preserved. Historical reports are not rewritten.

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
