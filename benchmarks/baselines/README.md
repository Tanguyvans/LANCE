# Baseline comparison VM

This folder contains the lightweight contract for comparing external pentest
agents such as CAI and PentGPT against the NATO Smart City IoT benchmarks.

The important rule is: external tools stay isolated on the baseline VM, while
the master VM only orchestrates runs, retrieves JSON, and evaluates results.

## Flow

```text
master VM
  deploys benchmark scenario
  extracts scenario targets
  SSH runs baseline tool per target on baseline VM
  copies raw JSON outputs back
  normalizes to 03_vuln_analysis.json
  evaluates with src.benchmark.evaluator

baseline VM
  contains CAI / PentGPT / dependencies
  has eth1 on the benchmark network
  writes one JSON result per target
```

## Baseline output contract

Each adapter should write JSON to the `{output}` path it receives:

```json
{
  "findings": [
    {
      "ip": "192.168.100.12",
      "type": "default_credentials",
      "severity": "HIGH",
      "details": "SSH accepts admin/admin",
      "evidence": "Successful login",
      "evidence_level": 2,
      "cve_ids": []
    }
  ]
}
```

The normalizer also accepts common aliases such as `host`, `target`,
`category`, `risk`, `proof`, `vulnerabilities`, or `results`.

## Commands

Open the guided terminal interface:

```bash
python3 -m src.baselines dashboard
```

If `rich` is not installed, use the plain fallback:

```bash
python3 -m src.baselines wizard
```

Deploy the isolated baseline VM:

```bash
python3 -m src.baselines deploy-vm
```

Install CAI and replace the placeholder adapter:

```bash
export MINIMAX_API_KEY="..."
python3 -m src.baselines setup-cai \
  --baseline-host root@192.168.88.36
```

For direct MiniMax usage, `setup-cai` writes both `MINIMAX_API_KEY` and the
OpenAI-compatible variables CAI actually reads:

```text
OPENAI_BASE_URL=https://api.minimax.io/v1
OPENAI_API_BASE=https://api.minimax.io/v1
OPENAI_API_KEY=<same MiniMax key>
CAI_MODEL=openai/MiniMax-M2.7
CAI_GUARDRAILS=false
```

The `openai/` prefix is required by CAI's LiteLLM layer to select the
OpenAI-compatible provider; the request still goes directly to MiniMax through
`https://api.minimax.io/v1`.

`CAI_GUARDRAILS=false` is scoped to the isolated baseline VM because the
benchmark prompts are authorized security-assessment prompts against lab
targets; otherwise CAI's prompt-injection guard can block the run before the
agent gets to use its tools.

Update only the CAI adapter scripts without touching the remote `.env` secrets:

```bash
python3 -m src.baselines setup-cai \
  --baseline-host root@192.168.88.36 \
  --preserve-remote-env
```

Override resources without editing YAML:

```bash
python3 -m src.baselines deploy-vm \
  --extra-vars "baseline_memory=4096" \
  --extra-vars "baseline_cores=2"
```

List the targets for a scenario:

```bash
python3 -m src.baselines targets --scenario 3
```

Deploy and prepare a benchmark scenario:

```bash
python3 -m src.baselines deploy-scenario --scenario 3
```

Destroy a benchmark scenario:

```bash
python3 -m src.baselines teardown-scenario --scenario 3
```

Dry-run the CAI baseline from the master VM:

```bash
python3 -m src.baselines run \
  --tool cai \
  --scenario 3 \
  --baseline-host root@192.168.88.184 \
  --dry-run
```

Pilot CAI exactly like the paper plan shortcut:

```bash
python3 -m src.baselines pilot-cai \
  --baseline-host root@192.168.88.184 \
  --dry-run
```

Run for real:

```bash
python3 -m src.baselines run \
  --tool pentgpt \
  --scenario 3 \
  --baseline-host root@192.168.88.184
```

Evaluate the resulting run directory:

```bash
python3 -m src.baselines compare output/baselines/pentgpt/S3_YYYY-mm-dd_HHMMSS
```

## Adapter scripts on the baseline VM

The Ansible playbook creates placeholders:

```text
/opt/baseline-tools/adapters/cai_run.sh
/opt/baseline-tools/adapters/pentgpt_run.sh
```

`setup-cai` automatically replaces `cai_run.sh` with a CAI-backed adapter. For
other tools, replace their script once installed. Keep their CLI stable:

```bash
./adapters/cai_run.sh --target 192.168.100.12 --scenario 3 --output /opt/baseline-tools/results/cai_S3_192.168.100.12.json
```

The CAI adapter defaults to `CAI_RUN_MODE=sdk`, which calls CAI's Python
`Runner.run_sync()` entry point instead of the interactive `cai` TUI. Set
`CAI_RUN_MODE=cli` on the baseline VM only when you explicitly want to reproduce
the interactive CLI baseline; in unattended runs it commonly times out on the
welcome screen without producing parseable findings.
