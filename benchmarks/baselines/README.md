# Baseline comparison VM

This folder contains the lightweight contract for comparing external pentest
agents such as CAI, PentestGPT, and VulnBot against the NATO Smart City IoT
benchmarks.

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
  contains CAI / PentestGPT / VulnBot adapters / dependencies
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

Install all supported baseline adapters:

```bash
export MINIMAX_API_KEY="..."
python3 -m src.baselines setup-baselines \
  --baseline-host root@192.168.88.36
```

This deploys:

```text
/opt/baseline-tools/adapters/cai_run.sh
/opt/baseline-tools/adapters/pentgpt_run.sh
/opt/baseline-tools/adapters/vulnbot_run.sh
```

Update only the adapter scripts without touching the remote `.env` secrets:

```bash
python3 -m src.baselines setup-baselines \
  --baseline-host root@192.168.88.36 \
  --preserve-remote-env
```

CAI uses its SDK by default. PentestGPT and VulnBot use benchmark-compatible
non-interactive adapters by default: they run bounded recon from the isolated VM,
send the evidence to MiniMax through the OpenAI-compatible API, and emit the same
per-IP JSON contract as CAI. To plug in upstream tool installs later, set
`PENTGPT_RUN_MODE=external` or `VULNBOT_RUN_MODE=external` on the baseline VM and
provide `PENTGPT_COMMAND` / `VULNBOT_COMMAND` templates that write the requested
`{output}` file.

Install only CAI and replace only the CAI adapter:

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

`deploy-scenario` already runs the full preparation chain:

```text
03_deploy_scenario.yml -> 04_inject_vulns.yml -> 05_populate_services.yml
```

If the scenario is already deployed and you only want to re-inject the
vulnerabilities:

```bash
python3 -m src.baselines inject-vulns \
  --scenario 3 \
  --populate \
  --verify
```

For a faster reset back to the vulnerable benchmark state:

```bash
python3 -m src.baselines reset-scenario \
  --scenario 3 \
  --verify
```

Destroy a benchmark scenario:

```bash
python3 -m src.baselines teardown-scenario --scenario 3
```

Switch from one deployed scenario to another in one command:

```bash
python3 -m src.baselines switch-scenario \
  --current-scenario 1 \
  --next-scenario 2
```

This runs the safe scenario handoff:

```text
99_teardown.yml -> 03_deploy_scenario.yml -> 04_inject_vulns.yml -> 05_populate_services.yml -> 06_verify.yml
```

Dry-run a baseline from the master VM:

```bash
python3 -m src.baselines run \
  --tool pentgpt \
  --scenario 3 \
  --baseline-host root@192.168.88.36 \
  --dry-run
```

Pilot CAI exactly like the paper plan shortcut:

```bash
python3 -m src.baselines pilot-cai \
  --baseline-host root@192.168.88.36 \
  --dry-run
```

Run for real:

```bash
python3 -m src.baselines run \
  --tool pentgpt \
  --scenario 3 \
  --baseline-host root@192.168.88.36
```

Run the three comparison baselines sequentially for the same scenario:

```bash
python3 -m src.baselines suite \
  --scenario 3 \
  --baseline-host root@192.168.88.36
```

Before the suite starts, the CLI refreshes the real adapter wrappers on the
baseline VM without touching the remote `.env` secrets. This protects against
`deploy_baseline_vm.yml` recreating placeholder scripts. To skip that refresh:

```bash
python3 -m src.baselines suite \
  --scenario 3 \
  --baseline-host root@192.168.88.36 \
  --no-refresh-adapters
```

The suite writes a timestamped folder so previous runs are not overwritten:

```text
output/baselines/suites/scenario_3_YYYYmmdd_HHMMSS/
  suite_summary.json
  cai/scenario_3/A/
  pentgpt/scenario_3/A/
  vulnbot/scenario_3/A/
```

Each tool run contains:

```text
raw/                 # JSON returned by the remote adapter for each target
logs/                # raw logs copied back from the baseline VM
03_vuln_analysis.json
04_exploitation.json
evaluator_score.json
metadata.json
```

Evaluate the resulting run directory:

```bash
python3 -m src.baselines compare output/baselines/pentgpt/scenario_3/A
```

The terminal dashboard exposes the same workflow with arrow-key selection:

```bash
python3 -m src.baselines dashboard
```

Use `Configure` to choose `cai`, `pentgpt`, or `vulnbot`, then `Run selected
baseline with live remote status`.

To run all three tools from the dashboard, choose `Run CAI + PentestGPT +
VulnBot suite`.

## External benchmark suites

The external harness lets us run our agent on benchmarks used by the tools we
compare against:

- `xbow`: XBOW Validation Benchmarks used by PentestGPT.
- `autopenbench`: AutoPenBench used by VulnBot and referenced by CAIBench.
- `ai-pentest`: AI-Pentest-Benchmark metadata for VulnHub VM targets.

Clone the upstream benchmark outside this repository, then inspect it:

```bash
python3 -m src.baselines external list \
  --suite xbow \
  --repo ../validation-benchmarks
```

Write a manifest for traceability:

```bash
python3 -m src.baselines external manifest \
  --suite xbow \
  --repo ../validation-benchmarks \
  --output output/external_benchmarks/xbow_manifest.json
```

Dry-run a challenge to see the Docker and agent commands that will execute:

```bash
python3 -m src.baselines external run \
  --suite xbow \
  --repo ../validation-benchmarks \
  --case XBEN-001-24 \
  --agent-command 'python3 -m src.agent_external --target {target_url} --output-dir {output_dir} --provider minimax' \
  --dry-run
```

The command template receives `{suite}`, `{case_id}`, `{target_url}`,
`{output_dir}`, and `{flag}`. For XBOW and AutoPenBench, the harness builds and
starts the benchmark with Docker Compose, runs the command, stores stdout/stderr,
and marks success if the generated flag appears in the agent output. The
AI-Pentest-Benchmark path is recorded as manual because those targets are
VulnHub/VM based rather than Docker-compose challenges.

## Adapter scripts on the baseline VM

The Ansible playbook creates placeholders:

```text
/opt/baseline-tools/adapters/cai_run.sh
/opt/baseline-tools/adapters/pentgpt_run.sh
/opt/baseline-tools/adapters/vulnbot_run.sh
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
