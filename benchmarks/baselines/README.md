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

or, if you prefer a tiny launcher script:

```bash
./scripts/baselines-dashboard.sh
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
python3 -m src.baselines deploy-scenario --scenario 3 --verify
```

`deploy-scenario` already deploys, injects vulnerabilities, and populates the
services by default. Add `--verify` when you want the command to block unless
the critical vulnerabilities are really present:

```text
03_deploy_scenario.yml -> 04_inject_vulns.yml -> 05_populate_services.yml -> 06_verify.yml
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

Run several targets in parallel when a tool is too slow:

```bash
python3 -m src.baselines run \
  --tool cai \
  --scenario 3 \
  --baseline-host root@192.168.88.36 \
  --jobs 2
```

Start with `--jobs 2` for CAI. Higher values can be faster, but they also
increase API concurrency and load on the baseline VM.

Run the three comparison baselines sequentially for the same scenario:

```bash
python3 -m src.baselines suite \
  --scenario 3 \
  --baseline-host root@192.168.88.36 \
  --jobs 2
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

To run our agent on external suites from the same dashboard, choose
`Run our agent on external benchmark suite`. The TUI lets you:

1. choose `Vulhub`, `AutoPenBench`, `XBOW`, or `AI-Pentest`;
2. sync this project to the baseline VM;
3. install/check Docker and the Python venv on the baseline VM;
4. clone Vulhub / AutoPenBench on the baseline VM if the repo is missing;
5. filter cases by name/CVE/category;
6. run one selected case or all filtered cases as a batch;
7. run in dry-run mode first, then real mode;
8. copy the saved result directory back under `output/external_benchmarks/`.

For batch runs, start with a filter and a small limit first. Vulhub contains many
Compose environments, so a full unfiltered real run can take hours and pull a
large number of Docker images. Batch summaries are written to:

```text
output/external_benchmarks/batches/<suite>_<timestamp>_summary.json
```

## External benchmark suites

The external harness lets us run our agent on benchmarks used by the tools we
compare against:

- `xbow`: XBOW Validation Benchmarks used by PentestGPT.
- `autopenbench`: AutoPenBench used by VulnBot and referenced by CAIBench.
- `vulhub`: Docker Compose vulnerable labs used by many pentest agents.
- `ai-pentest`: AI-Pentest-Benchmark metadata for VulnHub VM targets.

The TUI can clone Vulhub / AutoPenBench on the baseline VM for you. The default
remote paths are:

```text
/opt/nato-smartcity-iot                 # synced project copy used by src.agent_external
/opt/external-benchmarks/vulhub         # remote Vulhub checkout
/opt/external-benchmarks/auto-pen-bench # remote AutoPenBench checkout
/opt/baseline-tools/external-results    # remote run artifacts before copy-back
/opt/baseline-tools/external-jobs       # detached tmux job state/logs
```

Inspect a remote suite from CLI:

```bash
python3 -m src.baselines external list \
  --suite vulhub \
  --repo /opt/external-benchmarks/vulhub \
  --remote-host root@192.168.88.36

python3 -m src.baselines external list \
  --suite autopenbench \
  --repo /opt/external-benchmarks/auto-pen-bench \
  --remote-host root@192.168.88.36
```

Write a manifest for traceability:

```bash
python3 -m src.baselines external manifest \
  --suite vulhub \
  --repo ../vulhub \
  --output output/external_benchmarks/vulhub_manifest.json
```

Dry-run a challenge to see the Docker and agent commands that will execute:

```bash
python3 -m src.baselines external run \
  --suite vulhub \
  --repo /opt/external-benchmarks/vulhub \
  --case struts2/s2-045 \
  --remote-host root@192.168.88.36 \
  --agent-command 'python -m src.agent_external --target {target_or_url} --output-dir {output_dir} --provider minimax' \
  --dry-run
```

Run an AutoPenBench task. The harness reads `data/games.json`, keeps the
official expected flag, and exposes the task text to the agent command:

```bash
python3 -m src.baselines external run \
  --suite autopenbench \
  --repo /opt/external-benchmarks/auto-pen-bench \
  --case in-vitro_recon_target1 \
  --remote-host root@192.168.88.36 \
  --agent-command 'python -m src.agent_external --target {target_or_url} --hint "{task}" --output-dir {output_dir} --provider minimax'
```

The command template receives `{suite}`, `{case_id}`, `{target_url}`,
`{target_or_url}`, `{target_host}`, `{target_port}`, `{target_name}`, `{task}`,
`{vulnerability}`, `{output_dir}`, and `{flag}`.
For XBOW and AutoPenBench, the harness builds the benchmark with Docker Compose.
For Vulhub, it starts the compose stack directly because most cases use
pre-built images. Each run stores `planned.json`, `agent_stdout.txt`,
`agent_stderr.txt`, and `result.json`. Success is flag-based when a flag is
known; Vulhub cases usually need either `--flag` or manual inspection of the
saved output because upstream does not define one universal flag format.
The AI-Pentest-Benchmark path is recorded as manual because those targets are
VulnHub/VM based rather than Docker-compose challenges.

Run an installed comparison adapter on an external benchmark case:

```bash
python3 -m src.baselines external run \
  --suite vulhub \
  --repo /opt/external-benchmarks/vulhub \
  --case redis/CVE-2022-0543 \
  --baseline-tool cai \
  --baseline-max-turns 40 \
  --docker-cleanup
```

`--baseline-tool` accepts `cai`, `pentgpt`, or `vulnbot`. It calls the matching
adapter under `/opt/baseline-tools/adapters`, writes the raw adapter JSON into
the external run directory, and includes that JSON in `agent_stdout.txt` for
the existing proof/report path. The adapters must already be installed and
configured, for example with:

```bash
export MINIMAX_API_KEY="..."
python3 -m src.baselines setup-baselines \
  --baseline-host root@192.168.88.36
```

### Detached long runs on the baseline VM

For paper-scale batches, prefer detached jobs. Your local machine only starts
the job; after that, the VM owns the process, logs, state, Docker containers,
and outputs. You can close your terminal or disconnect SSH.

Start one or more cases in a remote tmux session:

```bash
python3 -m src.baselines external start-detached \
  --remote-host root@192.168.88.36 \
  --suite vulhub \
  --repo /opt/external-benchmarks/vulhub \
  --case 1panel/CVE-2024-39907
```

You can pass `--case` multiple times for a batch. The default command uses
`src.agent_external`, MiniMax, and the fair `context_policy=fair_network_only`
prompt. Control the job from your PC without re-running anything locally:

```bash
python3 -m src.baselines external jobs --remote-host root@192.168.88.36
python3 -m src.baselines external status --remote-host root@192.168.88.36 --job-id <job_id>
python3 -m src.baselines external logs --remote-host root@192.168.88.36 --job-id <job_id> --tail 100
python3 -m src.baselines external attach --remote-host root@192.168.88.36 --job-id <job_id>
python3 -m src.baselines external stop --remote-host root@192.168.88.36 --job-id <job_id>
python3 -m src.baselines external fetch --remote-host root@192.168.88.36 --job-id <job_id>
```

Remote files are written under:

```text
/opt/baseline-tools/external-jobs/<job_id>/job.json
/opt/baseline-tools/external-jobs/<job_id>/status.json
/opt/baseline-tools/external-jobs/<job_id>/summary.json
/opt/baseline-tools/external-jobs/<job_id>/job.log
```

`fetch` copies the job folder under `output/external_benchmarks/jobs/<job_id>`
and copies any completed run directories from
`/opt/baseline-tools/external-results`.

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
