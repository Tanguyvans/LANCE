# Real CAI and VulnBot campaign adapters

The paper comparison runs each upstream harness once against the complete
scenario CIDR. It never derives target IPs from ground truth and never runs the
tools device by device.

Configure one command template on each isolated worker:

```bash
export CAI_BENCHMARK_COMMAND='/opt/adapters/cai_real --scope {scope} --scenario {scenario} --credentials {credentials_file} --model {model} --max-turns {max_turns} --output {output} --trace {trace}'
export VULNBOT_BENCHMARK_COMMAND='/opt/adapters/vulnbot_real --scope {scope} --scenario {scenario} --credentials {credentials_file} --model {model} --max-turns {max_turns} --output {output} --trace {trace}'
```

The wrapper must invoke the real upstream project and write a JSON object with
`findings` and, when available, native `tool_calls`. Missing native traces are
not reconstructed: Detection F1 remains measurable, but Verified F1 receives no
credit without target-derived provenance.

Dry-run the contract without attacking anything:

```bash
python3 -m src.baselines run-local --tool cai --scenario 20 --mode blind \
  --command-template '/bin/true {output}' --dry-run
```

The actual lab installation remains outside this repository. The campaign must
stay `draft-not-authorized` until the real VulnBot smoke test passes.
