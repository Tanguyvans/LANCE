# Phase 3 block recovery after output-budget truncation

Full-mode device analysis (`analyze_device`) can exhaust the provider's
per-response **output (generation) budget** after its exploration tool calls
but before it calls `save_deliverable`. The observable signature is
`finish_reason=length` on the last response(s) with no validated save
receipt, surfacing as `missing_validated_deliverable` for the device. This
means generation was cut short. It does not alone prove whether the
requested output cap, a server cap, or the remaining context capacity was
binding. The recovery addresses producing the analysis in smaller outputs;
it does not claim to measure the remote server's effective capacity.

Observed case: run `2026-09-17_123943` (S2, `qwen3.8:27b`, full,
`phase3_max_tokens=4096`, `phase3_max_turns=10`): `s2-router` and `s2-iot-gw`
made tool calls, then returned two `length` responses each and never saved.

## Recovery

When the full attempt fails **and** the caller-owned completion metadata
reports `finish_reason=length`, Phase 3 runs a bounded block recovery for
that device only (compact mode is untouched):

1. **Derive** per-service blocks from the device topology (default 2
   services per block, at most 4 blocks; overflow merges into the last
   block; devices without services get one general block).
2. **Finalize** each block with a save-only micro-call: no recon tools are
   exposed, so no scan or state-changing action is repeated. The prompt
   carries the block-scoped scanner evidence, the in-scope automated
   findings, and the bounded observations retained from the truncated
   exploration (including target/query arguments). Only the failing block
   is retried (default 2 attempts total), with rejection feedback.
3. **Persist** each accepted block as a sidecar under `03_blocks/`. That
   directory is outside the `03_device_*.json` aggregation glob, so a
   partial block is never mistaken for a completed device.
4. **Assemble** deterministically only after every required block validates:
   automated scanner findings stay canonical and untouched, block findings
   join by id-dedup, severities/types are never rewritten, and the envelope
   is promoted through the same validated save transaction as a normal
   device. Any missing/invalid/conflicting block fails the device as
   incomplete — never as success, never as scanner-only completion.

Block responses ending in `length` are rejected even if their saved JSON
is parseable. Block index, device identity and service/port pairs are checked.
Stop, the device deadline, and the cost budget stay global across the
original attempt and all blocks; every block call uses the same tracker, so
all token usage is counted. These limits are checked before and after calls
and before assembly. A stop/deadline/budget hit aborts further calls
and leaves an explicit `truncated_output:` cause (with a structured
`cause: truncated_output` on the status entry and `device_done` event),
distinct from the generic `missing_validated_deliverable` diagnosis used
when no truncation was observed.

## Configured caps vs unknown remote caps

| Knob | Default | Meaning |
| --- | --- | --- |
| `LANCE_PHASE3_BLOCK_MAX_BLOCKS` | 4 | Max sidecar blocks per device |
| `LANCE_PHASE3_BLOCK_SERVICES_PER_BLOCK` | 2 | Services grouped per block |
| `LANCE_PHASE3_BLOCK_MAX_ATTEMPTS` | 2 | Total attempts for one failing block |
| `LANCE_PHASE3_BLOCK_MAX_TOKENS` | 4096 | Output cap per response during block recovery (same as the initial full analysis) |
| `LANCE_PHASE3_BLOCK_MAX_TURNS` | 4 | Turn cap per block attempt (below the full 10) |

These bound this harness's requests. The remote provider's actual output
cap is unknown from here and is never asserted; repeated truncation
therefore ends in explicit incompleteness with valid blocks preserved, not
in a declared success.

Only the default block-recovery response cap was raised from 2048 to 4096.
The initial analysis, other phases, retry count, shared deadline and run cost
budget are unchanged. An explicit `LANCE_PHASE3_BLOCK_MAX_TOKENS` override still
takes precedence (for example 8192 for a controlled comparison); there is no
automatic escalation. This output allowance does not change the context window
or guarantee that the remote provider can complete every block within it.

## Files

- `src/agent/phases/analysis/block_recovery.py` — derive/scope/validate/
  assemble helpers and cap resolution (no provider calls).
- `src/agent/phases/analysis/run.py` — `_recover_truncated_phase3_device`,
  `_run_phase3_block`, observation retention, `truncated_output` diagnostics.
- `src/agent/prompts/analyze_device_block.txt` — save-only block prompt;
  severity caps share the same include as `analyze_device.txt`.
- `tests/pipeline/test_analysis_block_recovery.py` — mocked end-to-end
  recovery plus helper contracts. All simulation is local; no mock result
  is presented as a real-device success.
