# Phase 1 graph recovery after output-budget truncation

Full-profile graph analysis (`graph_analysis`) can exhaust the provider's
per-response **output (generation) budget** after its graph-tool calls but
before it calls `save_deliverable`. The observable signature is
`finish_reason=length` on the last response with no validated save receipt,
surfacing as a missing `01_graph_analysis.md`. This means generation was
cut short. It does not alone prove whether the requested output cap, a
server cap, or the remaining context capacity was binding. The recovery
addresses producing the synthesis in a smaller output; it does not claim
to measure the remote server's effective capacity.

Observed case: run `2026-09-17_154552` (`qwen3.8:27b`, full): Phase 1 made
its graph calls, then returned two `length` responses and never saved.

## Recovery

When the full Phase 1 attempt fails **and** the caller-owned completion
metadata reports `finish_reason=length`, the runner makes a bounded
save-only recovery attempt (compact mode is untouched):

1. **Reuse** the existing graph observations: the deterministic projection
   of `tool_calls.jsonl` (also persisted in `01_graph_evidence.json`) is
   the only evidence source. No laboratory internals are read and no
   exploration call is replayed; the recovery tool surface is
   `save_deliverable` only.
2. **Gate** on evidence: without declared nodes, attack-surface facts, or
   full device coverage, recovery refuses instead of synthesizing device
   facts.
3. **Synthesize** short: the prompt carries the factual ledger (counts,
   per-device rows, evidence refs) and requires the 7 template sections
   with full device coverage. Anything absent from the ledger must be
   marked `Not pre-computed` / `unavailable — validate in Phase 2`;
   paths, scores, CVEs, and findings must never be invented. Everything
   saved is model work; nothing deterministic is injected into the file.
4. **Promote** through the same validated save transaction as a normal
   Phase 1 save (attempt archive, structural validator, device-coverage
   gate, promotion receipt). Additionally, a recovery save must contain
   all 7 template section headers as-is; anything shorter is rejected
   before the transaction with repair feedback. Partial text and
   truncated tool arguments cannot satisfy that boundary.

Length-gated saves apply to the initial full Phase 1 call as well: any
save proposed by a response whose `finish_reason` is `length` is rejected
before the transaction, so it is never archived, promoted, or validated.
The provider records each response's `finish_reason` before executing that
response's tool calls, so the gate always sees the proposing response.

A recovery response ending in `length` is rejected even if its saved
content is parseable. Cost tracking stays global across the original
attempt and the recovery calls; every call uses the same tracker, so all
token usage is counted. A stop aborts recovery with a `stopped` status —
never as truncation and never as success — while budget exhaustion
propagates as `BudgetExceeded` so the run keeps its original cause.
Other failures leave an explicit `truncated_output:` cause, distinct from
the generic missing-file diagnosis used when no truncation was observed.
Success is reported as `completed:recovered`, which counts as completed
for run status while remaining distinguishable in `phase_done`.

## Configured caps vs unknown remote caps

| Knob | Default | Meaning |
| --- | --- | --- |
| `LANCE_PHASE1_RECOVERY_MAX_ATTEMPTS` | 2 | Total save-only chats |
| `LANCE_PHASE1_RECOVERY_MAX_TURNS` | 4 | Turn cap per attempt (below the full 20) |
| `LANCE_PHASE1_RECOVERY_MAX_TOKENS` | 2048 | Output cap per attempt (below the full 4096) |

These bound this harness's requests. The remote provider's actual output
cap is unknown from here and is never asserted; repeated truncation
therefore ends in explicit incompleteness, not in a declared success.
Globally raising budgets or widening the context window was deliberately
not used, and provider behavior and score rules are unchanged.

## Files

- `src/agent/phases/graph/recovery.py` — caps, truncation predicate,
  recovery prompt builder, and the `GraphRecoveryPhase` mixin (save-only
  orchestration, stop/budget guards, promotion receipt check).
- `src/agent/core/runner.py` — captures Phase 1 completion metadata and
  reports `completed:recovered` vs explicit `failed:truncated_output:…`.
- `src/agent/pipeline.py` — mixes `GraphRecoveryPhase` into `Pipeline`.
- `tests/pipeline/test_graph_recovery.py` — mocked end-to-end recovery
  plus prompt/cap contracts. All simulation is local; no mock result is
  presented as a real-lab success.
