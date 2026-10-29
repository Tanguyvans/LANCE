"""Run lifecycle shared by every calibration harness.

The governance boundary in ``src/agent/core/executor.py`` reads a fixed set of
attributes from the object it wraps. Each harness rebuilt that object by hand,
so an omission surfaced only when a tool call failed. ``build_run`` declares
the attribute set once, checks it, and refuses to hand back a partial run.

The ``SimpleNamespace`` is deliberate: the harness drives one bounded arm, not
the six-phase pipeline, so it must not drag the pipeline runtime in. What it
must not do is rediscover the required attributes in four places.
"""
from __future__ import annotations

from types import SimpleNamespace
import threading
import time
from typing import Any

from src.agent.cost_tracker import CostTracker

# Attributes the governance boundary reads; see src/agent/core/executor.py.
REQUIRED_ATTRIBUTES = (
    "run_dir",
    "max_tool_calls",
    "max_duration_s",
    "max_turns",
    "_artifact_log_lock",
    "_evidence_integrity_failed",
    "_tool_call_count",
    "_run_started",
    "_execution_limit_reason",
    "experiment_scope",
    "context",
    "decision_policy",
    "tracker",
)
# Sub-keys of ``context`` the scope check depends on.
REQUIRED_CONTEXT_KEYS = ("target_subnet",)


def build_run(*, directory, scope, phase, policy, args,
              network: str = "127.0.0.1/32") -> SimpleNamespace:
    """Build one bounded arm and refuse an incomplete governance surface.

    ``args`` supplies the budgets (``max_tool_calls``, ``max_duration_s``,
    ``max_turns``, ``max_cost_usd``) and, for an LLM arm, the model and
    provider. A deterministic arm never claims a cost.
    """
    directory.mkdir(parents=True, exist_ok=True)
    # An explicitly opened empty collection is distinct from missing evidence
    # when the provider fails before the first tool operation.
    (directory / "tool_calls.jsonl").touch(exist_ok=False)
    llm = policy == "llm"
    run = SimpleNamespace(
        run_dir=directory,
        max_tool_calls=args.max_tool_calls,
        max_duration_s=args.max_duration_s,
        max_turns=args.max_turns,
        _artifact_log_lock=threading.Lock(),
        # The evidence latch: a lost evidence write must stay visible.
        _evidence_integrity_failed=False,
        _tool_call_count=0,
        _run_started=time.monotonic(),
        _execution_limit_reason=None,
        experiment_scope=scope,
        context={"target_subnet": network},
        decision_policy=policy,
        tracker=CostTracker(
            model=args.model if llm else "",
            provider=args.provider if llm else "",
            max_cost_usd=args.max_cost_usd,
            execution_metrics=True,
        ),
    )
    missing = [name for name in REQUIRED_ATTRIBUTES if not hasattr(run, name)]
    if missing:
        raise RuntimeError(f"Incomplete harness run: missing {', '.join(missing)}")
    absent = [key for key in REQUIRED_CONTEXT_KEYS if key not in run.context]
    if absent:
        raise RuntimeError(f"Incomplete harness context: missing {', '.join(absent)}")
    run.tracker.start_run()
    run.tracker.start_phase(phase)
    return run


def new_run(directory, policy, args, *, scope: str, phase: str | None = None,
            network: str = "127.0.0.1/32") -> SimpleNamespace:
    """Positional-compatible wrapper kept for the existing harness call sites."""
    return build_run(directory=directory, scope=scope, phase=phase or scope,
                     policy=policy, args=args, network=network)


def require_attributes(run: Any) -> None:
    """Assert a run exposes the governance surface before it wraps a tool."""
    missing = [name for name in REQUIRED_ATTRIBUTES if not hasattr(run, name)]
    if missing:
        raise RuntimeError(f"Run is missing {', '.join(missing)}")
