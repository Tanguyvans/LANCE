"""Cost and token tracking per agent phase and total."""
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field

try:
    from src.agent.pricing import get_dynamic_pricing
except ImportError:
    def get_dynamic_pricing(model: str):  # type: ignore
        return None

# Hardcoded pricing fallback (per million tokens, USD)
# Used when the OpenRouter dynamic catalog is unavailable or doesn't contain the model.
PRICING = {
    # Anthropic
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "anthropic/claude-sonnet-4": {"input": 3.0, "output": 15.0},
    "anthropic/claude-sonnet-4.5": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
    # MiniMax (direct + OpenRouter)
    "MiniMax-M2": {"input": 0.20, "output": 1.10},
    "MiniMax-M2.5": {"input": 0.30, "output": 1.20},
    "MiniMax-M2.7": {"input": 0.30, "output": 1.20},
    "minimax/MiniMax-M2": {"input": 0.20, "output": 1.10},
    "minimax/MiniMax-M2.5": {"input": 0.30, "output": 1.20},
    "minimax/minimax-m2": {"input": 0.20, "output": 1.10},
    "minimax/minimax-m2.5": {"input": 0.30, "output": 1.20},
    "minimax/minimax-m2.7": {"input": 0.30, "output": 1.20},
    # GLM (Zhipu)
    "glm-4-flash": {"input": 0.0, "output": 0.0},
    "glm-4-plus": {"input": 0.50, "output": 0.50},
    "glm-4.7": {"input": 0.50, "output": 2.20},
    # Qwen (Alibaba)
    "qwen-plus": {"input": 0.40, "output": 1.20},
    "qwen-turbo": {"input": 0.05, "output": 0.20},
    "qwen/qwen-plus": {"input": 0.40, "output": 1.20},
    "qwen/qwen-max": {"input": 1.60, "output": 6.40},
    "qwen/qwen3-max": {"input": 1.60, "output": 6.40},
    "qwen/qwen-2.5-72b-instruct": {"input": 0.35, "output": 0.40},
    "qwen/qwen3-coder": {"input": 0.20, "output": 0.80},
    # Google Gemini
    "google/gemini-2.0-flash-001": {"input": 0.10, "output": 0.40},
    "google/gemini-2.5-flash": {"input": 0.15, "output": 0.60},
    "google/gemini-2.5-flash-lite": {"input": 0.0, "output": 0.0},
    "google/gemini-2.5-pro-preview": {"input": 1.25, "output": 10.0},
    "google/gemini-3-flash-preview": {"input": 0.50, "output": 3.0},
    # OpenAI
    "openai/gpt-4o": {"input": 2.50, "output": 10.0},
    # Meta
    "meta-llama/llama-3.3-70b-instruct": {"input": 0.06, "output": 0.20},
    # MiniMax via OpenRouter
    "minimax/minimax-m2.5:free": {"input": 0.0, "output": 0.0},
    # DeepSeek
    "deepseek/deepseek-chat-v3-0324": {"input": 0.27, "output": 1.10},
    "deepseek/deepseek-v3.2": {"input": 0.26, "output": 0.38},
    "deepseek/deepseek-v3.2-exp": {"input": 0.26, "output": 0.38},
    "deepseek/deepseek-r1": {"input": 0.50, "output": 2.18},
}
DEFAULT_PRICING = {"input": 1.0, "output": 3.0}
METRICS_SCHEMA_VERSION = 2


def _resolve_pricing(
    model: str, provider: str | None = None
) -> tuple[dict[str, float], str, bool]:
    """Resolve pricing once so a completed run cannot be repriced later."""
    if provider in {"codex", "minimax"}:
        return {"input": 0.0, "output": 0.0}, "subscription", False
    dynamic = get_dynamic_pricing(model)
    if dynamic:
        return dynamic, "dynamic_catalog", False
    if model in PRICING:
        return PRICING[model], "static_catalog", False
    # Keep historical budget behaviour, but label unknown-model cost as estimated.
    return DEFAULT_PRICING, "default_estimate", True


@dataclass
class PhaseUsage:
    agent_name: str
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    turns: int = 0
    duration_s: float = 0.0
    model: str = ""
    input_price_per_million: float | None = None
    output_price_per_million: float | None = None
    pricing_source: str = ""
    cost_is_estimate: bool = False
    format_fallbacks: int = 0
    format_attempts: int = 0
    validation_failures: int = 0
    validation_attempts: int = 0
    validation_successes: int = 0
    tool_errors: int = 0

    def cost_usd(self, model: str = "") -> float:
        if model:
            pricing, _, _ = _resolve_pricing(model)
        elif self.input_price_per_million is not None and self.output_price_per_million is not None:
            pricing = {"input": self.input_price_per_million, "output": self.output_price_per_million}
        else:
            pricing, _, _ = _resolve_pricing(self.model)
        return (
            self.input_tokens * pricing["input"]
            + self.output_tokens * pricing["output"]
        ) / 1_000_000


@dataclass
class CostTracker:
    model: str = ""
    provider: str = ""
    phases: list[PhaseUsage] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _thread_local: threading.local = field(default_factory=threading.local, repr=False)
    _first_phase_start: float | None = field(default=None, repr=False)
    _last_phase_end: float | None = field(default=None, repr=False)

    def start_phase(self, agent_name: str) -> None:
        # Serialize pricing resolution so parallel agents share one catalog snapshot.
        started_at = time.monotonic()
        with self._lock:
            pricing, pricing_source, estimated = _resolve_pricing(
                self.model, self.provider
            )
            if self._first_phase_start is None or started_at < self._first_phase_start:
                self._first_phase_start = started_at
        self._thread_local.current = PhaseUsage(
            agent_name=agent_name, model=self.model,
            input_price_per_million=pricing["input"],
            output_price_per_million=pricing["output"],
            pricing_source=pricing_source, cost_is_estimate=estimated,
        )
        self._thread_local.start_time = started_at

    def record_turn(
        self, input_tokens: int, output_tokens: int, tool_call_count: int = 0
    ) -> None:
        current = getattr(self._thread_local, 'current', None)
        if current is None:
            return
        with self._lock:
            current.input_tokens += input_tokens
            current.output_tokens += output_tokens
            current.tool_calls += tool_call_count
            current.turns += 1

    def record_format_fallback(self) -> None:
        """Record a structured-save attempt that required recovery."""
        self.record_format_attempt(fallback_used=True)

    def record_format_attempt(self, fallback_used: bool = False) -> None:
        current = getattr(self._thread_local, "current", None)
        if current is None:
            return
        with self._lock:
            current.format_attempts += 1
            if fallback_used:
                current.format_fallbacks += 1

    def record_validation_failure(self) -> None:
        """Record a failed validation attempt (legacy call-site helper)."""
        self.record_validation_result(success=False)

    def record_validation_result(self, success: bool) -> None:
        current = getattr(self._thread_local, "current", None)
        if current is None:
            return
        with self._lock:
            current.validation_attempts += 1
            if success:
                current.validation_successes += 1
            else:
                current.validation_failures += 1

    def record_tool_error(self) -> None:
        current = getattr(self._thread_local, 'current', None)
        if current is None:
            return
        with self._lock:
            current.tool_errors += 1

    def end_phase(self) -> PhaseUsage | None:
        current = getattr(self._thread_local, 'current', None)
        start_time = getattr(self._thread_local, 'start_time', 0.0)
        if current is None:
            return None
        ended_at = time.monotonic()
        current.duration_s = ended_at - start_time
        with self._lock:
            self.phases.append(current)
            if self._last_phase_end is None or ended_at > self._last_phase_end:
                self._last_phase_end = ended_at
        usage = current
        self._thread_local.current = None
        return usage

    def total_cost(self) -> float:
        with self._lock:
            return sum(p.cost_usd() for p in self.phases)

    def total_tokens(self) -> tuple[int, int]:
        with self._lock:
            return (
                sum(p.input_tokens for p in self.phases),
                sum(p.output_tokens for p in self.phases),
            )

    def summary(self) -> dict:
        with self._lock:
            in_tok = sum(p.input_tokens for p in self.phases)
            out_tok = sum(p.output_tokens for p in self.phases)
            total_cost = sum(p.cost_usd() for p in self.phases)
            agent_duration = sum(p.duration_s for p in self.phases)
            wall_duration = (
                self._last_phase_end - self._first_phase_start
                if self._first_phase_start is not None and self._last_phase_end is not None
                else 0.0
            )
            return {
                "metrics_schema_version": METRICS_SCHEMA_VERSION,
                "model": self.model,
                "models": list(dict.fromkeys(p.model for p in self.phases if p.model)),
                "total_cost_usd": total_cost,
                "cost_is_estimate": any(p.cost_is_estimate for p in self.phases),
                "total_input_tokens": in_tok,
                "total_output_tokens": out_tok,
                "total_turns": sum(p.turns for p in self.phases),
                "total_tool_calls": sum(p.tool_calls for p in self.phases),
                # Historical total_duration_s is retained as agent-seconds.
                "total_duration_s": round(agent_duration, 1),
                "total_agent_duration_s": round(agent_duration, 1),
                "wall_clock_duration_s": round(wall_duration, 1),
                "total_format_fallbacks": sum(p.format_fallbacks for p in self.phases),
                "total_format_attempts": sum(p.format_attempts for p in self.phases),
                "total_validation_failures": sum(p.validation_failures for p in self.phases),
                "total_validation_attempts": sum(p.validation_attempts for p in self.phases),
                "total_validation_successes": sum(p.validation_successes for p in self.phases),
                "total_tool_errors": sum(p.tool_errors for p in self.phases),
                "phases": [
                    {
                        "agent": p.agent_name,
                        "turns": p.turns,
                        "input_tokens": p.input_tokens,
                        "output_tokens": p.output_tokens,
                        "tool_calls": p.tool_calls,
                        "model": p.model,
                        "cost_usd": p.cost_usd(),
                        "cost_is_estimate": p.cost_is_estimate,
                        "pricing_source": p.pricing_source,
                        "input_price_per_million": p.input_price_per_million,
                        "output_price_per_million": p.output_price_per_million,
                        "duration_s": round(p.duration_s, 1),
                        "format_fallbacks": p.format_fallbacks,
                        "format_attempts": p.format_attempts,
                        "validation_failures": p.validation_failures,
                        "validation_attempts": p.validation_attempts,
                        "validation_successes": p.validation_successes,
                        "tool_errors": p.tool_errors,
                    }
                    for p in self.phases
                ],
            }

    def to_json(self) -> str:
        """Return the cost summary as a JSON string."""
        return json.dumps(self.summary(), indent=2)

    def print_summary(self) -> None:
        print("\n" + "=" * 72)
        print("COST SUMMARY")
        print("=" * 72)
        print(
            f"{'Phase':<22} {'Turns':>6} {'In Tokens':>11} {'Out Tokens':>11} "
            f"{'Cost ($)':>9} {'Duration':>9}"
        )
        print("-" * 72)
        with self._lock:
            phases_copy = list(self.phases)
        for p in phases_copy:
            cost = p.cost_usd()
            issues = []
            if p.format_fallbacks: issues.append(f"FB:{p.format_fallbacks}")
            if p.validation_failures: issues.append(f"VF:{p.validation_failures}")
            if p.tool_errors: issues.append(f"TE:{p.tool_errors}")
            issues_str = " ".join(issues)
            print(
                f"{p.agent_name:<22} {p.turns:>6} {p.input_tokens:>11,} "
                f"{p.output_tokens:>11,} {cost:>9.4f} {p.duration_s:>8.0f}s  {issues_str}"
            )
        print("-" * 72)
        in_tok, out_tok = self.total_tokens()
        total = self.total_cost()
        with self._lock:
            total_turns = sum(p.turns for p in self.phases)
            total_dur = sum(p.duration_s for p in self.phases)
            total_fb = sum(p.format_fallbacks for p in self.phases)
            total_vf = sum(p.validation_failures for p in self.phases)
        
        issues_total = []
        if total_fb: issues_total.append(f"FB:{total_fb}")
        if total_vf: issues_total.append(f"VF:{total_vf}")
        issues_tot_str = " ".join(issues_total)

        print(
            f"{'TOTAL':<22} {total_turns:>6} "
            f"{in_tok:>11,} {out_tok:>11,} {total:>9.4f} {total_dur:>8.0f}s  {issues_tot_str}"
        )
        print("=" * 72)
