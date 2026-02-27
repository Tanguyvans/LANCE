"""Cost and token tracking per agent phase and total."""
from __future__ import annotations

import time
from dataclasses import dataclass, field

# Pricing per million tokens (USD)
PRICING = {
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "anthropic/claude-sonnet-4": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
}
DEFAULT_PRICING = {"input": 3.0, "output": 15.0}


@dataclass
class PhaseUsage:
    agent_name: str
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    turns: int = 0
    duration_s: float = 0.0
    model: str = ""

    def cost_usd(self, model: str = "") -> float:
        pricing = PRICING.get(model or self.model, DEFAULT_PRICING)
        return (
            self.input_tokens * pricing["input"]
            + self.output_tokens * pricing["output"]
        ) / 1_000_000


@dataclass
class CostTracker:
    model: str = ""
    phases: list[PhaseUsage] = field(default_factory=list)
    _current: PhaseUsage | None = field(default=None, repr=False)
    _start_time: float = field(default=0.0, repr=False)

    def start_phase(self, agent_name: str) -> None:
        self._current = PhaseUsage(agent_name=agent_name, model=self.model)
        self._start_time = time.monotonic()

    def record_turn(
        self, input_tokens: int, output_tokens: int, tool_call_count: int = 0
    ) -> None:
        if self._current is None:
            return
        self._current.input_tokens += input_tokens
        self._current.output_tokens += output_tokens
        self._current.tool_calls += tool_call_count
        self._current.turns += 1

    def end_phase(self) -> PhaseUsage | None:
        if self._current is None:
            return None
        self._current.duration_s = time.monotonic() - self._start_time
        self.phases.append(self._current)
        usage = self._current
        self._current = None
        return usage

    def total_cost(self) -> float:
        return sum(p.cost_usd(self.model) for p in self.phases)

    def total_tokens(self) -> tuple[int, int]:
        return (
            sum(p.input_tokens for p in self.phases),
            sum(p.output_tokens for p in self.phases),
        )

    def summary(self) -> dict:
        in_tok, out_tok = self.total_tokens()
        return {
            "model": self.model,
            "total_cost_usd": round(self.total_cost(), 4),
            "total_input_tokens": in_tok,
            "total_output_tokens": out_tok,
            "total_turns": sum(p.turns for p in self.phases),
            "total_duration_s": round(sum(p.duration_s for p in self.phases), 1),
            "phases": [
                {
                    "agent": p.agent_name,
                    "turns": p.turns,
                    "input_tokens": p.input_tokens,
                    "output_tokens": p.output_tokens,
                    "tool_calls": p.tool_calls,
                    "cost_usd": round(p.cost_usd(self.model), 4),
                    "duration_s": round(p.duration_s, 1),
                }
                for p in self.phases
            ],
        }

    def print_summary(self) -> None:
        print("\n" + "=" * 72)
        print("COST SUMMARY")
        print("=" * 72)
        print(
            f"{'Phase':<22} {'Turns':>6} {'In Tokens':>11} {'Out Tokens':>11} "
            f"{'Cost ($)':>9} {'Duration':>9}"
        )
        print("-" * 72)
        for p in self.phases:
            cost = p.cost_usd(self.model)
            print(
                f"{p.agent_name:<22} {p.turns:>6} {p.input_tokens:>11,} "
                f"{p.output_tokens:>11,} {cost:>9.4f} {p.duration_s:>8.0f}s"
            )
        print("-" * 72)
        in_tok, out_tok = self.total_tokens()
        total = self.total_cost()
        total_dur = sum(p.duration_s for p in self.phases)
        print(
            f"{'TOTAL':<22} {sum(p.turns for p in self.phases):>6} "
            f"{in_tok:>11,} {out_tok:>11,} {total:>9.4f} {total_dur:>8.0f}s"
        )
        print("=" * 72)
