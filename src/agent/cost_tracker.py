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
        m = model or self.model
        # Try dynamic pricing from OpenRouter first (up to date), then hardcoded fallback
        pricing = get_dynamic_pricing(m) or PRICING.get(m, DEFAULT_PRICING)
        return (
            self.input_tokens * pricing["input"]
            + self.output_tokens * pricing["output"]
        ) / 1_000_000


@dataclass
class CostTracker:
    model: str = ""
    phases: list[PhaseUsage] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _thread_local: threading.local = field(default_factory=threading.local, repr=False)

    def start_phase(self, agent_name: str) -> None:
        self._thread_local.current = PhaseUsage(agent_name=agent_name, model=self.model)
        self._thread_local.start_time = time.monotonic()

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

    def end_phase(self) -> PhaseUsage | None:
        current = getattr(self._thread_local, 'current', None)
        start_time = getattr(self._thread_local, 'start_time', 0.0)
        if current is None:
            return None
        current.duration_s = time.monotonic() - start_time
        with self._lock:
            self.phases.append(current)
        usage = current
        self._thread_local.current = None
        return usage

    def total_cost(self) -> float:
        with self._lock:
            return sum(p.cost_usd(self.model) for p in self.phases)

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
            total_cost = sum(p.cost_usd(self.model) for p in self.phases)
            return {
                "model": self.model,
                "total_cost_usd": round(total_cost, 4),
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
            cost = p.cost_usd(self.model)
            print(
                f"{p.agent_name:<22} {p.turns:>6} {p.input_tokens:>11,} "
                f"{p.output_tokens:>11,} {cost:>9.4f} {p.duration_s:>8.0f}s"
            )
        print("-" * 72)
        in_tok, out_tok = self.total_tokens()
        total = self.total_cost()
        with self._lock:
            total_turns = sum(p.turns for p in self.phases)
            total_dur = sum(p.duration_s for p in self.phases)
        print(
            f"{'TOTAL':<22} {total_turns:>6} "
            f"{in_tok:>11,} {out_tok:>11,} {total:>9.4f} {total_dur:>8.0f}s"
        )
        print("=" * 72)
