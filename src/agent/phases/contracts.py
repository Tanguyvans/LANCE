"""Structured phase outcomes; adapters retain the existing public statuses."""
from dataclasses import dataclass, field
from enum import StrEnum


class PhaseStatus(StrEnum):
    COMPLETED = "completed"
    WORKER_ERRORS = "executed_with_worker_errors"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class PhaseConsumption:
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    turns: int = 0


@dataclass(frozen=True)
class PhaseResult:
    status: PhaseStatus
    artifacts: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()
    reason: str | None = None
    consumption: PhaseConsumption = field(default_factory=PhaseConsumption)

    @property
    def legacy_status(self) -> str:
        return f"{self.status.value}:{self.reason}" if self.reason else self.status.value
