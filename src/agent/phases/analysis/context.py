"""Explicit inputs, boundary operations and intermediate results of phase 3."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Event
import json
import time

from src.agent.cost_tracker import CostTracker
from src.agent.execution_profiles import ExecutionProfile
from src.agent.provider import LLMProvider
from src.agent.registry import AgentConfig
from src.agent.phases.contracts import PhaseStatus


EventCallback = Callable[[dict], None]


@dataclass(frozen=True)
class AnalysisServices:
    """Boundary operations still supplied by the existing run engine."""
    wrap_tool: Callable[..., dict]
    apply_tool_policy: Callable[[list[dict], int], list[dict]]
    save_transaction: Callable[..., list[dict]]
    model_callback: Callable[..., EventCallback]
    discover_surface: Callable[[str, EventCallback | None], list[dict]]
    persist_findings: Callable[[dict, dict], None]
    promoted_deliverable: Callable[..., tuple[bool, str]]
    recover_device: Callable[..., None]
    validate_cves: Callable[..., None]
    check_limits: Callable[[], None]
    validate: Callable[[str], tuple[bool, str]]


@dataclass(frozen=True)
class AnalysisContext:
    run_dir: Path
    config: AgentConfig
    provider: LLMProvider | None
    tracker: CostTracker
    profile: ExecutionProfile
    services: AnalysisServices
    variables: Mapping[str, object]
    compact_local: bool = False
    local_moe: bool = False
    dry_run: bool = False
    sealed: bool = False
    target_network: str | None = None
    stop_event: Event | None = None
    decision_policy: str = "llm"
    benchmark_split: str = "unassigned"
    experiment_scope: str | None = None
    tool_policy: Mapping = field(default_factory=dict)
    analysis_limits: Mapping = field(default_factory=dict)
    max_duration_s: float | None = None
    run_started: float | None = None
    emit: EventCallback | None = None
    started_at: str = field(default_factory=lambda: datetime.now().astimezone().isoformat())
    started_monotonic: float = field(default_factory=time.monotonic)
    tokens_before: tuple[int, int] = (0, 0)
    cost_before: float = 0.0
    turns_before: int = 0


@dataclass(frozen=True)
class ScanResult:
    devices: list[dict]
    observations: dict
    scanner_errors: tuple[str, ...] = ()
    surface_error: str | None = None
    skipped: bool = False


@dataclass(frozen=True)
class DeviceResult:
    device_id: str
    error: str | None = None
    cause: str | None = None


@dataclass(frozen=True)
class DeviceAnalysisResult:
    devices: tuple[DeviceResult, ...] = ()
    worker_count: int = 0


@dataclass(frozen=True)
class AnalysisExecutionResult:
    scan: ScanResult
    analysis: DeviceAnalysisResult

    @property
    def status(self) -> PhaseStatus:
        if self.scan.skipped:
            return PhaseStatus.SKIPPED
        if self.scan.surface_error or any(
            device.error is not None for device in self.analysis.devices
        ):
            return PhaseStatus.WORKER_ERRORS
        # A scanner probe may fail and still leave every device analyzed
        # (redundant observations, retry). Scanner errors stay recorded as
        # information, but only a device left without analysis degrades the
        # phase — including no device at all behind scanner errors.
        analyzed = sum(device.error is None for device in self.analysis.devices)
        if self.scan.scanner_errors and analyzed == 0:
            return PhaseStatus.WORKER_ERRORS
        return PhaseStatus.COMPLETED


def save_execution_status(
    context: AnalysisContext,
    execution: AnalysisExecutionResult | None = None,
    *,
    finished: bool = False,
) -> None:
    """Keep the evaluator's existing status artifact and field names."""
    data = {
        "status": "running", "started_at": context.started_at,
        "devices_total": 0, "devices_analyzed": 0, "devices_failed": [],
        "scanner_errors": [], "worker_count": 0,
    }
    if execution is not None:
        data.update({
            "devices_total": len(execution.scan.devices),
            "devices_analyzed": sum(device.error is None for device in execution.analysis.devices),
            "devices_failed": [
                {"device_id": device.device_id, "error": device.error,
                 **({"cause": device.cause} if device.cause else {})}
                for device in execution.analysis.devices if device.error is not None
            ],
            "scanner_errors": list(execution.scan.scanner_errors),
            "worker_count": execution.analysis.worker_count,
        })
        if execution.scan.surface_error is not None:
            data["surface_error"] = execution.scan.surface_error
        if context.decision_policy == "rules" and not execution.scan.skipped:
            data["decision_policy"] = "rules"
        if finished:
            data["status"] = (
                "completed_with_device_errors"
                if execution.status is PhaseStatus.WORKER_ERRORS else execution.status.value
            )
    if finished:
        data["finished_at"] = datetime.now().astimezone().isoformat()
    (context.run_dir / "03_phase3_status.json").write_text(
        json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8",
    )
