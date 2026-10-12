"""Explicit phase inputs and execution services; no Pipeline dependency."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from types import MappingProxyType
from typing import TYPE_CHECKING

from src.agent.core.graph_context import bind_graph_callable, graph_for
from src.agent.core.run_context import RunContext

if TYPE_CHECKING:
    from src.agent.cost_tracker import CostTracker
    from src.agent.execution_profiles import ExecutionProfile
    from src.agent.phases.analysis.context import AnalysisContext
    from src.agent.provider import LLMProvider
    from src.agent.registry import AgentConfig

EventCallback = Callable[[dict], None]


@dataclass(frozen=True)
class PhaseServices:
    execute: Callable[[AgentConfig, EventCallback | None], str]
    record_analysis_status: Callable[[str | None], None]


@dataclass(frozen=True)
class PhaseContext:
    run_context: RunContext
    config: AgentConfig
    execution_profile: ExecutionProfile
    provider: LLMProvider | None
    tracker: CostTracker | None
    variables: Mapping[str, object]
    stop_event: Event | None
    decision_policy: str
    services: PhaseServices
    emit: EventCallback | None = None
    analysis: AnalysisContext | None = None

    @property
    def run_dir(self) -> Path:
        return self.run_context.run_dir


def phase_context(run, config=None, stream_callback=None) -> PhaseContext:
    """Adapt the public engine once; phase implementations receive capabilities."""
    if isinstance(run, PhaseContext):
        if config is not None and config != run.config:
            raise ValueError("Phase context belongs to a different configuration")
        return run
    graph = graph_for(run)
    resources = getattr(run, "run_context", None)
    if not isinstance(resources, RunContext):
        resources = RunContext(getattr(run, "run_dir", Path(".")), graph)
    execute = run._run_local_report_phase if config.phase == 6 else run._run_agent
    analysis = None
    policy = getattr(run, "decision_policy", "llm")
    if config.phase == 3 and (config.deterministic_aggregation or policy == "rules"):
        # Keep the compatibility engine's status reset ahead of context
        # capture, including when capture itself raises.
        run._phase3_execution_status = None
        from src.agent.phases.analysis.run import build_context
        analysis = bind_graph_callable(graph, build_context)(run, config, stream_callback)
    return PhaseContext(
        run_context=resources, config=config,
        execution_profile=run.execution_profile,
        provider=getattr(run, "provider", None), tracker=getattr(run, "tracker", None),
        variables=MappingProxyType(deepcopy(getattr(run, "context", {}))),
        stop_event=getattr(run, "_stop_event", None), decision_policy=policy,
        services=PhaseServices(
            execute=bind_graph_callable(graph, execute),
            record_analysis_status=lambda status: setattr(run, "_phase3_execution_status", status),
        ),
        emit=stream_callback, analysis=analysis,
    )
