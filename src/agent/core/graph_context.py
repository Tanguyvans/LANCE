"""Run-owned graph state and scoped access for existing graph tools."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, fields
from functools import wraps
from typing import Any


@dataclass
class GraphContext:
    backend: Any = None
    infra: Any = None
    cve_reports: Any = None
    risk_scores: Any = None
    attack_report: Any = None
    scenario_topology: dict | None = None
    discovery_mode: dict | None = None
    weighted_graph: Any = None
    last_disbalance_report: dict | None = None

    def reset(self) -> None:
        for item in fields(self):
            setattr(self, item.name, None)


# Direct, standalone graph-tool calls retain their existing shared session.
# Pipeline runs always supply a distinct GraphContext; they never use this one.
_standalone_graph = GraphContext()
_active_graph: ContextVar[GraphContext | None] = ContextVar("run_graph", default=None)


def current_graph_context() -> GraphContext:
    return _active_graph.get() or _standalone_graph


@contextmanager
def bind_graph_context(graph: GraphContext):
    token = _active_graph.set(graph)
    try:
        yield graph
    finally:
        _active_graph.reset(token)


def graph_for(owner) -> GraphContext:
    run = getattr(owner, "run_context", None)
    graph = getattr(run, "graph", None)
    if not isinstance(graph, GraphContext):
        graph = getattr(owner, "graph", None)
    return graph if isinstance(graph, GraphContext) else current_graph_context()


def graph_bound(function):
    """Bind an explicit phase/run context, including inside worker threads."""
    @wraps(function)
    def scoped(owner, *args, **kwargs):
        with bind_graph_context(graph_for(owner)):
            return function(owner, *args, **kwargs)
    return scoped


def bind_graph_callable(graph: GraphContext, function):
    """Capture graph ownership when constructing an execution service."""
    @wraps(function)
    def scoped(*args, **kwargs):
        with bind_graph_context(graph):
            return function(*args, **kwargs)
    return scoped
