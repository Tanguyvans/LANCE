"""Resources whose identity belongs to one pipeline run."""
from dataclasses import dataclass, field
from pathlib import Path

from src.agent.core.graph_context import GraphContext


@dataclass(frozen=True)
class RunContext:
    run_dir: Path
    graph: GraphContext = field(default_factory=GraphContext)
