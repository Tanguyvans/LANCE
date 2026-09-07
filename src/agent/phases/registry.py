"""Explicit routing for the six phases; profiles select policy, not a module path."""
from src.agent.phases.graph import run as graph
from src.agent.phases.recon import run as recon
from src.agent.phases.analysis import run as analysis
from src.agent.phases.verification import run as verification
from src.agent.phases.intrusion import run as intrusion
from src.agent.phases.report import run as report


PHASE_MODULES = {
    1: graph,
    2: recon,
    3: analysis,
    4: verification,
    5: intrusion,
    6: report,
}


def run_phase(context, config, stream_callback=None):
    profile = context.execution_profile.name
    if profile not in {"compact", "full"}:
        raise ValueError(f"Unsupported execution profile: {profile}")
    return PHASE_MODULES[config.phase].run(context, config, stream_callback)
