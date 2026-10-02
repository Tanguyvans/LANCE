"""Rules policy phase entry points; lifecycle and validators stay in Pipeline."""
from src.agent.phases.verification.rules import verify


def run_phase(run, config, stream_callback=None):
    if config.phase not in {3, 4}:
        raise ValueError("Rules policy supports analysis and verification only")
    if config.phase == 3:
        from src.agent.phases.analysis.run import run as analyze
        return analyze(run, config, stream_callback).legacy_status
    if stream_callback:
        stream_callback({"type": "phase_start", "phase": config.phase, "name": config.name, "deliverable": config.deliverable_file})
    verify(run, config, stream_callback)
    status = run._phase4_execution_status
    run.tracker.start_phase(f"rules_validate_{config.phase}")
    try:
        valid, message = run._validator(config.validator)(config.deliverable_file)
        run.tracker.record_validation_result(valid)
    finally:
        run.tracker.end_phase()
    if not valid:
        status = f"failed:{message}"
    if stream_callback:
        stream_callback({"type": "phase_done", "phase": config.phase, "name": config.name, "status": status, "deliverable": config.deliverable_file, "turns": 0, "cost_usd": 0})
    return status
