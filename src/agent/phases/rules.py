"""Rules policy phase entry points; lifecycle and validators stay in Pipeline."""
from src.agent.phases.verification.rules import verify
from src.agent.core import runtime


def run_phase(run, config, stream_callback=None):
    if config.phase not in {3, 4}:
        raise ValueError("Rules policy supports analysis and verification only")
    runtime.set_skill_filter(config.skill_filter.get("tags") if config.skill_filter else None)
    if stream_callback:
        stream_callback({"type": "phase_start", "phase": config.phase, "name": config.name, "deliverable": config.deliverable_file})
    if config.phase == 3:
        run.tracker.start_phase("rules_analysis")
        try:
            run._run_phase3(config, stream_callback)
            run._aggregate_device_vulns(config, stream_callback)
        finally:
            run.tracker.end_phase()
        status = getattr(run, "_phase3_execution_status", None) or "completed"
    else:
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
