"""Deterministic scanning and supplemental evidence for phase 3."""
import json
import logging

from src.agent.core import runtime
from src.agent.core.executor import EvidenceWriteError
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.analysis.context import AnalysisContext, ScanResult
from src.agent.phases.analysis.supplemental import supplement_scans

log = logging.getLogger(__name__)


def scan_phase(context: AnalysisContext) -> ScanResult:
    surface_error = None
    try:
        devices = json.loads(runtime.get_attack_surface())
    except Exception as exc:
        log.exception("Could not load Phase 3 attack surface: %s", exc)
        devices = []
        surface_error = str(exc)
    if isinstance(devices, dict):
        devices = devices.get("nodes", [])

    if context.target_network and not devices and not context.dry_run:
        devices = context.services.discover_surface(context.target_network, context.emit)
        from src.agent.tools.graph_tools import update_discovery_hosts
        update_discovery_hosts(devices)
        runtime.init_weighted_graph()

    if context.dry_run:
        log.info("Dry run: skipping Phase 3a scanner")
        return ScanResult(devices, {}, surface_error=surface_error, skipped=True)

    available, _ = runtime.filter_unavailable_tools(runtime.RECON_TOOLS)
    tools = [
        context.services.wrap_tool(
            tool, phase=3, agent="deterministic_scanner", decision_source="rules",
            config=context.config,
        )
        for tool in context.services.apply_tool_policy(available, 3)
    ]
    scanner_kwargs = {
        "compact": context.compact_local, "tools": tools,
        "max_workers": 1 if context.experiment_scope == "analysis-verification" else 6,
    }
    recon_policy = runtime.tool_policy_for_phase(context.tool_policy, "recon")
    if recon_policy is not None:
        scanner_kwargs["allowed_tool_names"] = recon_policy
    errors = []
    try:
        observations = runtime.run_scanner(
            context.run_dir, devices, context.emit, stop_event=context.stop_event,
            **scanner_kwargs,
        )
    except (BudgetExceeded, EvidenceWriteError):
        raise
    except Exception as exc:
        log.exception("Phase 3 scanner failed globally; preserving per-device fallbacks")
        observations = {}
        errors.append(str(exc))
        for device in devices:
            observations[device.get("id", "")] = {
                "scan_results": {}, "findings": [], "error": str(exc),
            }
            context.services.persist_findings(device, observations)
    errors.extend(
        str(data["error"]) for data in observations.values()
        if isinstance(data, dict) and data.get("error")
    )
    supplement_scans(
        context, devices, observations,
        {tool["name"]: tool["function"] for tool in tools}, errors,
    )
    if context.compact_local:
        context.services.validate_cves(observations, devices, context.emit)
    return ScanResult(devices, observations, tuple(errors), surface_error)
