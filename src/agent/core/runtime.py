"""Infrastructure dependencies and tool catalog for the run engine; phase policies live with their phase."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from src.benchmark.scenario_exports import (
    default_export_store,
    resolve_ground_truth_path,
    resolve_scenario_path,
    resolve_topology_path,
)
from src.benchmark.scenario_deployment import GeneratedScenarioDeployment, ManualScenarioDeployment
from src.benchmark.tool_registry import (
    INTERNAL_TOOLS,
    SERVICE_ALIASES,
    available_tool_names,
    tool_policy_for_phase,
)
from src.agent.registry import AGENTS, AgentConfig
from src.agent.exploit_evidence import (
    extract_endpoint_paths as _extract_endpoint_paths,
    has_positive_exploit_evidence as _has_positive_exploit_evidence,
    synthesize_exploit_result as _synthesize_exploit_result,
)
from src.agent.finding_policy import (
    finding_semantic_issue as _finding_semantic_issue,
    normalise_full_finding_semantics as _normalise_full_finding_semantics,
)
from src.agent.report_evidence import phase4_evidence_level as _phase4_evidence_level, is_verified_report_finding as _is_verified_report_finding
from src.agent.execution_profiles import (
    filter_profile_tools,
    phase3_tool_names,
    resolve_execution_profile_for_model,
)
from src.agent.provider import LLMProvider
from src.agent.results import prerequisite_status_allows_artifact, run_status
from src.agent.artifacts import artifact_available
from src.config import (
    BENCHMARK_SUBNET,
    DEFAULT_PORTS,
    DEVICE_DEFAULT_PORTS,
    LOCAL_MOE_REPORT_PHASE_TIMEOUT,
    PHYSICAL_SUBNET,
)
from src.agent.prompt_manager import load_prompt
from src.agent.cost_tracker import CostTracker
from src.agent.tools.graph_tools import (
    GRAPH_TOOLS,
    load_lab_context,
    get_attack_surface,
    get_device_info,
    init_weighted_graph,
    trigger_disbalance_on_exploit,
)
from src.agent.tools.recon_tools import RECON_TOOLS
from src.agent.tools.tool_loader import filter_unavailable_tools
from src.agent.tools.deliverable import (
    DELIVERABLE_TOOLS,
    set_output_dir,
    set_expected_deliverable,
    _extract_json,
)
from src.agent.tools.skill_tools import (
    SKILL_TOOLS,
    cve_search,
    get_skills_metadata,
    set_cve_cache_only,
    set_skill_filter,
)
from src.agent.scanner import run_scanner
from src.agent.validators import VALIDATORS
from src.benchmark.strict_v3 import cve_is_allowed
from src.benchmark.metric_contract import metric_contract_metadata
from src.agent.vuln_taxonomy import canonicalize, exploit_category, is_noise


log = logging.getLogger(__name__)

OUTPUT_DIR = Path("output/agent")

def _resolve_model_provider(model: str) -> str:
    """Resolve a model's provider from the registry, with legacy fallback."""
    try:
        from src.db.database import get_model

        row = get_model(model)
        if row and row.get("provider"):
            return row["provider"]
    except Exception:
        pass

    from src.agent.codex_app_server import is_codex_model
    if is_codex_model(model):
        return "codex"
    return "minimax" if "/" not in model else "openrouter"

def _build_intrusion_tools() -> list[dict]:
    """Extract bounded Phase 5 action tools from RECON_TOOLS."""
    _intrusion_names = {
        "curl_headers", "http_get", "http_request", "mqtt_listen", "ssh_exec",
        "try_credential", "telnet_connect", "ftp_list", "modbus_scan", "tcp_send",
        "udp_send",
    }
    return [t for t in RECON_TOOLS if t["name"] in _intrusion_names]

TOOL_GROUPS: dict[str, list[dict]] = {
    "graph": GRAPH_TOOLS,
    "recon": RECON_TOOLS,
    "deliverable": DELIVERABLE_TOOLS,
    "skill": SKILL_TOOLS,
    "intrusion": _build_intrusion_tools(),
}

# This is a phase safety boundary, not a model-capability profile. Credential
# use and remote execution remain in their dedicated verification/intrusion phases.
RECON_READ_ONLY_TOOL_NAMES = frozenset({
    "arp_scan", "curl_headers", "decode_value", "dig_query", "enum4linux",
    "ftp_list", "gobuster_dir", "http_get", "modbus_scan", "mqtt_listen",
    "nikto_scan", "nmap_discovery", "nmap_scan", "nuclei_scan", "nvd_lookup",
    "openssl_inspect", "searchsploit", "smbclient_list", "sqlmap", "ssh_audit",
    "tls_inspect", "traceroute", "whatweb", "wpscan",
})

# These tools cross the scratch/network boundary or query previous runs.
SEALED_FORBIDDEN_TOOLS = {"python_exec", "search_history"}


def _expand_phase_selection(phases: list[int] | None) -> list[int] | None:
    """Include prerequisites when a user selects a downstream phase.

    A fresh Pipeline always has a fresh run directory, so selecting report or
    intrusion without their upstream artifacts cannot produce a meaningful
    run. Keep explicit partial runs (for example [1] or [3]) intact,
    while making downstream selections self-contained.
    """
    if phases is None:
        return None
    selected = {int(phase) for phase in phases}
    if 6 in selected:
        selected.update({1, 2, 3, 4, 5})
    elif 5 in selected:
        selected.update({1, 2, 3, 4})
    elif 4 in selected:
        selected.update({1, 2, 3})
    return sorted(selected)

def _get_git_commit() -> str | None:
    """Return the short hash of the current git commit, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None

AGENT_DIR = Path(__file__).resolve().parents[1]

REPO_ROOT = AGENT_DIR.parent.parent
