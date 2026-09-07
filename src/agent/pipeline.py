"""Pipeline lifecycle and phase orchestration; public entry for API, CLI and workers."""
from __future__ import annotations

import json
import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from src.agent.phases.intrusion.compact import CompactIntrusionPhase
from src.agent.core import runtime
from src.agent.phases.registry import run_phase
from src.agent.phases.graph.run import GraphPhase
from src.agent.phases.graph.compact import CompactGraphPhase
from src.agent.phases.recon.run import ReconPhase
from src.agent.phases.recon.compact import CompactReconPhase
from src.agent.phases.analysis.run import AnalysisPhase
from src.agent.phases.analysis.aggregation import FindingAggregation
from src.agent.phases.analysis.compact import CompactAnalysisPhase
from src.agent.phases.verification.run import VerificationPhase
from src.agent.phases.intrusion.run import IntrusionPhase
from src.agent.phases.report.run import ReportPhase
from src.agent.phases.report.compact import CompactReportPhase
from src.agent.core.runner import AgentRunner
from src.agent.core.lifecycle import ScenarioLifecycle
from src.agent.core.runtime import OUTPUT_DIR, log


class Pipeline(
    GraphPhase,
    CompactGraphPhase,
    ReconPhase,
    CompactReconPhase,
    AnalysisPhase,
    FindingAggregation,
    CompactAnalysisPhase,
    VerificationPhase,
    IntrusionPhase,
    CompactIntrusionPhase,
    ReportPhase,
    CompactReportPhase,
    AgentRunner,
    ScenarioLifecycle,
):
    """Orchestrate phase modules with one shared run lifecycle."""

    def __init__(
        self,
        provider: runtime.LLMProvider,
        dry_run: bool = False,
        phases: list[int] | None = None,
        scenario_id: int | str | None = None,
        auto_teardown: bool = True,
        max_cost_usd: float | None = None,
        phase_models: dict[int | str, str] | None = None,
        custom_config: dict | None = None,  # {architecture, posture, selected_packs, excluded_vulns}
        target_network: str | None = None,  # CIDR for Docker discovery mode e.g. "192.168.1.0/24"
        blind: bool = False,  # Deploy scenario VMs but hide topology from agent (force discovery)
        execution_context=None,  # Sealed benchmark contract (src.benchmark.contracts.ExecutionContext)
        benchmark_split: str | None = None,
        manage_scenario: bool = True,
        execution_profile: str = "auto",
    ):
        self.provider = provider
        self.execution_profile_resolution = runtime.resolve_execution_profile_for_model(
            execution_profile, getattr(provider, "model", None)
        )
        self.execution_profile = self.execution_profile_resolution.profile
        self.execution_profile_policy = self.execution_profile_resolution.requested_policy
        self.phase_execution_profiles: dict[str, dict] = {}
        self.dry_run = dry_run
        self.requested_phases = (
            None if phases is None else sorted({int(phase) for phase in phases})
        )
        self.phases = runtime._expand_phase_selection(self.requested_phases)
        self.scenario_id = scenario_id
        self.execution_context = execution_context
        self.benchmark_split = benchmark_split or getattr(execution_context, "split", None)
        if self.benchmark_split is None and scenario_id is not None:
            try:
                from src.benchmark.catalog import get_scenario
                self.benchmark_split = get_scenario(str(scenario_id)).split
            except (ImportError, FileNotFoundError, KeyError, ValueError):
                self.benchmark_split = "dev-public"
        self.benchmark_split = self.benchmark_split or "unassigned"
        self.sealed = self.benchmark_split == "eval-sealed"
        # Benchmark runs must not change the CVE knowledge source on a cache
        # miss. Development runs without a benchmark split keep live lookup.
        self.cve_lookup_policy = (
            "cache_only" if self.benchmark_split != "unassigned" else "live_on_miss"
        )
        runtime.set_cve_cache_only(self.cve_lookup_policy == "cache_only")
        self.manage_scenario = bool(manage_scenario)
        self._generated_deployment: runtime.GeneratedScenarioDeployment | runtime.ManualScenarioDeployment | None = None
        self.auto_teardown = auto_teardown
        self.max_cost_usd = max_cost_usd
        self.phase_models = phase_models or {}
        self.custom_config = custom_config
        # A manual scenario may narrow the tools available in each phase.
        # It never grants capabilities beyond the normal runtime config.
        self.scenario_tool_policy: dict = {}
        self.scenario_lab_config: dict = {}
        self.blind = blind
        self.target_network = target_network
        self.max_tool_calls: int | None = None
        self._tool_call_count = 0
        self._artifact_log_lock = threading.Lock()
        _, self.runtime_unavailable_tools = runtime.filter_unavailable_tools(
            [tool for group in runtime.TOOL_GROUPS.values() for tool in group]
        )

        if self.sealed:
            if execution_context is None:
                raise ValueError(
                    "A sealed scenario requires an evaluator-issued execution_context"
                )
            # A sealed worker must not share the repository/oracle filesystem.  The
            # dedicated worker image intentionally contains no benchmarks directory.
            if Path("benchmarks/ground_truth").exists():
                raise RuntimeError(
                    "Refusing sealed evaluation in a process that can read the public "
                    "repository. Launch the dedicated benchmark worker container."
                )
            scope = getattr(execution_context, "scope", None)
            ingress = list(
                getattr(execution_context, "ingress_cidrs", [])
                or getattr(scope, "ingress_cidrs", [])
                or []
            )
            if not self.target_network and ingress:
                self.target_network = " ".join(ingress)
            if not self.target_network:
                raise ValueError("Sealed execution_context must provide at least one ingress CIDR")
            self.blind = True
            self.manage_scenario = False
            self.auto_teardown = False
            limits = getattr(execution_context, "limits", None)
            if self.max_cost_usd is None and limits is not None:
                self.max_cost_usd = getattr(limits, "max_cost_usd", None)
            if limits is not None:
                self.max_tool_calls = getattr(limits, "max_tool_calls", None)
        if self.blind and self.scenario_id is not None and self.target_network is None:
            # Default benchmark subnet — covers S1-S12. S13 (multi-VLAN) will land
            # on the same /24 via the OpenWrt router's WAN, then must pivot.
            self.target_network = runtime.BENCHMARK_SUBNET
        self.tracker = runtime.CostTracker(model=provider.model, provider=provider.provider)
        self.context: dict = {}
        # Set by run(); shared with phase workers so a dashboard stop request
        # can cancel queued work instead of waiting for the whole phase.
        self._stop_event = None

        # Create timestamped run directory
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.run_dir = OUTPUT_DIR / timestamp
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.git_commit = runtime._get_git_commit()

        # Point deliverable tools and validators at this run dir
        runtime.set_output_dir(self.run_dir)
        import src.agent.validators as val_mod
        val_mod.OUTPUT_DIR = self.run_dir

    def run(
        self,
        stream_callback: Callable[[dict], None] | None = None,
        stop_event=None,
    ) -> dict[str, str]:
        """Own the run lifecycle; keep legacy results and events compatible."""
        self._termination = None
        self._scenario_owned = False
        self._active_phase = None
        self._run_results: dict[str, str] = {}
        try:
            results = self._execute_run(stream_callback, stop_event)
        except KeyboardInterrupt:
            self._termination = "stopped"
            raise
        except BaseException:
            self._termination = "failed"
            if self._active_phase is not None:
                self._run_results[self._active_phase] = "failed:exception"
            raise
        finally:
            cleanup = "not_required"
            if self._scenario_owned and self.auto_teardown and not self.dry_run:
                try:
                    cleanup = "completed" if self._run_teardown(stream_callback) else "failed"
                except Exception:
                    cleanup = "failed"
                    log.exception("Run cleanup failed")
            if self._termination is None and stop_event and stop_event.is_set():
                self._termination = "stopped"
            status = runtime.run_status(self._run_results, self._termination)
            if cleanup == "failed" and status == "completed":
                status = "partial"
            # Metadata failure must not hide the original execution exception.
            try:
                self._update_run_meta({
                    "status": status, "cleanup_status": cleanup,
                    "results": self._run_results,
                })
            except Exception:
                log.exception("Could not persist terminal run state")
            self._persist_run(status)

        if stream_callback:
            stream_callback({
                "type": "pipeline_done", "results": results,
                "status": status, "cleanup_status": cleanup,
                "total_cost_usd": round(self.tracker.total_cost(), 4),
                "run_dir": str(self.run_dir),
            })
        return results

    def _persist_run(self, status: str) -> None:
        """Record terminal history without hiding an execution error."""
        try:
            from src.db.database import init_db, record_phase_usage, record_run

            init_db()
            summary = self.tracker.summary()
            tokens_in, tokens_out = self.tracker.total_tokens()
            run_id = record_run({
                "run_dir": str(self.run_dir),
                "ts": self.run_dir.name,
                "scenario_id": self.scenario_id,
                "model": getattr(self.provider, "model", None),
                "provider": getattr(self.provider, "provider", None),
                "status": status,
                "cost_usd": round(self.tracker.total_cost(), 4),
                "tokens_in": tokens_in,
                "tokens_out": tokens_out,
                "git_commit": self.git_commit,
            })
            if run_id is not None and summary.get("phases"):
                record_phase_usage(run_id, summary["phases"])
        except Exception as exc:
            log.warning("DB run persistence failed (non-fatal): %s", exc)

    def _execute_run(
        self,
        stream_callback: Callable[[dict], None] | None = None,
        stop_event=None,
    ) -> dict[str, str]:
        """Execute the full pipeline. Returns {agent_name: status} dict.

        Args:
            stream_callback: Optional callback for real-time events.
                Event types: pipeline_start, phase_start, text_chunk, tool_call,
                tool_result, turn_done, phase_done, pipeline_done.
        """
        # A dashboard stop is a run-level control, not a compact-model feature.
        self._stop_event = stop_event
        runtime.reset_tool_cache()
        self.scenario_tool_policy = self._load_scenario_tool_policy(self.scenario_id)
        self._load_scenario_runtime_limits(self.scenario_id)

        # Load lab context — discovery mode, scenario topology, or physical lab
        if self.target_network is not None:
            from src.agent.tools.graph_tools import load_discovery_context
            lab = load_discovery_context(self.target_network)
            target_subnet = self.target_network
        elif self.scenario_id is not None:
            from src.agent.tools.graph_tools import load_scenario_topology
            lab = load_scenario_topology(self.scenario_id)
            from src.agent.tools.graph_tools import _scenario_topology as _st_post
            _subnets = (_st_post or {}).get("subnets", [runtime.BENCHMARK_SUBNET])
            target_subnet = " ".join(_subnets) if len(_subnets) > 1 else (_subnets[0] if _subnets else runtime.BENCHMARK_SUBNET)
            # Initialize weighted attack graph for disbalance computation
            runtime.init_weighted_graph()
        else:
            lab = runtime.load_lab_context()
            target_subnet = runtime.PHYSICAL_SUBNET
            # Initialize weighted attack graph for disbalance computation
            runtime.init_weighted_graph()
        self.context = {
            "device_count": str(lab["device_count"]),
            "link_count": str(lab["link_count"]),
            "cve_count": str(lab["cve_count"]),
            "top_risk": str(lab["top_risk"]),
            "target_subnet": target_subnet,
            "scenario_context": "",
            "network_topology_edges": "",
            "execution_profile": self.execution_profile.name,
            "tool_policy": self.scenario_tool_policy,
            "scenario_lab_config": self.scenario_lab_config,
        }

        # Build compact edge list from whatever topology is available
        from src.agent.tools.graph_tools import _scenario_topology as _st, _backend as _bk
        if _st is not None:
            edges = _st.get("edges", [])
            self.context["network_topology_edges"] = "\n".join(
                f"  {e['source']} -> {e['target']}" for e in edges
            )
            # Pre-compute nmap_scan groups by role so Phase 2 doesn't have to guess
            self.context["nmap_scan_groups"] = self._build_nmap_groups(_st.get("nodes", []))
        elif _bk is not None:
            try:
                topo = _bk.to_dict()
                edges = topo.get("edges", [])
                self.context["network_topology_edges"] = "\n".join(
                    f"  {e.get('source', e.get('from', '?'))} -> {e.get('target', e.get('to', '?'))}"
                    for e in edges
                )
            except Exception:
                pass
        if "nmap_scan_groups" not in self.context:
            self.context["nmap_scan_groups"] = ""

        print("Loading lab context...")
        print(
            f"  Devices: {lab['device_count']}, Links: {lab['link_count']}, "
            f"CVEs: {lab['cve_count']}, Top risk: {lab['top_risk']}"
        )

        # Save run metadata (git commit, model) for traceability
        run_meta = {
            "model": getattr(self.provider, "model", None),
            "git_commit": self.git_commit,
            "benchmark_split": self.benchmark_split,
            "cve_lookup_policy": self.cve_lookup_policy,
            "cve_source": (
                "immutable_benchmark_snapshot_v1"
                if self.cve_lookup_policy == "cache_only"
                else "live_nvd_with_mutable_cache"
            ),
            "runtime_unavailable_tools": self.runtime_unavailable_tools,
            "oracle_access": False,
            "requested_phases": (
                self.requested_phases
                if self.requested_phases is not None else [1, 2, 3, 4, 5, 6]
            ),
            "effective_phases": (
                self.phases if self.phases is not None else [1, 2, 3, 4, 5, 6]
            ),
            **self.execution_profile_resolution.metadata(),
            "execution_profile_config": self.execution_profile.metadata(),
            **runtime.metric_contract_metadata(),
        }
        contract_hash = getattr(self.execution_context, "contract_hash", None)
        if not contract_hash and self.execution_context is not None:
            try:
                import hashlib
                contract_payload = self.execution_context.to_json().encode("utf-8")
                contract_hash = hashlib.sha256(contract_payload).hexdigest()
            except (AttributeError, TypeError, ValueError):
                contract_hash = None
        if contract_hash:
            run_meta["contract_hash"] = contract_hash
        session_id = getattr(self.execution_context, "session_id", None)
        if session_id:
            run_meta["session_id"] = session_id
        (self.run_dir / "run_meta.json").write_text(json.dumps(run_meta, indent=2))

        if stream_callback:
            stream_callback({
                "type": "pipeline_start",
                "device_count": lab["device_count"],
                "link_count": lab["link_count"],
                "cve_count": lab["cve_count"],
                "top_risk": lab["top_risk"],
                "execution_profile": self.execution_profile.name,
                "execution_profile_policy": self.execution_profile_resolution.requested_policy,
            })

        # Load benchmark scenario context if specified.
        # In blind mode, we deploy the scenario but hide the topology — the agent
        # must discover targets itself, so scenario_context stays empty.
        if self.scenario_id is not None:
            if not self.blind and not self.sealed:
                scenario_context = self._load_scenario_context(self.scenario_id)
                if scenario_context:
                    self.context["scenario_context"] = scenario_context
                    print(f"  Benchmark scenario: S{self.scenario_id} — {scenario_context.splitlines()[0]}")
            else:
                print(f"  Benchmark scenario: S{self.scenario_id} (BLIND — topology hidden, discovery on {self.target_network})")

            # Save scenario metadata for evaluator
            meta = {
                "scenario_id": self.scenario_id,
                "split": self.benchmark_split,
                "run_dir": str(self.run_dir),
                "model": getattr(self.provider, "model", None),
                "git_commit": self.git_commit,
                "oracle_access": False,
                **self.execution_profile_resolution.metadata(),
            }
            if session_id:
                meta["session_id"] = session_id
            if contract_hash:
                meta["contract_hash"] = contract_hash
            if self.custom_config:
                meta["custom_config"] = self.custom_config
            (self.run_dir / "scenario_meta.json").write_text(json.dumps(meta, indent=2))

            # Deploy benchmark VMs before starting the pipeline
            if self.manage_scenario and not self.dry_run:
                deploy_ok = self._run_scenario_deploy(stream_callback)
                if not deploy_ok:
                    self._termination = "failed"
                    return {}

        # Get agents sorted by phase
        agents = sorted(runtime.AGENTS.values(), key=lambda a: a.phase)
        if self.phases is not None:
            agents = [a for a in agents if a.phase in self.phases]

        results = self._run_results

        for agent_config in agents:
            self._active_phase = agent_config.name
            # Switch provider/model if specific model set for this phase
            phase_num = agent_config.phase
            # Handle keys from JSON as strings or ints
            target_model = self.phase_models.get(phase_num) or self.phase_models.get(str(phase_num))
            if target_model and target_model != self.provider.model:
                target_provider = runtime._resolve_model_provider(target_model)
                log.info("Switching to phase %d specific model: %s (%s)", phase_num, target_model, target_provider)
                self.provider = runtime.LLMProvider(provider=target_provider, model=target_model)
                self.tracker.model = target_model
                self.tracker.provider = target_provider

            self.execution_profile_resolution = runtime.resolve_execution_profile_for_model(
                self.execution_profile_policy, getattr(self.provider, "model", None)
            )
            self.execution_profile = self.execution_profile_resolution.profile
            self.context["execution_profile"] = self.execution_profile.name
            self.phase_execution_profiles[str(phase_num)] = {
                "model": getattr(self.provider, "model", None),
                **self.execution_profile_resolution.metadata(),
            }
            self._update_run_meta({
                "phase_execution_profiles": self.phase_execution_profiles
            })

            # Honour stop request between phases
            if stop_event and stop_event.is_set():
                self._termination = "stopped"
                log.info("Pipeline stop requested — halting before phase %d", agent_config.phase)
                if stream_callback:
                    stream_callback({"type": "error", "message": "Pipeline arrêté par l'utilisateur"})
                break

            # Check prerequisites
            if agent_config.phase == 6 and not (
                self.run_dir / "04_exploitation.json"
            ).is_file():
                # This is intentionally explicit in addition to the generic
                # prerequisite check. A report based only on Phase 3 claims
                # would look successful while its report-facing context is
                # correctly empty because no exploitation evidence exists.
                log.warning(
                    "Skipping report: 04_exploitation.json is missing; "
                    "run Phase 4 before Phase 6"
                )
                results[agent_config.name] = "skipped:prerequisites"
                continue
            if not self._check_prerequisites(agent_config, results):
                log.warning("Skipping %s: prerequisites not met", agent_config.name)
                results[agent_config.name] = "skipped:prerequisites"
                continue

            # Check conditional execution
            if not self._check_conditional(agent_config):
                log.info(
                    "Skipping %s: conditional check failed (empty queue)",
                    agent_config.name,
                )
                skip_status = "skipped:conditional"
                if agent_config.phase == 5:
                    exploit_path = self.run_dir / "04_exploitation.json"
                    try:
                        exploit_data = json.loads(exploit_path.read_text(encoding="utf-8"))
                        summary = exploit_data.get("summary", {})
                        total = int(summary.get("total_tested", 0) or 0)
                        confirmed = int(summary.get("confirmed", 0) or 0)
                        failed = int(summary.get("not_exploitable", 0) or 0)
                        errors = int(summary.get("errors", 0) or 0)
                        if total > 0 and confirmed == 0 and failed == 0 and errors >= total:
                            skip_status = "blocked:phase4_no_conclusive_results"
                    except (OSError, json.JSONDecodeError, TypeError, ValueError):
                        skip_status = "blocked:phase4_missing_or_invalid"
                results[agent_config.name] = skip_status
                continue

            # Pre-generate context files before certain phases
            if agent_config.phase == 5:
                self._generate_intrusion_context()
            if agent_config.phase == 6:
                self._generate_phase6_context()
                self._pregenerate_report_sections()

            status = run_phase(self, agent_config, stream_callback)

            results[agent_config.name] = status

            if agent_config.phase == 1:
                self._build_graph_evidence_projection()
            if agent_config.phase == 2:
                self._build_recon_evidence_projection()

            # After Phase 2 in discovery mode, infer topology links via traceroute
            if agent_config.phase == 2 and self.target_network:
                self._infer_topology_links(stream_callback)

            # After Phase 5 (intrusion): small models often run the campaign but
            # never emit the final deliverable. Synthesize it from recorded tool
            # calls so the report phase still has data. Then emit hop events.
            if agent_config.phase == 5:
                self._ensure_intrusion_deliverable(agent_config, results, stream_callback)
                self._emit_intrusion_events(stream_callback)

            # Enforce budget limit after each phase
            if self.max_cost_usd is not None and self.tracker.total_cost() >= self.max_cost_usd:
                self._termination = "budget_exceeded"
                log.warning(
                    "Budget limit reached ($%.4f >= $%.4f) — stopping pipeline",
                    self.tracker.total_cost(), self.max_cost_usd,
                )
                if stream_callback:
                    stream_callback({
                        "type": "error",
                        "message": f"Budget dépassé (${self.tracker.total_cost():.4f} ≥ ${self.max_cost_usd:.4f}) — pipeline arrêté",
                    })
                break

        self._active_phase = None

        # Print cost summary
        self.tracker.print_summary()

        # Save cost summary to run directory
        cost_path = self.run_dir / "cost_summary.json"
        cost_path.write_text(self.tracker.to_json(), encoding="utf-8")
        log.info("Cost summary saved to %s", cost_path)

        # Episodic memory is intentionally disabled for sealed runs.  Otherwise
        # later submissions could recover findings from earlier challenge seeds.
        if not self.sealed:
            try:
                from src.agent.knowledge.ingest import ingest_run_findings
                ingested = ingest_run_findings(self.run_dir, self.provider.model)
                if ingested:
                    log.info("Ingested %d findings into run_history", ingested)
            except Exception as e:
                log.warning("Run history ingestion failed (non-fatal): %s", e)

        # Custom development scenarios have no repository GT.  Generate their
        # oracle only after every agent phase has finished, so python_exec and
        # deliverable tools can never read the answer key during the run.
        if self.custom_config and not self.sealed:
            self._save_ground_truth()

        return results

    def _update_run_meta(self, updates: dict) -> None:
        """Merge updates into run_meta.json for traceability (phase status, errors)."""
        path = self.run_dir / "run_meta.json"
        meta = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        meta.update(updates)
        path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    def _check_prerequisites(
        self, config: runtime.AgentConfig, results: dict[str, str]
    ) -> bool:
        """Require an actual artifact, even when the producer was skipped."""
        for prereq_name in config.prerequisites:
            status = results.get(prereq_name)
            if not runtime.prerequisite_status_allows_artifact(status):
                return False
            prereq_config = runtime.AGENTS.get(prereq_name)
            if prereq_config is None:
                return False
            if not runtime.artifact_available(self.run_dir, prereq_config.deliverable_file):
                return False
        return True

    def _check_conditional(self, config: runtime.AgentConfig) -> bool:
        """Check conditional execution (e.g., vuln queue non-empty).

        Supports both 03_vuln_analysis.json (key: "vulnerabilities") and
        04_exploitation.json (key: "tests" with CONFIRMED entries).
        """
        if not config.conditional:
            return True
        path = self.run_dir / config.conditional
        if not path.exists():
            return False
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            # 03_vuln_analysis.json style
            if "vulnerabilities" in data:
                return len(data["vulnerabilities"]) > 0
            # 04_exploitation.json style. Phase 5 is a reconciliation stage:
            # it must run after an executed Phase 4 even when every fresh probe
            # failed or errored. Otherwise the absence of a CONFIRMED verdict
            # hides the phase-5 evidence boundary and makes path metrics
            # unavailable instead of recording an explicit zero.
            if "tests" in data:
                tests = data.get("tests")
                if not isinstance(tests, list):
                    return False
                if config.phase == 5 and not self.execution_profile.routed_tools:
                    summary = data.get("summary") or {}
                    execution_state = str(summary.get("execution_state") or "").casefold()
                    return bool(tests) and execution_state in {
                        "executed", "executed_with_worker_errors", "stopped",
                    }
                confirmed = [t for t in tests if t.get("status") == "CONFIRMED"]
                return len(confirmed) > 0
            return False
        except (json.JSONDecodeError, KeyError):
            return False
