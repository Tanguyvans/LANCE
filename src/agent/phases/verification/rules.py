"""Bounded verification policy using the same plans, executor and evidence rules."""
from __future__ import annotations

import json
import threading

from src.agent.core.executor import EvidenceWriteError, check_execution_limits
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.verification.contract import _phase4_verification_plan
from src.agent.phases.verification.evidence import _exploit_relpath, _tool_records_for_vuln
from src.agent.exploit_evidence import synthesize_exploit_result


def verify(run, config, stream_callback=None):
    candidates = json.loads((run.run_dir / "03_vuln_analysis.json").read_text())["vulnerabilities"]
    tools = {t["name"]: t for t in run._resolve_tools(config)}
    run._exploit_tool_context = threading.local()
    run._phase4_execution_errors = {}
    run._phase4_execution_status = "completed"
    run._phase4_schedule = {
        "candidate_count": len(candidates), "scheduled_count": len(candidates),
        "scheduled_vuln_ids": [v["id"] for v in candidates],
        "skipped_count": 0, "skipped_candidates": [],
    }
    for vuln in candidates:
        check_execution_limits(run)
        identifier = vuln["id"]
        run._exploit_tool_context.vulnerability = {
            "vuln_id": identifier, "device_id": vuln.get("device_id"),
            "device_ip": vuln.get("device_ip"), "vuln_type": vuln.get("type"),
            **{key: vuln.get(key, "") for key in ("service", "port", "protocol", "endpoint", "product")},
        }
        run.tracker.start_phase(f"rules_verify_{identifier}")
        try:
            plan = _phase4_verification_plan(vuln, compact=False)
            tool = tools.get(plan.get("tool"))
            if plan.get("plan_error") or not tool or not callable(tool.get("function")) or not plan.get("args_hint"):
                run._phase4_execution_errors[identifier] = [{"stage": "rules_plan", "kind": "unsupported", "reason": str(plan.get("plan_error") or "No available bounded probe with complete arguments")}]
                run._phase4_execution_status = "executed_with_worker_errors"
            else:
                tool["function"](**plan["args_hint"])
        except (BudgetExceeded, EvidenceWriteError):
            raise
        except Exception as exc:
            run._phase4_execution_errors[identifier] = [{"stage": "rules_probe", "kind": "exception", "exception_type": type(exc).__name__}]
            run._phase4_execution_status = "executed_with_worker_errors"
        finally:
            run._exploit_tool_context.vulnerability = None
            run.tracker.end_phase()
        result = synthesize_exploit_result(vuln, _tool_records_for_vuln(run.run_dir, identifier), compact=False)
        path = run.run_dir / _exploit_relpath(vuln.get("device_id", "unknown"), vuln.get("type", ""), identifier)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    run._aggregate_exploit_results()
