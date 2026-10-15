"""Durable UI progress derived from controller events, never from finding labels."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path

from src.agent.procedures import get_procedure


STEP_STATUSES = frozenset({"pending", "running", "completed", "partial", "failed",
                           "stopped", "skipped", "not_observed"})
RUN_STATUSES = frozenset({"pending", "waiting", "running", "completed", "partial", "failed",
                          "stopped", "budget_exceeded", "skipped"})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _phase_status(status) -> str:
    if status == "completed":
        return "completed"
    if isinstance(status, str):
        if status.startswith("failed"):
            return "failed"
        if status.startswith("stopped") or status == "budget_exceeded":
            return "stopped"
        if status == "skipped":
            return "skipped"
        if "error" in status or "partial" in status:
            return "partial"
    return "not_observed"


class RulesProcedureProgress:
    """Retain the executed descriptor and distinguish completion from coverage.

    A successful deployment command does not complete preparation: injection and
    the controller's verification must also have succeeded. Teardown before the
    first deployment belongs to preparation, not to this run's final cleanup.
    A failed preliminary cleanup remains visible even if later preflight checks
    succeed: those checks do not establish that the previous machines vanished.
    """

    def __init__(self, run_dir: Path, *, auto_teardown: bool):
        self.run_dir = Path(run_dir)
        self.auto_teardown = auto_teardown
        self.preparation_started = False
        self.preparation_cleanup_failed = False
        descriptor = get_procedure("rules-audit-v1")
        self.data = {
            "schema_version": 1, "runner_kind": "rules", "status": "pending",
            "procedure": {key: descriptor[key] for key in ("id", "title", "version", "fingerprint")},
            "steps": [{**step, "status": "pending"} for step in descriptor["steps"]],
            "controls_complete": None,
        }
        self.publish()

    def _step(self, identifier: str, status: str, *, reason: str | None = None):
        step = next(item for item in self.data["steps"] if item["id"] == identifier)
        step.update(status=status, updated_at=_now())
        if reason:
            step["reason"] = reason
        else:
            step.pop("reason", None)

    def publish(self) -> dict:
        self.data["updated_at"] = _now()
        temporary = self.run_dir / ".procedure_progress.tmp"
        # The directory belongs to the controller-created run. Replacing the
        # temporary entry avoids following an existing symlink on open.
        temporary.unlink(missing_ok=True)
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(self.data, handle, ensure_ascii=False, indent=2)
        temporary.replace(self.run_dir / "procedure_progress.json")
        return deepcopy(self.data)

    def observe(self, event: dict, *, terminal: bool = False) -> dict | None:
        kind = event.get("type")
        changed = False
        if kind in {"lab_waiting", "lab_acquired"}:
            self.data["status"] = "waiting" if kind == "lab_waiting" else "running"
            changed = True
        elif kind in {"deploy_start", "inject_start", "verify_start"}:
            self.preparation_started = True
            self.data["status"] = "running"
            self._step("deployment", "running", reason=kind.removesuffix("_start"))
            changed = True
        elif kind in {"deploy_done", "inject_done", "verify_done"}:
            self.preparation_started = True
            if event.get("success") is False:
                self._step("deployment", "failed", reason=kind.removesuffix("_done"))
            elif kind == "verify_done" and event.get("success") is True:
                self._step("deployment", "partial" if self.preparation_cleanup_failed else "completed",
                           reason="predeployment_cleanup_failed" if self.preparation_cleanup_failed
                           else "preflight_checks_completed")
            else:
                self._step("deployment", "running", reason=kind.removesuffix("_done"))
            changed = True
        elif kind in {"phase_start", "phase_done"} and event.get("phase") in {3, 4}:
            identifier = {3: "analysis", 4: "verification"}[event["phase"]]
            self.data["status"] = "running"
            status = "running" if kind == "phase_start" else _phase_status(event.get("status"))
            self._step(identifier, status, reason=str(event.get("status")) if kind == "phase_done" else None)
            changed = True
        elif (kind in {"teardown_start", "teardown_done"} and not self.preparation_started
              and event.get("playbook") == "99_teardown.yml"):
            # This is the controller's observed cleanup before the first
            # deploy/inject/verify event. Its success alone does not prepare the
            # requested scenario; final cleanup has not begun.
            self.data["status"] = "running"
            success = event.get("success")
            if kind == "teardown_done" and success is False:
                self.preparation_cleanup_failed = True
            status = ("failed" if kind == "teardown_done" and success is False else
                      "not_observed" if kind == "teardown_done" and success is not True else "running")
            self._step("deployment", status,
                       reason="predeployment_cleanup_failed" if self.preparation_cleanup_failed
                       else "predeployment_cleanup")
            changed = True
        elif kind in {"teardown_start", "teardown_done"} and self.preparation_started:
            status = ("running" if kind == "teardown_start" else
                      "completed" if event.get("success") is True else "failed")
            self._step("cleanup", status)
            changed = True
        elif kind == "pipeline_done":
            if terminal:
                self.finish(event)
            else:
                self._step("results", "running", reason="finalizing_artifacts")
            changed = True
        if changed:
            return self.publish()
        return None

    def finish(self, event: dict) -> None:
        status = event.get("status")
        self.data["status"] = status if status in RUN_STATUSES else "failed"
        interruption = "stopped" if status in {"stopped", "budget_exceeded"} else "failed"
        for step in self.data["steps"]:
            identifier = step["id"]
            if identifier == "results":
                summary = self.run_dir / "run_summary.md"
                try:
                    saved = not summary.is_symlink() and summary.is_file() and summary.stat().st_size > 0
                except OSError:
                    saved = False
                self._step(identifier, "completed" if saved else "not_observed",
                           reason="summary_saved" if saved else "summary_unavailable")
            elif identifier == "cleanup" and step["status"] == "pending" and not self.auto_teardown:
                self._step(identifier, "skipped", reason="automatic_cleanup_disabled")
            elif step["status"] == "running":
                self._step(identifier, interruption, reason="terminal_before_step_completion")
            elif step["status"] == "pending":
                self._step(identifier, "not_observed", reason="no_completion_event")
        controls = [item for item in self.data["steps"] if item["id"] in {"analysis", "verification"}]
        self.data["controls_complete"] = all(item["status"] == "completed" for item in controls)
