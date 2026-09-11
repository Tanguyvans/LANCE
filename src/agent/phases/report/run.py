"""Report phase: common execution and evidence handling."""
from __future__ import annotations
from collections.abc import Callable
import json
import logging
import time
from src.agent.core import runtime
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.report import context as report_context, rendering as report_rendering
from src.agent.phases.report.validation import _local_report_memo_contradicts_context


log = logging.getLogger(__name__)


class ReportPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _build_local_report_analysis_context(self) -> dict:
        return report_context.build_report_analysis_context(self.run_dir)

    def _generate_phase6_context(self) -> None:
        report_context.generate_phase6_context(
            self.run_dir, self.context, compact=self._uses_compact_local_moe()
        )

    def _pregenerate_report_sections(self) -> None:
        report_rendering.pregenerate_report_sections(self.run_dir)

    def _merge_report_with_prefill(self) -> None:
        report_rendering.merge_report_with_prefill(
            self.run_dir, self.context, model=self.provider.model,
            validate_report=runtime.VALIDATORS["report_markdown"],
        )

    def _run_local_report_phase(
        self, config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> str:
        """Run the common one-shot analyst-note/report-rendering contract."""
        report_path = self.run_dir / config.deliverable_file
        note_path = self.run_dir / "06_report_analysis.md"
        context_path = self.run_dir / "06_report_analysis_context.json"
        deadline = time.monotonic() + max(0.01, float(runtime.LOCAL_MOE_REPORT_PHASE_TIMEOUT))
        pending_budget_error: BudgetExceeded | None = None
        analysis_context: dict = {}
        note_status, cause, phase_error = "absent", "memo_absent", None
        cleanup_failed = False

        for stale_path in (report_path, note_path):
            try:
                if stale_path.exists():
                    stale_path.unlink()
            except OSError as exc:
                cleanup_failed = True
                phase_error = f"stale_output_cleanup:{exc}"
                cause = "stale_output_cleanup"

        def stopped() -> bool:
            event = getattr(self, "_stop_event", None)
            return bool(event is not None and event.is_set())

        if stream_callback:
            stream_callback({
                "type": "phase_start", "phase": config.phase, "name": config.name,
                "description": config.description, "deliverable": config.deliverable_file,
            })
        self.tracker.start_phase(config.name)
        try:
            analysis_context = self._build_local_report_analysis_context()
            context_json = json.dumps(analysis_context, ensure_ascii=False, separators=(",", ":"))
            context_path.write_text(context_json, encoding="utf-8")
            system_prompt = runtime.load_prompt("report", {
                "report_analysis_context": context_json,
                "note_budget": self.execution_profile.report_max_tokens,
                "turn_budget": 1,
                "profile": self.execution_profile.name,
            })
            if stopped():
                note_status, cause = "not_run", "stopped"
            else:
                self.tracker.check_budget()
                result = self.provider.chat_with_tools(
                    system_prompt=system_prompt,
                    user_message="Write the short analyst note now.",
                    tools=[], max_turns=1,
                    max_tokens=self.execution_profile.report_max_tokens,
                    cost_tracker=self.tracker,
                    stream_callback=self._model_stream_callback(
                        stream_callback, phase=config.phase, agent="report_analyst_note"
                    ),
                    repeat_guard=False, stop_event=self._stop_event, deadline=deadline,
                )
                text = str(result).strip() if result else ""
                if text:
                    self._model_stream_callback(
                        None, phase=config.phase, agent="report_analyst_note_result"
                    )({"type": "text_chunk", "text": text})
                if stopped():
                    note_status, cause = "not_promoted", "stopped"
                elif time.monotonic() > deadline:
                    note_status, cause = "not_promoted", "timeout"
                elif not text or text in {
                    "(max turns reached)", "(malformed tool call JSON — max retries)",
                }:
                    note_status, cause = "absent", "memo_empty"
                elif (_looks_unusable_model_memo(text)
                      or _local_report_memo_contradicts_context(text, analysis_context)):
                    note_status, cause = "rejected", "memo_rejected"
                else:
                    note_path.write_text(text + "\n", encoding="utf-8")
                    note_status, cause = "usable", "none"
                    if stream_callback:
                        stream_callback({
                            "type": "text_chunk", "phase": config.phase,
                            "agent": "report_analyst_note_result", "text": text,
                        })
        except BudgetExceeded as exc:
            pending_budget_error = exc
            note_status, cause, phase_error = "not_promoted", "budget_exceeded", str(exc)
        except Exception as exc:
            phase_error = str(exc)
            error_name = type(exc).__name__.casefold()
            if stopped():
                note_status, cause = "not_promoted", "stopped"
            elif isinstance(exc, TimeoutError) or "timeout" in error_name or "deadline" in error_name or time.monotonic() > deadline:
                note_status, cause = "not_promoted", "timeout"
            else:
                note_status, cause = "absent", "provider_error"
            log.warning("Phase 6 analyst note unavailable: %s", exc)
        finally:
            if note_status != "usable":
                try:
                    if note_path.exists():
                        note_path.unlink()
                except OSError:
                    log.exception("Could not remove non-promoted Phase 6 note")
            final_valid, validation_message = False, "report_not_rendered"
            try:
                report_rendering.render_deterministic_report(
                    self.run_dir, self.context, model=self.provider.model,
                    validate_report=runtime.VALIDATORS["report_markdown"],
                    analysis_status=note_status, analysis_cause=cause,
                )
                final_valid, validation_message = runtime.VALIDATORS[
                    "final_report_markdown"
                ](config.deliverable_file)
            except Exception as exc:
                validation_message = f"render_error:{exc}"
                phase_error = phase_error or str(exc)
                log.exception("Phase 6 deterministic rendering failed")
            self.tracker.record_validation_result(success=final_valid)
            usage = self.tracker.end_phase()
            if not final_valid:
                status, terminal_cause = f"failed:{validation_message}", "final_report_invalid"
            elif cleanup_failed:
                status, terminal_cause = "failed:stale_output_cleanup", "stale_output_cleanup"
            elif pending_budget_error is not None:
                status, terminal_cause = "budget_exceeded", "budget_exceeded"
            elif stopped():
                status, terminal_cause = "stopped", "stopped"
            elif note_status == "usable":
                status, terminal_cause = "completed", "none"
            else:
                status, terminal_cause = f"partial:{cause}", cause
            try:
                self._update_run_meta({
                    "phase6_status": status,
                    "phase6_llm": "analyst_note" if note_status == "usable" else "deterministic_only",
                    "phase6_note_status": note_status, "phase6_cause": terminal_cause,
                    "phase6_error": phase_error,
                    "phase6_analysis": "06_report_analysis.md" if note_status == "usable" else None,
                    "phase6_timeout_s": float(runtime.LOCAL_MOE_REPORT_PHASE_TIMEOUT),
                    "phase6_report_validation": validation_message,
                    "phase6_context_bytes": context_path.stat().st_size if context_path.exists() else 0,
                    "phase6_context_omissions": analysis_context.get("omissions", {}),
                })
            except Exception:
                log.exception("Could not persist Phase 6 metadata")
            if stream_callback:
                stream_callback({
                    "type": "phase_done", "phase": config.phase, "name": config.name,
                    "status": status, "deliverable": config.deliverable_file,
                    "cost_usd": round(usage.cost_usd(), 4) if usage else 0,
                    "turns": usage.turns if usage else 0,
                })
        if pending_budget_error is not None:
            raise pending_budget_error
        return status


def run(context, config, stream_callback=None):
    # Both profiles use the same bounded note + deterministic renderer.  The
    # old report _run_agent path intentionally remains available to other
    # phases but is no longer an entry point for Phase 6.
    return context._run_local_report_phase(config, stream_callback)
