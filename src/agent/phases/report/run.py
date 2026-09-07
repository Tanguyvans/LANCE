"""Report phase: common execution and evidence handling."""
from __future__ import annotations
import logging
from src.agent.core import runtime
from src.agent.phases.report import context as report_context, rendering as report_rendering


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


def run(context, config, stream_callback=None):
    if context.execution_profile.name == "compact" and context._uses_compact_local_moe():
        return context._run_local_report_phase(config, stream_callback)
    try:
        status = context._run_agent(config, stream_callback)
        context._update_run_meta({"phase6_llm": "completed"})
    except Exception as exc:
        log.warning("Phase 6 agent error — using prefill fallback: %s", exc)
        status = "error"
        context._update_run_meta({"phase6_llm": "fallback", "phase6_error": str(exc)})
    finally:
        context._merge_report_with_prefill()
    return status
