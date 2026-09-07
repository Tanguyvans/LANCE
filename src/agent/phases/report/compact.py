"""Report phase: compact adaptations."""
from __future__ import annotations
from collections.abc import Callable
import json
import time
import logging
from src.agent.phases.report.validation import _local_report_memo_contradicts_context
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.core import runtime


log = logging.getLogger(__name__)


class CompactReportPhase:
    """Phase operations using the shared run state; no independent lifecycle."""

    def _run_local_report_phase(
        self,
        config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> str:
        """Run one bounded local analysis, then compose and validate the report."""
        if stream_callback:
            stream_callback({
                "type": "phase_start", "phase": config.phase, "name": config.name,
                "description": config.description, "deliverable": config.deliverable_file,
            })

        context = self._build_local_report_analysis_context()
        context_path = self.run_dir / "06_report_analysis_context.json"
        context_path.write_text(
            json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        prompt = (
            "You are the final security analyst. Produce a concise evidence-based "
            "analyst memo, not a full report and not JSON. Identify the most important "
            "recon discrepancies, attack paths, exploit/intrusion implications, and "
            "prioritized remediations. Preserve useful uncertainty and nuance. Never "
            "invent facts. The deterministic pipeline will embed your complete memo "
            "verbatim in section 10.3 of the final report. You have no tools because "
            "all authoritative evidence is supplied below.\n\nEVIDENCE:\n"
            + json.dumps(context, ensure_ascii=False)
        )

        self.tracker.start_phase(config.name)
        analysis_error = ""
        deadline = time.monotonic() + runtime.LOCAL_MOE_REPORT_PHASE_TIMEOUT
        try:
            result_text = self.provider.chat_with_tools(
                system_prompt=prompt,
                user_message="Write the analyst memo now.",
                tools=[],
                max_turns=1,
                max_tokens=min(config.max_tokens, 1536),
                cost_tracker=self.tracker,
                stream_callback=self._model_stream_callback(
                    stream_callback, phase=config.phase, agent="report_local_analysis"
                ),
                repeat_guard=False,
                stop_event=self._stop_event,
                deadline=deadline,
            )
            if result_text and result_text.strip() not in {
                "(max turns reached)", "(malformed tool call JSON — max retries)",
            }:
                analysis_text = result_text.strip()
                if (
                    _looks_unusable_model_memo(analysis_text)
                    or _local_report_memo_contradicts_context(analysis_text, context)
                ):
                    log.warning(
                        "Local Phase 6 analyst memo rejected as inconsistent with artifacts"
                    )
                else:
                    (self.run_dir / "06_report_analysis.md").write_text(
                        analysis_text + "\n", encoding="utf-8"
                    )
                    self._model_stream_callback(
                        None, phase=config.phase, agent="report_local_analysis_result"
                    )({"type": "text_chunk", "text": analysis_text})
        except Exception as exc:
            analysis_error = str(exc)
            log.warning("Local Phase 6 analysis failed; composing from evidence: %s", exc)

        self._merge_report_with_prefill()
        valid, msg = runtime.VALIDATORS["final_report_markdown"](config.deliverable_file)
        status = "completed" if valid else f"failed:{msg}"
        self.tracker.record_validation_result(success=valid)
        usage = self.tracker.end_phase()
        self._update_run_meta({
            "phase6_llm": "local_bounded" if not analysis_error else "local_fallback",
            "phase6_error": analysis_error or None,
            "phase6_analysis": "06_report_analysis.md",
            "phase6_timeout_s": runtime.LOCAL_MOE_REPORT_PHASE_TIMEOUT,
            "phase6_report_validation": msg,
        })
        if stream_callback:
            stream_callback({
                "type": "phase_done", "phase": config.phase, "name": config.name,
                "status": status, "deliverable": config.deliverable_file,
                "cost_usd": round(usage.cost_usd(), 4) if usage else 0,
                "turns": usage.turns if usage else 0,
            })
        return status
