"""Phase 6: independently resumable cards followed by deterministic assembly."""
from __future__ import annotations
from collections.abc import Callable
import logging
import time

from src.agent.core import runtime
from src.agent.core.memo import _looks_unusable_model_memo
from src.agent.cost_tracker import BudgetExceeded
from src.agent.phases.report import context as report_context, rendering as report_rendering
from src.agent.phases.report import sections
from src.agent.phases.report.validation import _local_report_memo_contradicts_context


log = logging.getLogger(__name__)


class ReportPhase:
    def _build_local_report_analysis_context(self) -> dict:
        return report_context.build_report_analysis_context(self.run_dir)

    def _generate_phase6_context(self) -> None:
        report_context.generate_phase6_context(
            self.run_dir, self.context, compact=self._uses_compact_local_moe(),
        )

    def _pregenerate_report_sections(self) -> None:
        report_rendering.pregenerate_report_sections(self.run_dir)

    def _merge_report_with_prefill(self) -> None:
        report_rendering.merge_report_with_prefill(
            self.run_dir, self.context, model=self.provider.model,
            validate_report=self._validator("report_markdown"),
        )

    def _run_local_report_phase(
        self, config: runtime.AgentConfig,
        stream_callback: Callable[[dict], None] | None = None,
    ) -> str:
        phase_timeout = max(0.01, float(runtime.LOCAL_MOE_REPORT_PHASE_TIMEOUT))
        deadline = time.monotonic() + phase_timeout
        pending_budget_error = None
        note_path = self.run_dir / "06_report_analysis.md"
        manifest = {"contract": "sectioned-report", "sections": [], "expected_sections": 0}
        cause, phase_error = "none", None
        summary_text = ""

        def stopped():
            event = getattr(self, "_stop_event", None)
            return bool(event is not None and event.is_set())

        if stream_callback:
            stream_callback({"type": "phase_start", "phase": config.phase, "name": config.name,
                             "description": config.description, "deliverable": config.deliverable_file})
        self.tracker.start_phase(config.name)
        try:
            # Only active projections are replaced. Cached card snapshots survive
            # retries, but are reused only for identical input/prompt/model facts.
            for name in (config.deliverable_file, "06_report_analysis.md", "06_report_cards.md", "06_report_intrusion_cards.md"):
                path = self.run_dir / name
                if path.exists():
                    path.unlink()
            sections.write_object(self.run_dir, sections.MANIFEST, manifest)
            cards, summary = sections.build_cards(self.run_dir, getattr(self, "_run_results", {}))
            manifest["expected_sections"] = len(cards) + 1
            for index in range(len(cards) + 1):
                if index == len(cards):
                    card = {"key": "summary", "kind": "summary", "title": "Synthèse exécutive",
                            "facts": {**summary, "writing": {
                                "usable": sum(e["status"] == "usable" for e in manifest["sections"]),
                                "incomplete": sum(e["status"] != "usable" for e in manifest["sections"]),
                            }}, "source_issue": None}
                else:
                    card = cards[index]
                prompt = sections.section_prompt(card)
                token_limit = self.execution_profile.report_max_tokens
                fingerprint = sections.digest({"card": card, "prompt": prompt,
                                               "provider": self.provider.provider, "model": self.provider.model,
                                               "tokens": token_limit, "contract": manifest["contract"]})
                filename = f"06_report_sections/{fingerprint}.json"
                record = sections.reusable(self.run_dir, filename, fingerprint, card)
                reused = record is not None
                if record is None:
                    record = {"fingerprint": fingerprint, "card": card, "status": "unavailable",
                              "cause": "memo_absent", "finish_reason": None, "text": ""}
                    if stopped():
                        record["cause"] = "stopped"
                    elif pending_budget_error is not None:
                        record["cause"] = "budget_exceeded"
                    elif time.monotonic() >= deadline:
                        record["cause"] = "timeout"
                    elif card.get("source_issue"):
                        record["cause"] = card["source_issue"]
                    elif len(prompt.encode("utf-8")) > sections.CONTEXT_MAX_BYTES:
                        record["cause"] = "context_too_large"
                    else:
                        metadata = {}
                        call_deadline = min(deadline, time.monotonic() + max(0.01, runtime.REPORT_SECTION_TIMEOUT))
                        try:
                            self.tracker.check_budget()
                            result = self.provider.chat_with_tools(
                                system_prompt=prompt, user_message="Rédige uniquement cette section maintenant.",
                                tools=[], max_turns=1, max_tokens=token_limit,
                                cost_tracker=self.tracker,
                                stream_callback=self._model_stream_callback(
                                    stream_callback, phase=config.phase, agent=f"report_{card['key']}"),
                                repeat_guard=False, stop_event=self._stop_event, deadline=call_deadline,
                                completion_metadata=metadata,
                            )
                            text = str(result).strip() if result else ""
                            record["finish_reason"] = metadata.get("finish_reason")
                            record["draft"] = text
                            if text:
                                self._model_stream_callback(None, phase=config.phase, agent=f"report_{card['key']}")(
                                    {"type": "text_chunk", "text": text})
                            if stopped():
                                record["cause"] = "stopped"
                            elif time.monotonic() > call_deadline:
                                record["cause"] = "timeout"
                            elif metadata.get("finish_reason") == "length":
                                record["cause"] = "memo_truncated"
                            elif metadata.get("finish_reason") not in (None, "stop"):
                                record["cause"] = "memo_incomplete"
                            elif not text or text in {"(max turns reached)", "(malformed tool call JSON — max retries)"}:
                                record["cause"] = "memo_empty"
                            elif (len(text) > sections.NOTE_MAX_CHARS or _looks_unusable_model_memo(text)
                                  or _local_report_memo_contradicts_context(text, {})):
                                record["cause"] = "memo_rejected"
                            else:
                                record.update(status="usable", cause="none", text=text,
                                              text_digest=sections.digest(text))
                        except BudgetExceeded as exc:
                            pending_budget_error = exc
                            record["cause"] = "budget_exceeded"
                        except Exception as exc:
                            record["cause"] = ("stopped" if stopped() else "timeout" if
                                isinstance(exc, TimeoutError) or "timeout" in type(exc).__name__.lower()
                                or time.monotonic() > call_deadline else "provider_error")
                    sections.write_object(self.run_dir, filename, record)
                entry = {"key": card["key"], "kind": card["kind"], "artifact": filename,
                         "fingerprint": fingerprint, "facts_digest": sections.digest(card),
                         "status": record["status"], "cause": record["cause"], "reused": reused,
                         "finish_reason": record.get("finish_reason")}
                manifest["sections"].append(entry)
                sections.write_object(self.run_dir, sections.MANIFEST, manifest)
                if stream_callback:
                    stream_callback({"type": "report_section", "phase": 6, **entry})
                if card["kind"] == "summary" and record["status"] == "usable" and not stopped():
                    summary_text = record["text"]
                    note_path.write_text(summary_text + "\n", encoding="utf-8")
            failures = [e["cause"] for e in manifest["sections"] if e["status"] != "usable"]
            cause = ("budget_exceeded" if pending_budget_error is not None else
                     "stopped" if stopped() else failures[0] if failures else "none")
        except Exception as exc:
            cause, phase_error = "section_assembly_error", type(exc).__name__
            log.exception("Phase 6 section assembly failed")
        finally:
            final_valid, validation_message = False, "report_not_rendered"
            try:
                cards_text = sections.render_cards(self.run_dir, manifest)
                (self.run_dir / "06_report_cards.md").write_text(cards_text, encoding="utf-8")
                (self.run_dir / "06_report_intrusion_cards.md").write_text(
                    sections.render_cards(self.run_dir, manifest, intrusion=True), encoding="utf-8")
                report_rendering.render_deterministic_report(
                    self.run_dir, self.context, model=self.provider.model,
                    validate_report=self._validator("report_markdown"),
                    analysis_status="usable" if summary_text else "unavailable", analysis_cause=cause,
                )
                final_valid, validation_message = self._validator("final_report_markdown")(config.deliverable_file)
            except Exception as exc:
                validation_message = f"render_error:{type(exc).__name__}"
                log.exception("Phase 6 deterministic rendering failed")
            self.tracker.record_validation_result(success=final_valid)
            usage = self.tracker.end_phase()
            if pending_budget_error is not None:
                status, cause = "budget_exceeded", "budget_exceeded"
            elif stopped():
                status, cause = "stopped", "stopped"
            elif not final_valid or phase_error:
                status = f"failed:{validation_message if not final_valid else cause}"
            else:
                status = "completed" if cause == "none" else f"partial:{cause}"
            self._update_run_meta({
                "phase6_status": status, "phase6_cause": cause, "phase6_error": phase_error,
                "phase6_report_contract": "sectioned-report", "phase6_llm": "independent_sections",
                "phase6_note_status": "usable" if summary_text else "unavailable",
                "phase6_analysis": "06_report_analysis.md" if summary_text else None,
                "phase6_sections": sections.MANIFEST, "phase6_section_count": len(manifest["sections"]),
                "phase6_sections_usable": sum(e["status"] == "usable" for e in manifest["sections"]),
                "phase6_finish_reason": manifest["sections"][-1].get("finish_reason") if manifest["sections"] else None,
                "phase6_timeout_s": phase_timeout, "phase6_report_validation": validation_message,
            })
            if stream_callback:
                stream_callback({"type": "phase_done", "phase": config.phase, "name": config.name,
                                 "status": status, "deliverable": config.deliverable_file,
                                 "cost_usd": round(usage.cost_usd(), 4) if usage else 0,
                                 "turns": usage.turns if usage else 0})
        if pending_budget_error is not None:
            raise pending_budget_error
        return status


def run(context, config, stream_callback=None):
    return context._run_local_report_phase(config, stream_callback)
