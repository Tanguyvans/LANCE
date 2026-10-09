"""Independent entry points for the LANCE harness and bounded baseline runners.

The baseline runners deliberately expose only structured, scoped reconnaissance
tools. They share the pipeline's destination guard, evidence log, cost tracker,
cooperative cancellation and laboratory reservation.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import math
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

from src.agent.core import runtime
from src.agent.core.executor import RunStopped, wrap_tool
from src.agent.cost_tracker import BudgetExceeded, CostTracker
from src.agent.phases.intrusion.scope import _intrusion_scope_violation
from src.agent.tools.runtime import run_cooperatively, tool_stop_context
from src.benchmark.lab_lock import LabWaitCancelled, LabWaitDeadlineExceeded, reserve_lab


SCRIPT_IDS = frozenset({"discovery-v1", "smoke-v1"})
_SIMPLE_TOOL_NAMES = frozenset({"nmap_discovery", "nmap_scan"})
_PORTS = re.compile(r"[0-9,-]+\Z")
log = logging.getLogger(__name__)


def validate_target_network(value: str | None) -> ipaddress.IPv4Network:
    if (not isinstance(value, str) or not value.strip() or value != value.strip()
            or "/" not in value):
        raise ValueError("An explicit authorized IPv4 CIDR is required")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("target_network must be one canonical IPv4 CIDR") from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen < 16:
        raise ValueError("target_network must be an IPv4 CIDR of /16 or narrower")
    if network.is_multicast or network.is_unspecified or network.is_loopback:
        raise ValueError("target_network is not an auditable network")
    return network


def _target_in_scope(value: object, network: ipaddress.IPv4Network, *, address_only=False) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or any(c.isspace() for c in value):
        raise ValueError("Target must be one explicit IP or CIDR")
    try:
        target = ipaddress.ip_address(value) if address_only else ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError("Target must be one explicit IP or CIDR") from exc
    if not isinstance(target, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
        raise ValueError("Only IPv4 targets are supported")
    outside = target not in network if address_only else not target.subnet_of(network)
    if outside:
        raise ValueError("Target is outside the authorized CIDR")
    return value


def _checked_args(name: str, args: dict, network: ipaddress.IPv4Network) -> dict:
    """Reject model-supplied options outside the small baseline tool contract."""
    if not isinstance(args, dict):
        raise ValueError("Tool arguments must be an object")
    if name == "nmap_discovery":
        if set(args) != {"target"}:
            raise ValueError("nmap_discovery accepts only target")
        return {"target": _target_in_scope(args["target"], network)}
    if name == "nmap_scan":
        if not {"target"} <= set(args) or set(args) - {"target", "ports"}:
            raise ValueError("nmap_scan accepts only target and ports")
        checked = {"target": _target_in_scope(args["target"], network, address_only=True)}
        if "ports" in args:
            ports = args["ports"]
            if not isinstance(ports, str) or not _PORTS.fullmatch(ports) or len(ports) > 128:
                raise ValueError("Invalid port list")
            for part in ports.split(","):
                numbers = part.split("-")
                if len(numbers) > 2 or any(not n or not 1 <= int(n) <= 65535 for n in numbers):
                    raise ValueError("Invalid port list")
                if len(numbers) == 2 and int(numbers[0]) > int(numbers[1]):
                    raise ValueError("Invalid port range")
            checked["ports"] = ports
        return checked
    raise ValueError("Tool is not available in baseline runners")


def _baseline_nmap(run: "SimpleRunner", name: str, args: dict) -> str:
    """Execute a fixed argv with DNS disabled and the remaining run budget."""
    remaining = run._deadline - time.monotonic()
    if remaining <= 0:
        raise BudgetExceeded("Elapsed-time budget exhausted")
    if name == "nmap_discovery":
        command = ["nmap", "-n", "-sn", args["target"]]
        tool_timeout = 30.0
    elif name == "nmap_scan":
        command = ["nmap", "-n", "-sV", "-T4", "--max-retries=1"]
        if "ports" in args:
            command.extend(["-p", args["ports"]])
        command.append(args["target"])
        tool_timeout = 300.0
    else:
        raise ValueError("Unsupported baseline tool")
    deadline_limited = remaining <= tool_timeout
    stdout, stderr, return_code, timed_out, cancelled = run_cooperatively(
        command, timeout=min(tool_timeout, remaining),
    )
    # Retain the completion marker and count before limiting evidence size.
    # An nmap summary with zero hosts is still a valid negative observation.
    scan_completed = "Nmap done:" in stdout
    discovered_hosts = sum(line.startswith("Nmap scan report for ")
                           for line in stdout.splitlines())
    stdout_truncated = len(stdout) > 4000
    stderr_truncated = len(stderr) > 1000
    return json.dumps({
        "stdout": stdout[:4000], "stderr": stderr[:1000],
        "stdout_truncated": stdout_truncated, "stderr_truncated": stderr_truncated,
        "scan_completed": scan_completed, "discovered_hosts": discovered_hosts,
        "return_code": return_code,
        "timed_out": timed_out, "cancelled": cancelled,
        "deadline_exceeded": timed_out and deadline_limited,
        "argv": command,
    })


def _nmap_observation(result: object) -> bool:
    """An exit code alone does not prove any usable scan observation."""
    try:
        payload = json.loads(result) if isinstance(result, str) else result
    except (TypeError, ValueError):
        return False
    return bool(
        isinstance(payload, dict)
        and payload.get("return_code") == 0
        and not payload.get("error")
        and isinstance(payload.get("stdout"), str)
        and (payload.get("scan_completed") is True or "Nmap done:" in payload["stdout"])
    )


def _tool_catalog(run: "SimpleRunner") -> list[dict]:
    candidates = [tool for tool in runtime.RECON_TOOLS if tool["name"] in _SIMPLE_TOOL_NAMES]
    filtered, unavailable = runtime.filter_unavailable_tools(candidates)
    run.runtime_unavailable_tools = unavailable
    available = {tool["name"]: tool for tool in filtered}
    tools = []
    for name in ("nmap_discovery", "nmap_scan"):
        source = available.get(name)
        if source is None or not callable(source.get("function")):
            continue
        def checked_call(*, _name=name, **kwargs):
            checked = _checked_args(_name, kwargs, run.network)
            # Keep the existing application destination guard as an independent
            # defence if a future tool schema is broadened.
            refusal = _intrusion_scope_violation(_name, checked, str(run.network))
            if refusal is not None:
                return json.dumps(refusal)
            return _baseline_nmap(run, _name, checked)

        schema = {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
            "additionalProperties": False,
        }
        if name == "nmap_scan":
            schema["properties"]["ports"] = {"type": "string", "description": "Comma-separated TCP ports or ranges"}
        narrow = {**source, "description": {
            "nmap_discovery": "Find live hosts in the authorized CIDR with nmap -sn.",
            "nmap_scan": "Inspect TCP services on one in-scope IPv4 address; optional ports.",
        }[name], "input_schema": schema, "function": checked_call}
        wrapped = wrap_tool(run, narrow, phase="baseline", agent=run.runner_kind,
                            decision_source=run.runner_kind)
        executor = wrapped["function"]

        def with_stop(*, _executor=executor, **kwargs):
            with tool_stop_context(run._stop_event):
                result = _executor(**kwargs)
            # The shared wrapper has already archived this result. Preserve
            # the process-level reason before the provider can turn it into a
            # generic tool error or a no-observation result.
            try:
                payload = json.loads(result) if isinstance(result, str) else result
            except (TypeError, ValueError):
                payload = None
            if isinstance(payload, dict) and payload.get("cancelled"):
                raise RunStopped("Run stopped")
            if isinstance(payload, dict) and payload.get("deadline_exceeded"):
                run._execution_limit_reason = "Elapsed-time budget exhausted"
                raise BudgetExceeded(run._execution_limit_reason)
            if _nmap_observation(result):
                run._usable_observations += 1
            return result

        tools.append({**wrapped, "function": with_stop})
    return tools


class SimpleRunner:
    """One independent run with the same evidence boundary as the harness."""

    def __init__(self, *, kind: str, provider, network: ipaddress.IPv4Network | None,
                 script_id: str | None, max_cost_usd: float | None,
                 max_tool_calls: int, max_duration_s: float,
                 output_dir: Path | None):
        self.runner_kind = kind
        self.provider = provider
        self.network = network
        self.target_network = str(network) if network is not None else None
        self.script_id = script_id
        self.benchmark_split = "unassigned"
        self.experiment_scope = "baseline"
        self.decision_policy = kind
        self.max_tool_calls = max_tool_calls
        self.max_duration_s = max_duration_s
        self.max_cost_usd = max_cost_usd
        self._tool_call_count = 0
        self._usable_observations = 0
        self._artifact_log_lock = threading.Lock()
        self._stop_event = None
        self._execution_limit_reason = None
        self._evidence_integrity_failed = False
        self.context = {"target_subnet": str(network)} if network is not None else {}
        self.tracker = CostTracker(model=getattr(provider, "model", ""),
                                   provider=getattr(provider, "provider", ""),
                                   max_cost_usd=max_cost_usd)
        self.tracker.execution_metrics = True
        root = Path(output_dir if output_dir is not None else runtime.OUTPUT_DIR).resolve()
        root.mkdir(parents=True, exist_ok=True)
        self.run_dir = root / f"{datetime.now():%Y-%m-%d_%H%M%S}_{uuid4().hex[:12]}"
        self.run_dir.mkdir()

    def _metadata(self, status: str, **extra) -> dict:
        meta = {
            "runner_kind": self.runner_kind,
            "status": status,
            "target_network": self.target_network,
            "benchmark_split": self.benchmark_split,
            "max_cost_usd": self.max_cost_usd,
            "max_tool_calls": self.max_tool_calls,
            "max_duration_s": self.max_duration_s,
            "git_commit": runtime._get_git_commit(),
            "started_at": self.started_at,
        }
        if self.runner_kind == "scripted":
            meta["script_id"] = self.script_id
        else:
            meta.update(model=getattr(self.provider, "model", None),
                        provider=getattr(self.provider, "provider", None))
        meta.update(extra)
        return meta

    def _write_meta(self, status: str, **extra) -> None:
        (self.run_dir / "run_meta.json").write_text(
            json.dumps(self._metadata(status, **extra), indent=2), encoding="utf-8")

    def run(self, stream_callback=None, stop_event=None) -> dict[str, str]:
        self._stop_event = stop_event
        self._run_started = time.monotonic()
        self._deadline = self._run_started + self.max_duration_s
        self.started_at = datetime.now().astimezone().isoformat()
        self.tracker.start_run()
        self._finalized = False
        self._write_meta("waiting")
        if stream_callback:
            stream_callback({"type": "runner_started", "runner_kind": self.runner_kind,
                             "target_network": self.target_network,
                             "script_id": self.script_id,
                             "run_dir": str(self.run_dir)})
        try:
            if self.script_id == "smoke-v1":
                # A UI/API/CLI smoke test must not contend for or touch the lab.
                return self._run_reserved(stream_callback=stream_callback, stop_event=stop_event)
            with reserve_lab(stop_event=stop_event, callback=stream_callback,
                             deadline=self._deadline):
                return self._run_reserved(stream_callback=stream_callback, stop_event=stop_event)
        except LabWaitCancelled:
            result = {self.runner_kind: "stopped"}
            self._finalize("stopped", result, "Run stopped while waiting for the laboratory.",
                           stream_callback)
            return result
        except LabWaitDeadlineExceeded:
            result = {self.runner_kind: "budget_exceeded"}
            self._finalize("budget_exceeded", result,
                           "Run exceeded its time budget while waiting for the laboratory.",
                           stream_callback)
            return result
        except Exception:
            if not self._finalized:
                self._finalize("failed", {self.runner_kind: "failed"},
                               "Run failed before execution.", stream_callback)
            raise

    def _run_reserved(self, stream_callback=None, stop_event=None) -> dict[str, str]:
        status = "failed"
        result: dict[str, str] = {}
        detail = ""
        self._write_meta("running")
        try:
            if stop_event is not None and stop_event.is_set():
                raise RunStopped("Run stopped")
            tools = [] if self.script_id == "smoke-v1" else _tool_catalog(self)
            by_name = {tool["name"]: tool for tool in tools}
            if self.script_id == "smoke-v1":
                self.tracker.start_phase(self.runner_kind)
                try:
                    if stream_callback:
                        stream_callback({"type": "script_step", "script_id": self.script_id,
                                         "step": "checked", "message": "Mode hors ligne validé ; aucun scan lancé."})
                    detail = ("Procedure: smoke-v1.\n\n"
                              "Offline launch, event stream and artifact smoke test. "
                              "No network probe, model call or laboratory reservation was made. "
                              "This is not an audit result.")
                finally:
                    self.tracker.end_phase()
            elif self.runner_kind == "scripted":
                if "nmap_discovery" not in by_name:
                    raise RuntimeError("nmap_discovery is unavailable")
                self.tracker.start_phase(self.runner_kind)
                try:
                    observation = by_name["nmap_discovery"]["function"](target=self.target_network)
                    if stream_callback:
                        stream_callback({"type": "tool_result", "name": "nmap_discovery",
                                         "tool": "nmap_discovery",
                                         "result": observation})
                    parsed = json.loads(observation) if isinstance(observation, str) else observation
                    if ((stop_event is not None and stop_event.is_set())
                            or (isinstance(parsed, dict) and parsed.get("cancelled"))):
                        raise RunStopped("Run stopped")
                    if isinstance(parsed, dict) and parsed.get("deadline_exceeded"):
                        raise BudgetExceeded("Elapsed-time budget exhausted")
                    if isinstance(parsed, dict) and (parsed.get("error") or parsed.get("ok") is False
                                                     or parsed.get("return_code", 0) not in (0, None)):
                        raise RuntimeError("Discovery tool reported an error")
                    if not _nmap_observation(observation):
                        raise RuntimeError("Discovery produced no usable Nmap observation")
                    stdout = parsed.get("stdout", "") if isinstance(parsed, dict) else ""
                    host_count = parsed.get("discovered_hosts") if isinstance(parsed, dict) else None
                    if type(host_count) is not int or host_count < 0:
                        host_count = sum(line.startswith("Nmap scan report for ")
                                         for line in stdout.splitlines()) if isinstance(stdout, str) else 0
                    detail = (f"Procedure: {self.script_id}.\n\n"
                              f"Discovered hosts reported by nmap: {host_count}.\n\n"
                              "See tool_calls.jsonl for the underlying observations.")
                finally:
                    self.tracker.end_phase()
            else:
                if not tools:
                    raise RuntimeError("No baseline reconnaissance tools are available")
                self.tracker.start_phase(self.runner_kind)
                try:
                    detail = self.provider.chat_with_tools(
                        system_prompt=(
                            "You are a single security audit agent on an explicitly authorized IPv4 network. "
                            "Use only the provided read-only reconnaissance tools and stay inside the CIDR. "
                            "Report observations and uncertainty; do not claim exploitation or verified access."
                        ),
                        user_message=f"Inspect the authorized network {self.target_network} and summarize observed hosts and services.",
                        tools=tools,
                        max_turns=min(30, self.max_tool_calls + 2),
                        cost_tracker=self.tracker,
                        stop_event=stop_event,
                        deadline=self._deadline,
                        stream_callback=stream_callback,
                    )
                    if not isinstance(detail, str) or not detail.strip():
                        raise RuntimeError("Model returned no audit summary")
                finally:
                    self.tracker.end_phase()
            if stop_event is not None and stop_event.is_set():
                raise RunStopped("Run stopped")
            if self._execution_limit_reason:
                raise BudgetExceeded(self._execution_limit_reason)
            if self.script_id != "smoke-v1" and self._usable_observations == 0:
                raise RuntimeError("No usable in-scope Nmap observations were recorded")
            if time.monotonic() - self._run_started >= self.max_duration_s:
                raise BudgetExceeded("Elapsed-time budget exhausted")
            self.tracker.check_budget()
            status = "completed"
            result = {self.runner_kind: "completed"}
            return result
        except (RunStopped, KeyboardInterrupt):
            status = "stopped"
            detail = "Run stopped."
            result = {self.runner_kind: "stopped"}
            return result
        except BudgetExceeded:
            status = "budget_exceeded"
            detail = "Run stopped by its execution budget."
            result = {self.runner_kind: "budget_exceeded"}
            return result
        except TimeoutError:
            if time.monotonic() < self._deadline:
                detail = "Run failed (TimeoutError)."
                result = {self.runner_kind: "failed"}
                raise
            status = "budget_exceeded"
            detail = "Run stopped by its execution time budget."
            result = {self.runner_kind: "budget_exceeded"}
            return result
        except Exception as exc:
            detail = f"Run failed ({type(exc).__name__})."
            result = {self.runner_kind: "failed"}
            raise
        finally:
            self._finalize(status, result, detail, stream_callback)

    def _finalize(self, status: str, result: dict[str, str], detail: str,
                  stream_callback=None) -> None:
        self.tracker.finalize()
        (self.run_dir / "cost_summary.json").write_text(self.tracker.to_json(), encoding="utf-8")
        (self.run_dir / "run_summary.md").write_text(
            f"# {self.runner_kind.title()} run\n\n"
            f"Status: {status}\n\nTarget: {self.target_network or 'none (offline test)'}\n\n"
            f"{detail}\n", encoding="utf-8")
        self._write_meta(status, finished_at=datetime.now().astimezone().isoformat(),
                         total_cost_usd=self.tracker.total_cost(),
                         total_tool_calls=self._tool_call_count)
        self._finalized = True
        if stream_callback:
            terminal = {"runner_kind": self.runner_kind, "status": status,
                        "results": result, "run_dir": str(self.run_dir),
                        "total_cost_usd": self.tracker.total_cost()}
            stream_callback({"type": "runner_done", **terminal})
            stream_callback({"type": "pipeline_done", **terminal})


class LanceRunner:
    """Thin adapter retaining the existing Pipeline object and public API."""

    runner_kind = "lance"

    def __init__(self, pipeline):
        self.pipeline = pipeline

    def __getattr__(self, name):
        return getattr(self.pipeline, name)

    def _tag(self):
        updater = getattr(self.pipeline, "_update_run_meta", None)
        if callable(updater):
            try:
                updater({"runner_kind": "lance"})
            except Exception:
                log.warning("Could not tag LANCE run metadata", exc_info=True)

    def run(self, stream_callback=None, stop_event=None):
        self._tag()
        try:
            return self.pipeline.run(stream_callback=stream_callback, stop_event=stop_event)
        finally:
            self._tag()


@contextmanager
def _cli_stop_signals(stop_event: threading.Event):
    """Translate terminal interrupts into cooperative cancellation."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    previous = {}

    def request_stop(signum, frame):
        stop_event.set()

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, request_stop)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def make_runner(
    kind: str, *, provider=None, scenario_id=None, target_network=None,
    max_cost_usd=None, max_tool_calls=None, max_duration_s=None,
    execution_profile="auto", script_id=None, output_dir=None, **pipeline_kwargs,
):
    """Build one execution strategy; simple baselines require explicit scope."""
    if kind == "lance":
        if script_id is not None:
            raise ValueError("script_id applies only to scripted runs")
        from src.agent.pipeline import Pipeline
        pipeline = Pipeline(
            provider=provider, scenario_id=scenario_id,
            target_network=target_network, max_cost_usd=max_cost_usd,
            max_tool_calls=max_tool_calls, max_duration_s=max_duration_s,
            execution_profile=execution_profile, output_dir=output_dir,
            **pipeline_kwargs,
        )
        return LanceRunner(pipeline)
    if kind not in {"vanilla", "scripted"}:
        raise ValueError(f"Unknown runner kind: {kind!r}")
    if scenario_id is not None or pipeline_kwargs:
        raise ValueError("Simple runners do not deploy scenarios or accept harness settings")
    if execution_profile != "auto":
        raise ValueError("Execution profiles apply only to the LANCE harness")
    if kind == "scripted" and script_id == "smoke-v1":
        if target_network is not None:
            raise ValueError("smoke-v1 is offline and does not accept target_network")
        if max_tool_calls is not None or max_cost_usd is not None:
            raise ValueError("smoke-v1 does not use tools or a model budget")
        network = None
    else:
        network = validate_target_network(target_network)
    if kind == "scripted":
        if script_id not in SCRIPT_IDS:
            raise ValueError(f"script_id must be one of: {', '.join(sorted(SCRIPT_IDS))}")
        if provider is not None:
            raise ValueError("Scripted runs do not use a model provider")
        default_calls, default_duration = (0 if script_id == "smoke-v1" else 1), 120.0
    else:
        if provider is None or not callable(getattr(provider, "chat_with_tools", None)):
            raise ValueError("Vanilla runs require a model provider")
        if script_id is not None:
            raise ValueError("script_id applies only to scripted runs")
        default_calls, default_duration = 30, 600.0
    calls = default_calls if max_tool_calls is None else max_tool_calls
    duration = default_duration if max_duration_s is None else max_duration_s
    if script_id != "smoke-v1" and (type(calls) is not int or not 1 <= calls <= 100):
        raise ValueError("max_tool_calls must be between 1 and 100")
    if (not isinstance(duration, (int, float)) or isinstance(duration, bool)
            or not math.isfinite(duration) or not 0 < duration <= 3600):
        raise ValueError("max_duration_s must be between 0 and 3600")
    if max_cost_usd is not None and (not isinstance(max_cost_usd, (int, float))
                                     or isinstance(max_cost_usd, bool)
                                     or not math.isfinite(max_cost_usd) or max_cost_usd <= 0):
        raise ValueError("max_cost_usd must be positive")
    return SimpleRunner(kind=kind, provider=provider, network=network,
                        script_id=script_id, max_cost_usd=max_cost_usd,
                        max_tool_calls=calls, max_duration_s=float(duration),
                        output_dir=output_dir)


def main(argv=None) -> int:
    """Standalone CLI for baseline runs; it never provisions a scenario."""
    parser = argparse.ArgumentParser(description="Run a bounded LANCE baseline")
    parser.add_argument("kind", choices=["vanilla", "scripted"])
    parser.add_argument("--target-network", help="Explicit authorized IPv4 CIDR (not used by smoke-v1)")
    parser.add_argument("--script-id", choices=sorted(SCRIPT_IDS))
    parser.add_argument("--provider", default=os.environ.get("AGENT_PROVIDER"))
    parser.add_argument("--model", default=os.environ.get("AGENT_MODEL"))
    parser.add_argument("--max-cost-usd", type=float)
    parser.add_argument("--max-tool-calls", type=int)
    parser.add_argument("--max-duration-s", type=float)
    args = parser.parse_args(argv)
    try:
        if args.kind == "scripted" and args.script_id not in SCRIPT_IDS:
            raise ValueError(f"script_id must be one of: {', '.join(sorted(SCRIPT_IDS))}")
        if args.kind == "vanilla" and args.script_id is not None:
            raise ValueError("script_id applies only to scripted runs")
        if args.kind == "scripted" and args.script_id == "smoke-v1":
            if args.target_network is not None:
                raise ValueError("smoke-v1 is offline and does not accept target_network")
        else:
            validate_target_network(args.target_network)
    except ValueError as exc:
        parser.error(str(exc))
    provider = None
    if args.kind == "vanilla":
        if not args.provider:
            parser.error("vanilla requires --provider or AGENT_PROVIDER")
        from src.agent.provider import LLMProvider, validate_provider_choice
        validate_provider_choice(args.provider)
        provider = LLMProvider(provider=args.provider, model=args.model)
    try:
        runner = make_runner(
            args.kind, provider=provider, target_network=args.target_network,
            script_id=args.script_id, max_cost_usd=args.max_cost_usd,
            max_tool_calls=args.max_tool_calls, max_duration_s=args.max_duration_s,
        )
    except ValueError as exc:
        parser.error(str(exc))
    stop_event = threading.Event()
    try:
        with _cli_stop_signals(stop_event):
            result = runner.run(stop_event=stop_event)
    except Exception as exc:
        print(f"Run failed: {type(exc).__name__}", file=sys.stderr)
        print(runner.run_dir)
        return 1
    print(runner.run_dir)
    status = result.get(args.kind)
    return {"completed": 0, "stopped": 2, "budget_exceeded": 3}.get(status, 1)


if __name__ == "__main__":
    raise SystemExit(main())
