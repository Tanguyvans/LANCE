"""Baseline runner contracts without live providers, tools or networks."""
from __future__ import annotations

import json
import fcntl
import signal
import threading
import time

import pytest

from src.agent.core import runtime
from src.agent import cost_tracker
from src.agent.cost_tracker import BudgetExceeded
from src.agent.run_modes import SCRIPT_IDS, _baseline_nmap, main, make_runner, validate_target_network


@pytest.fixture(autouse=True)
def _offline_pricing(monkeypatch):
    monkeypatch.setattr(cost_tracker, "get_dynamic_pricing", lambda model: None)


def _tool(name, fn):
    return {"name": name, "description": name, "input_schema": {"type": "object"},
            "function": fn}


class _Provider:
    provider = "mock"
    model = "mock-model"

    def __init__(self, call):
        self.call = call

    def chat_with_tools(self, **kwargs):
        return self.call(kwargs)


@pytest.mark.parametrize("bad", [None, "", "192.168.1.5", "192.168.1.5/24",
                                       "0.0.0.0/0", "::1/128", "127.0.0.0/24",
                                       "192.168.1.0/24 10.0.0.0/24"])
def test_baselines_reject_ambiguous_or_broad_scope(tmp_path, bad):
    with pytest.raises(ValueError):
        make_runner("scripted", target_network=bad, script_id="discovery-v1",
                    output_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


def test_public_scope_validator_and_script_catalog():
    assert str(validate_target_network("192.168.100.0/24")) == "192.168.100.0/24"
    assert SCRIPT_IDS == {"discovery-v1", "smoke-v1"}


@pytest.mark.parametrize("kwargs", [
    {"script_id": None}, {"script_id": "unlisted-v1"},
    {"script_id": "discovery-v1", "scenario_id": "S1"},
    {"script_id": "discovery-v1", "execution_profile": "full"},
    {"script_id": "discovery-v1", "provider": object()},
])
def test_scripted_rejects_harness_or_unlisted_options(tmp_path, kwargs):
    with pytest.raises(ValueError):
        make_runner("scripted", target_network="192.168.100.0/24",
                    output_dir=tmp_path, **kwargs)
    assert list(tmp_path.iterdir()) == []


def test_scripted_run_archives_observation_and_terminal_event(tmp_path, monkeypatch):
    calls = []

    def discovery(run, name, args):
        calls.append((name, args))
        return json.dumps({"stdout": "Nmap scan report for 192.168.100.2\nNmap done: 256 IP addresses (1 host up)",
                           "stderr": "", "return_code": 0})

    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr("src.agent.run_modes._baseline_nmap", discovery)
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    events = []
    assert runner.run(stream_callback=events.append) == {"scripted": "completed"}
    assert calls == [("nmap_discovery", {"target": "192.168.100.0/24"})]
    metadata = json.loads((runner.run_dir / "run_meta.json").read_text())
    evidence = [json.loads(line) for line in (runner.run_dir / "tool_calls.jsonl").read_text().splitlines()]
    assert metadata["runner_kind"] == "scripted"
    assert metadata["script_id"] == "discovery-v1"
    assert metadata["status"] == "completed"
    assert metadata["total_tool_calls"] == 1
    assert evidence[0]["tool"] == "nmap_discovery"
    assert evidence[0]["args"] == {"target": "192.168.100.0/24"}
    assert (runner.run_dir / "cost_summary.json").exists()
    assert (runner.run_dir / "run_summary.md").exists()
    assert "Discovered hosts reported by nmap: 1" in (runner.run_dir / "run_summary.md").read_text()
    assert events[0]["type"] == "runner_started"
    assert events[0]["target_network"] == "192.168.100.0/24"
    assert any(event.get("type") == "tool_result" and event.get("name") == "nmap_discovery"
               for event in events)
    assert events[-2]["type"] == "runner_done" and events[-2]["status"] == "completed"
    assert events[-1]["type"] == "pipeline_done"


def test_smoke_script_completes_without_network_model_or_lab(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline smoke test must not use tools or the laboratory")

    monkeypatch.setattr("src.agent.run_modes.reserve_lab", forbidden)
    monkeypatch.setattr("src.agent.run_modes._tool_catalog", forbidden)
    runner = make_runner("scripted", script_id="smoke-v1", output_dir=tmp_path)
    events = []
    assert runner.run(stream_callback=events.append) == {"scripted": "completed"}
    meta = json.loads((runner.run_dir / "run_meta.json").read_text())
    assert meta["script_id"] == "smoke-v1"
    assert meta["target_network"] is None
    assert meta["status"] == "completed"
    assert meta["total_tool_calls"] == 0
    assert meta["max_tool_calls"] == 0
    assert not (runner.run_dir / "tool_calls.jsonl").exists()
    assert "This is not an audit result" in (runner.run_dir / "run_summary.md").read_text()
    assert (runner.run_dir / "cost_summary.json").exists()
    assert [event["type"] for event in events] == [
        "runner_started", "script_step", "runner_done", "pipeline_done",
    ]


@pytest.mark.parametrize("kwargs", [
    {"target_network": "192.168.100.0/24"}, {"max_tool_calls": 1},
    {"max_cost_usd": 1.0}, {"provider": object()},
])
def test_smoke_script_rejects_network_and_unused_budgets(tmp_path, kwargs):
    with pytest.raises(ValueError):
        make_runner("scripted", script_id="smoke-v1", output_dir=tmp_path, **kwargs)
    assert list(tmp_path.iterdir()) == []


def test_cli_smoke_without_cidr_creates_offline_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(runtime, "OUTPUT_DIR", tmp_path)
    assert main(["scripted", "--script-id", "smoke-v1"]) == 0
    run_dir = next(tmp_path.iterdir())
    assert str(run_dir) in capsys.readouterr().out
    assert json.loads((run_dir / "run_meta.json").read_text())["status"] == "completed"
    with pytest.raises(SystemExit) as exc:
        main(["scripted", "--script-id", "smoke-v1", "--target-network", "192.0.2.0/24"])
    assert exc.value.code == 2


def test_vanilla_uses_one_provider_loop_and_rejects_outside_targets(tmp_path, monkeypatch):
    touched = []
    monkeypatch.setattr(runtime, "RECON_TOOLS", [
        _tool("nmap_discovery", lambda **kwargs: touched.append(kwargs) or "{}")
    ])
    monkeypatch.setattr("src.agent.run_modes._baseline_nmap",
                        lambda *args: touched.append(args) or "{}")

    def model(kwargs):
        assert kwargs["max_turns"] <= 30
        tool = kwargs["tools"][0]["function"]
        refusal = json.loads(tool(target="192.168.88.0/24"))
        assert refusal["error_kind"] == "intrusion_target_out_of_scope"
        assert touched == []
        return "No in-scope observations."

    runner = make_runner("vanilla", provider=_Provider(model),
                         target_network="192.168.100.0/24", output_dir=tmp_path)
    with pytest.raises(RuntimeError, match="No usable"):
        runner.run()
    metadata = json.loads((runner.run_dir / "run_meta.json").read_text())
    assert metadata["model"] == "mock-model" and metadata["provider"] == "mock"
    assert metadata["status"] == "failed"
    assert touched == []
    assert "intrusion_target_out_of_scope" in (runner.run_dir / "tool_calls.jsonl").read_text()


def test_tool_budget_stops_vanilla_before_second_execution(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runtime, "RECON_TOOLS", [
        _tool("nmap_discovery", lambda **kwargs: None)
    ])
    monkeypatch.setattr("src.agent.run_modes._baseline_nmap", lambda *args: calls.append(args) or json.dumps({
        "stdout": "Nmap done: 256 IP addresses (0 hosts up)", "stderr": "", "return_code": 0,
    }))

    def model(kwargs):
        tool = kwargs["tools"][0]["function"]
        tool(target="192.168.100.0/24")
        with pytest.raises(BudgetExceeded):
            tool(target="192.168.100.0/24")
        return "Stopped by budget."

    runner = make_runner("vanilla", provider=_Provider(model),
                         target_network="192.168.100.0/24", max_tool_calls=1,
                         output_dir=tmp_path)
    assert runner.run() == {"vanilla": "budget_exceeded"}
    assert len(calls) == 1
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "budget_exceeded"


def test_script_failure_persists_failed_terminal(tmp_path, monkeypatch):
    def broken(*args):
        raise RuntimeError("simulated tool failure")

    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr("src.agent.run_modes._baseline_nmap", broken)
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    events = []
    with pytest.raises(RuntimeError, match="simulated"):
        runner.run(stream_callback=events.append)
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "failed"
    assert events[-2]["type"] == "runner_done" and events[-2]["status"] == "failed"
    assert (runner.run_dir / "cost_summary.json").exists()


def test_stop_while_waiting_for_lab_persists_terminal(tmp_path, monkeypatch):
    from src.benchmark import lab_lock

    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: "{}")])

    class _Waiting:
        def __enter__(self):
            raise lab_lock.LabWaitCancelled("cancelled")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr("src.agent.run_modes.reserve_lab", lambda **kwargs: _Waiting())
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    events = []
    assert runner.run(stream_callback=events.append, stop_event=threading.Event()) == {
        "scripted": "stopped"
    }
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "stopped"
    assert events[-2]["type"] == "runner_done" and events[-2]["status"] == "stopped"
    assert not (runner.run_dir / "tool_calls.jsonl").exists()


def test_lab_wait_counts_toward_simple_run_deadline(tmp_path, monkeypatch):
    path = tmp_path / "lab.lock"
    monkeypatch.setenv("LANCE_LAB_LOCK", str(path))
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    with path.open("a+") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        runner = make_runner("scripted", target_network="192.168.100.0/24",
                             script_id="discovery-v1", max_duration_s=0.04, output_dir=tmp_path)
        events = []
        assert runner.run(stream_callback=events.append) == {"scripted": "budget_exceeded"}
        assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "budget_exceeded"
        assert events[-2]["type"] == "runner_done" and events[-2]["status"] == "budget_exceeded"
        assert not (runner.run_dir / "tool_calls.jsonl").exists()


def test_baseline_nmap_disables_dns_and_uses_remaining_deadline(tmp_path, monkeypatch):
    commands = []

    def cooperative(command, *, timeout):
        commands.append((command, timeout))
        return "Nmap done: 256 IP addresses (0 hosts up)", "", 0, False, False

    monkeypatch.setattr("src.agent.run_modes.run_cooperatively", cooperative)
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    runner._deadline = time.monotonic() + 0.05
    discovery = json.loads(_baseline_nmap(runner, "nmap_discovery", {"target": "192.168.100.0/24"}))
    assert discovery["return_code"] == 0
    assert discovery["argv"] == ["nmap", "-n", "-sn", "192.168.100.0/24"]
    assert commands[0][0] == ["nmap", "-n", "-sn", "192.168.100.0/24"]
    assert 0 < commands[0][1] <= 0.05
    _baseline_nmap(runner, "nmap_scan", {"target": "192.168.100.2", "ports": "22,80"})
    assert commands[1][0] == ["nmap", "-n", "-sV", "-T4", "--max-retries=1",
                              "-p", "22,80", "192.168.100.2"]


def test_nmap_output_is_bounded_without_losing_completion_or_host_count(tmp_path, monkeypatch):
    output = ("Nmap scan report for 192.168.100.2\n" * 2
              + "x" * 5000 + "\nNmap done: 256 IP addresses (2 hosts up)")
    monkeypatch.setattr("src.agent.run_modes.run_cooperatively",
                        lambda command, *, timeout: (output, "e" * 2000, 0, False, False))
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    runner._deadline = time.monotonic() + 1
    result = json.loads(_baseline_nmap(runner, "nmap_discovery", {"target": "192.168.100.0/24"}))
    assert len(result["stdout"]) == 4000 and result["stdout_truncated"] is True
    assert len(result["stderr"]) == 1000 and result["stderr_truncated"] is True
    assert result["scan_completed"] is True
    assert result["discovered_hosts"] == 2


def test_cancelled_script_discovery_is_stopped_after_evidence(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr("src.agent.run_modes.run_cooperatively",
                        lambda command, *, timeout: ("", "cancelled", -2, False, True))
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    events = []
    assert runner.run(stream_callback=events.append, stop_event=threading.Event()) == {
        "scripted": "stopped"
    }
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "stopped"
    assert (runner.run_dir / "tool_calls.jsonl").exists()
    assert events[-2]["status"] == "stopped"


def test_nmap_timeout_at_run_deadline_is_budget_exceeded(tmp_path, monkeypatch):
    observed = []
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])

    def timed_out(command, *, timeout):
        observed.append(timeout)
        return "", "timed out", -1, True, False

    monkeypatch.setattr("src.agent.run_modes.run_cooperatively", timed_out)
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", max_duration_s=0.05, output_dir=tmp_path)
    assert runner.run() == {"scripted": "budget_exceeded"}
    assert observed and observed[0] <= 0.05
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "budget_exceeded"


def test_vanilla_nmap_deadline_marker_survives_provider_tool_handling(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr("src.agent.run_modes.run_cooperatively",
                        lambda command, *, timeout: ("", "timed out", -1, True, False))

    def model(kwargs):
        tool = kwargs["tools"][0]["function"]
        try:
            tool(target="192.168.100.0/24")
        except BudgetExceeded:
            pass  # Model loop may catch a tool error before returning.
        return "No observation."

    runner = make_runner("vanilla", provider=_Provider(model),
                         target_network="192.168.100.0/24", max_duration_s=1,
                         output_dir=tmp_path)
    assert runner.run() == {"vanilla": "budget_exceeded"}
    evidence = json.loads((runner.run_dir / "tool_calls.jsonl").read_text().splitlines()[0])
    assert json.loads(evidence["result"])["deadline_exceeded"] is True
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "budget_exceeded"


@pytest.mark.parametrize("at_deadline,expected", [(True, "budget_exceeded"), (False, "failed")])
def test_provider_timeout_only_counts_as_budget_at_run_deadline(tmp_path, monkeypatch,
                                                                 at_deadline, expected):
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    runner = None

    def model(kwargs):
        if at_deadline:
            runner._deadline = time.monotonic() - 1
        raise TimeoutError("simulated provider timeout")

    runner = make_runner("vanilla", provider=_Provider(model),
                         target_network="192.168.100.0/24", output_dir=tmp_path)
    if at_deadline:
        assert runner.run() == {"vanilla": "budget_exceeded"}
    else:
        with pytest.raises(TimeoutError, match="simulated"):
            runner.run()
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == expected


@pytest.mark.parametrize("payload", [
    {"stdout": "", "stderr": "nmap failed", "return_code": -1},
    {"stdout": "", "stderr": "", "return_code": 0},
])
def test_scripted_nmap_errors_or_empty_output_never_complete(tmp_path, monkeypatch, payload):
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr("src.agent.run_modes._baseline_nmap", lambda *args: json.dumps(payload))
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)
    with pytest.raises(RuntimeError):
        runner.run()
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "failed"


def test_unavailable_nmap_never_completes_vanilla(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    monkeypatch.setattr(runtime, "filter_unavailable_tools",
                        lambda tools: ([], {"nmap_discovery": "missing_command:nmap"}))
    runner = make_runner("vanilla", provider=_Provider(lambda kwargs: "unsupported"),
                         target_network="192.168.100.0/24", output_dir=tmp_path)
    with pytest.raises(RuntimeError, match="No baseline"):
        runner.run()
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("status,expected", [("completed", 0), ("stopped", 2),
                                              ("budget_exceeded", 3), ("failed", 1)])
def test_cli_exit_status_reflects_terminal_result(tmp_path, monkeypatch, capsys, status, expected):
    class FakeRunner:
        run_dir = tmp_path

        def run(self, stop_event=None):
            assert isinstance(stop_event, threading.Event)
            return {"scripted": status}

    monkeypatch.setattr("src.agent.run_modes.make_runner", lambda *args, **kwargs: FakeRunner())
    assert main(["scripted", "--target-network", "192.168.100.0/24",
                 "--script-id", "discovery-v1"]) == expected
    assert str(tmp_path) in capsys.readouterr().out


def test_cli_failure_exception_returns_nonzero(tmp_path, monkeypatch, capsys):
    class FakeRunner:
        run_dir = tmp_path

        def run(self, stop_event=None):
            raise RuntimeError("failure")

    monkeypatch.setattr("src.agent.run_modes.make_runner", lambda *args, **kwargs: FakeRunner())
    assert main(["scripted", "--target-network", "192.168.100.0/24",
                 "--script-id", "discovery-v1"]) == 1
    assert "Run failed: RuntimeError" in capsys.readouterr().err


@pytest.mark.parametrize("signum", [signal.SIGINT, signal.SIGTERM])
def test_cli_signals_request_cooperative_stop_and_restore_handler(tmp_path, monkeypatch,
                                                                  signum):
    previous = signal.getsignal(signum)

    class FakeRunner:
        run_dir = tmp_path

        def run(self, stop_event=None):
            assert stop_event is not None and not stop_event.is_set()
            handler = signal.getsignal(signum)
            assert callable(handler)
            handler(signum, None)
            assert stop_event.is_set()
            return {"scripted": "stopped"}

    monkeypatch.setattr("src.agent.run_modes.make_runner", lambda *args, **kwargs: FakeRunner())
    assert main(["scripted", "--target-network", "192.168.100.0/24",
                 "--script-id", "discovery-v1"]) == 2
    assert signal.getsignal(signum) == previous


def test_cli_signal_during_lab_wait_finalizes_run(tmp_path, monkeypatch):
    from src.benchmark.lab_lock import LabWaitCancelled
    from src.agent import run_modes

    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)

    class InterruptedWait:
        def __enter__(self):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            raise LabWaitCancelled("stopped while waiting")

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(run_modes, "reserve_lab", lambda **kwargs: InterruptedWait())
    monkeypatch.setattr(run_modes, "make_runner", lambda *args, **kwargs: runner)
    assert main(["scripted", "--target-network", "192.168.100.0/24",
                 "--script-id", "discovery-v1"]) == 2
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "stopped"


def test_cli_signal_reaches_active_nmap_and_archives_stop(tmp_path, monkeypatch):
    from src.agent import run_modes
    from src.agent.tools.runtime import get_tool_stop_event

    monkeypatch.setattr(runtime, "RECON_TOOLS", [_tool("nmap_discovery", lambda **kwargs: None)])
    runner = make_runner("scripted", target_network="192.168.100.0/24",
                         script_id="discovery-v1", output_dir=tmp_path)

    def cooperative(command, *, timeout):
        active_stop = get_tool_stop_event()
        assert active_stop is not None and not active_stop.is_set()
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        assert active_stop.is_set()
        return "", "cancelled", -2, False, True

    monkeypatch.setattr(run_modes, "run_cooperatively", cooperative)
    monkeypatch.setattr(run_modes, "make_runner", lambda *args, **kwargs: runner)
    assert main(["scripted", "--target-network", "192.168.100.0/24",
                 "--script-id", "discovery-v1"]) == 2
    assert json.loads((runner.run_dir / "run_meta.json").read_text())["status"] == "stopped"
    evidence = json.loads((runner.run_dir / "tool_calls.jsonl").read_text().splitlines()[0])
    assert json.loads(evidence["result"])["cancelled"] is True
