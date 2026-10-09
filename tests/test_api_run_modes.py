"""Dashboard runner selection and event handling without a laboratory."""
from __future__ import annotations

import asyncio
import queue
import sys
import threading
from types import ModuleType

import pytest
from pydantic import ValidationError

from src.api.routes import pipeline as route
from src.api.run_coordinator import RunCoordinator


def test_finish_sends_done_to_the_finished_runs_queue_after_new_start_interleaves():
    first_queue, next_queue = queue.Queue(), queue.Queue()

    class Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    state = {
        "running": True, "lab_waiting": False, "stopping": False,
        "loop": Loop(), "queue": first_queue,
    }

    class InterleavingLock:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            # A new run replaces the shared stream as soon as finish releases
            # the lock. Its queue must not receive the old terminal marker.
            state["queue"] = next_queue

    RunCoordinator(InterleavingLock()).finish(state)
    assert first_queue.get_nowait() == {"type": "__done__"}
    assert next_queue.empty()


@pytest.mark.parametrize("payload", [
    {"runner_kind": "scripted"},
    {"runner_kind": "scripted", "target_network": "127.0.0.0/24"},
    {"runner_kind": "scripted", "target_network": "127.0.0.0/24", "script_id": "unknown"},
    {"runner_kind": "vanilla", "provider": "local", "model": "test"},
    {"runner_kind": "scripted", "target_network": "127.0.0.1", "script_id": "discovery-v1"},
    {"runner_kind": "scripted", "target_network": "not-a-cidr/24", "script_id": "discovery-v1"},
    {"runner_kind": "scripted", "target_network": "127.0.0.0/24", "script_id": "discovery-v1"},
    {"runner_kind": "scripted", "target_network": "10.0.0.0/8", "script_id": "discovery-v1"},
    {"runner_kind": "scripted", "target_network": "192.168.1.1/24", "script_id": "discovery-v1"},
    {"runner_kind": "scripted", "target_network": "127.0.0.0/24", "script_id": "discovery-v1", "scenario_id": "1"},
    {"runner_kind": "scripted", "target_network": "127.0.0.0/24", "script_id": "discovery-v1", "provider": "local", "model": "test"},
    {"runner_kind": "scripted", "target_network": "192.168.1.0/24", "script_id": "discovery-v1", "execution_profile": "full"},
    {"runner_kind": "scripted", "target_network": "192.168.1.0/24", "script_id": "discovery-v1", "max_tool_calls": 101},
    {"runner_kind": "scripted", "target_network": "192.168.1.0/24", "script_id": "discovery-v1", "max_duration_s": 3601},
    {"runner_kind": "scripted", "target_network": "192.168.1.0/24", "script_id": "discovery-v1", "max_cost_usd": float("nan")},
    {"runner_kind": "vanilla", "target_network": "127.0.0.0/24"},
    {"runner_kind": "lance", "provider": "local", "model": "test", "max_tool_calls": 1},
])
def test_start_rejects_incomplete_or_mixed_runner_contracts(payload):
    with pytest.raises(ValidationError):
        route.StartRequest(**payload)


def test_start_accepts_script_without_provider_and_exposes_runner_kind(monkeypatch):
    snapshot = dict(route._state)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(route.threading, "Thread", NoopThread)
    route._state["running"] = False
    route._state["teardown_running"] = False
    try:
        req = route.StartRequest(
            runner_kind="scripted", target_network="192.168.1.0/24",
            script_id="discovery-v1", max_tool_calls=3, max_duration_s=10,
        )
        assert asyncio.run(route.start_pipeline(req)) == {"status": "started"}
        status = route.get_status()
        assert status["runner_kind"] == "scripted"
        assert status["execution_profile"] is None
        assert status["model"] is None
        assert status["phases_done"] == []
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_deploy_only_does_not_require_provider_or_model(monkeypatch):
    request = route.StartRequest(scenario_id="1", deploy_only=True)
    assert request.model is None
    assert request.provider is None
    snapshot = dict(route._state)

    class NoopThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            pass

    monkeypatch.setattr(route.threading, "Thread", NoopThread)
    route._state["running"] = False
    route._state["teardown_running"] = False
    try:
        assert asyncio.run(route.start_pipeline(request)) == {"status": "started"}
        assert route.get_status()["model"] is None
    finally:
        route._state.clear()
        route._state.update(snapshot)


def test_deploy_only_worker_does_not_construct_model_provider(monkeypatch):
    from src.agent import pipeline as agent_pipeline
    from src.agent import provider as agent_provider

    events = queue.Queue()

    class Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    class Pipeline:
        def __init__(self, *, provider, **kwargs):
            assert provider.model == ""

        def run_deploy_only(self, *, stream_callback, stop_event):
            stream_callback({"type": "pipeline_done", "status": "completed", "run_dir": "/tmp/deploy-fixture"})

    def forbid_provider(**kwargs):
        raise AssertionError("deploy-only should not construct a model provider")

    monkeypatch.setattr(agent_pipeline, "Pipeline", Pipeline)
    monkeypatch.setattr(agent_provider, "LLMProvider", forbid_provider)
    monkeypatch.setattr(route, "_state", {
        "queue": events, "loop": Loop(), "stop_event": threading.Event(),
        "recent_events": [], "running": True, "lab_waiting": False,
        "stopping": False, "run_dir": None, "cost": 0.0,
    })
    route._pipeline_thread(route.StartRequest(scenario_id="1", deploy_only=True))
    received = []
    while not events.empty():
        received.append(events.get_nowait())
    assert [event["type"] for event in received] == ["pipeline_done", "__done__"]


@pytest.mark.parametrize("terminal_status", ["completed", "failed"])
def test_scripted_worker_publishes_terminal_event_without_benchmark_evaluation(monkeypatch, terminal_status):
    events = queue.Queue()
    created = {}

    class Loop:
        def call_soon_threadsafe(self, callback, event):
            callback(event)

    class Runner:
        run_dir = "/tmp/scripted-fixture"
        tracker = None

        def run(self, *, stream_callback, stop_event):
            stream_callback({"type": "lab_waiting"})
            assert route._state["lab_waiting"] is True
            stream_callback({"type": "lab_acquired"})
            assert route._state["lab_waiting"] is False
            stream_callback({"type": "runner_started", "runner_kind": "scripted"})
            stream_callback({"type": "tool_result", "tool": "nmap_discovery"})
            if terminal_status == "failed":
                stream_callback({
                    "type": "runner_done", "status": "failed", "run_dir": self.run_dir,
                })
                raise RuntimeError("fixture failure after terminal persistence")
            return {"status": terminal_status}

    modes = ModuleType("src.agent.run_modes")

    def make_runner(kind, **kwargs):
        created.update(kind=kind, **kwargs)
        return Runner()

    modes.make_runner = make_runner
    modes.SCRIPT_IDS = frozenset({"discovery-v1"})
    modes.validate_target_network = lambda value: None
    monkeypatch.setitem(sys.modules, "src.agent.run_modes", modes)
    monkeypatch.setattr(route, "_state", {
        "queue": events, "loop": Loop(), "stop_event": threading.Event(),
        "recent_events": [], "running": True, "lab_waiting": False,
        "stopping": False, "run_dir": None, "cost": 0.0,
    })

    req = route.StartRequest(
        runner_kind="scripted", target_network="192.168.1.0/24", script_id="discovery-v1"
    )
    route._simple_runner_thread(req)
    received = []
    while not events.empty():
        received.append(events.get_nowait())
    assert [event["type"] for event in received] == [
        "lab_waiting", "lab_acquired", "runner_started", "tool_result", "runner_done", "__done__",
    ]
    assert created["kind"] == "scripted"
    assert created["target_network"] == "192.168.1.0/24"
    assert route._state["running"] is False
    assert route._state["run_dir"] == Runner.run_dir
    assert route._state["run_status"] == terminal_status
    assert received[4]["status"] == terminal_status
    assert not any(event["type"] == "evaluation_done" for event in received)
