"""Real process/thread contention, without network or laboratory operations."""
import fcntl
import multiprocessing
import os
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from src.benchmark.lab_lock import LabWaitCancelled, reserve_lab, serialized_lab


def _hold(path, ready, release):
    os.environ["LANCE_LAB_LOCK"] = path
    with reserve_lab():
        ready.set()
        release.wait(10)


def test_processes_wait_then_acquire_and_release(tmp_path, monkeypatch):
    path = tmp_path / "lab.lock"
    monkeypatch.setenv("LANCE_LAB_LOCK", str(path))
    ctx = multiprocessing.get_context("spawn")
    ready, release = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_hold, args=(str(path), ready, release))
    process.start()
    try:
        assert ready.wait(10)
        waited, acquired = threading.Event(), threading.Event()
        def use():
            with reserve_lab(callback=lambda event: waited.set() if event["type"] == "lab_waiting" else None):
                acquired.set()
        worker = threading.Thread(target=use, daemon=True)
        worker.start()
        assert waited.wait(3)
        assert not acquired.is_set()
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert acquired.is_set()
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(5)
    with reserve_lab():
        pass


def test_cancel_wait_does_not_execute_pipeline_or_release_other_owner(tmp_path, monkeypatch):
    path = tmp_path / "lab.lock"
    monkeypatch.setenv("LANCE_LAB_LOCK", str(path))
    stop = threading.Event()
    events = []
    @serialized_lab
    def run(self, stream_callback=None, stop_event=None):
        pytest.fail("Cancelled pipeline must not deploy anything")
    with path.open("a+") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        def callback(event):
            events.append(event)
            if event["type"] == "lab_waiting":
                stop.set()
        assert run(SimpleNamespace(run_dir=tmp_path), callback, stop) == {}
        assert events[-1]["status"] == "stopped"
        with path.open("a+") as other:
            with pytest.raises(BlockingIOError):
                fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_exception_releases_lock_and_nested_calls_do_not_deadlock(tmp_path, monkeypatch):
    path = tmp_path / "lab.lock"
    monkeypatch.setenv("LANCE_LAB_LOCK", str(path))
    with pytest.raises(ValueError):
        with reserve_lab():
            with reserve_lab():
                raise ValueError("failed audit")
    with path.open("a+") as other:
        fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_disabled_lock_preserves_standalone_behavior(monkeypatch):
    monkeypatch.delenv("LANCE_LAB_LOCK", raising=False)
    stop = threading.Event()
    stop.set()
    with reserve_lab(stop_event=stop):
        pass


def test_invalid_lock_path_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("LANCE_LAB_LOCK", str(tmp_path))
    with pytest.raises(OSError):
        with reserve_lab():
            pytest.fail("Must not execute without the configured lock")
