"""Cooperative host-wide lab reservation, shared by API, CLI and deployments.

Unset LANCE_LAB_LOCK leaves standalone installations unchanged. The lock file
must be the same inode for every instance; never delete or replace it.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import wraps
import fcntl
import inspect
import os
from pathlib import Path
import threading
import time


class LabWaitCancelled(RuntimeError):
    """The user stopped a request before it acquired the laboratory."""


_held = threading.local()


@contextmanager
def reserve_lab(*, stop_event=None, callback=None):
    configured = os.environ.get("LANCE_LAB_LOCK")
    if not configured or getattr(_held, "active", False):
        yield
        return
    path = Path(configured)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as handle:
        waiting = False
        while True:
            if stop_event is not None and stop_event.is_set():
                raise LabWaitCancelled("Arrêt pendant l’attente du laboratoire")
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if not waiting and callback:
                    callback({"type": "lab_waiting", "message": "En attente du laboratoire partagé"})
                waiting = True
                if stop_event is not None:
                    stop_event.wait(0.2)
                else:
                    time.sleep(0.2)
        _held.active = True
        try:
            if callback:
                callback({"type": "lab_acquired"})
            yield
        finally:
            _held.active = False
            fcntl.flock(handle, fcntl.LOCK_UN)


def serialized_lab(method):
    """Reserve the lab for a complete pipeline, including its cleanup."""
    signature = inspect.signature(method)

    @wraps(method)
    def wrapped(*args, **kwargs):
        bound = signature.bind(*args, **kwargs)
        callback = bound.arguments.get("stream_callback")
        try:
            with reserve_lab(stop_event=bound.arguments.get("stop_event"), callback=callback):
                return method(*args, **kwargs)
        except LabWaitCancelled:
            if callback:
                callback({"type": "pipeline_done", "status": "stopped", "results": {},
                          "total_cost_usd": 0, "run_dir": str(args[0].run_dir)})
            return {}

    return wrapped
