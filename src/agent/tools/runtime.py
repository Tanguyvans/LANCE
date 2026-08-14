"""Runtime context shared by tool handlers.

The context is deliberately orthogonal to the execution profile.  It only
allows an already-requested run stop to cancel a subprocess; it does not
change which tools a model can select or how many calls it may make.
"""

from __future__ import annotations

import contextvars
import os
import signal
import subprocess
import time
from typing import Any


_tool_stop_event: contextvars.ContextVar[Any | None] = contextvars.ContextVar(
    "tool_stop_event", default=None
)


def get_tool_stop_event():
    """Return the cooperative stop event for the current tool invocation."""
    return _tool_stop_event.get()


class _ToolStopContext:
    def __init__(self, stop_event):
        self.stop_event = stop_event
        self.token = None

    def __enter__(self):
        self.token = _tool_stop_event.set(self.stop_event)
        return self

    def __exit__(self, exc_type, exc, tb):
        _tool_stop_event.reset(self.token)
        return False


def tool_stop_context(stop_event):
    """Return a context manager carrying the run-level stop event."""
    return _ToolStopContext(stop_event)


def _terminate_process(process: subprocess.Popen[str]) -> None:
    """Terminate a subprocess and its process group when possible."""
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass


def run_cooperatively(
    command: list[str],
    *,
    timeout: float,
    input_data: str | bytes | None = None,
) -> tuple[str, str, int, bool, bool]:
    """Run a command while observing the current stop event.

    Returns ``stdout, stderr, return_code, timed_out, cancelled``.  The
    polling interval is short enough for an interactive stop while keeping
    the normal tool execution path unchanged when no stop event is present.
    """
    stop_event = get_tool_stop_event()
    if stop_event is not None and stop_event.is_set():
        return "", "Command cancelled by run stop request", -2, False, True

    popen_kwargs: dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": isinstance(input_data, str) or input_data is None,
    }
    if input_data is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True

    try:
        process = subprocess.Popen(command, **popen_kwargs)
    except FileNotFoundError:
        return "", f"Command not found: {command[0]}", -1, False, False

    pending_input = input_data
    deadline = time.monotonic() + max(0.01, float(timeout))
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process(process)
            stdout, stderr = process.communicate()
            return (
                stdout or "",
                stderr or f"Command timed out after {timeout}s",
                -1,
                True,
                False,
            )
        try:
            stdout, stderr = process.communicate(
                input=pending_input,
                timeout=min(0.25, remaining),
            )
            return stdout or "", stderr or "", process.returncode, False, False
        except subprocess.TimeoutExpired:
            pending_input = None
            if stop_event is not None and stop_event.is_set():
                _terminate_process(process)
                stdout, stderr = process.communicate()
                return (
                    stdout or "",
                    stderr or "Command cancelled by run stop request",
                    -2,
                    False,
                    True,
                )
