"""Process-wide admission control; tools never hold the model request lock."""
from contextlib import contextmanager
from threading import Lock
from time import monotonic
from urllib.parse import urlsplit

from .provider_transport import deadline_remaining

_registry_lock = Lock()
_locks = {}


class RequestQueueStopped(Exception):
    """User cancelled before any HTTP request was sent."""


@contextmanager
def request_slot(base_url, *, sequential=True, stop_event=None, deadline=None):
    # Models and provider aliases on one origin share the same capacity.
    url = urlsplit(str(base_url))
    key = (url.scheme.lower(), (url.hostname or '').lower(),
           url.port or (443 if url.scheme == 'https' else 80))
    with _registry_lock:
        lock = _locks.setdefault(key, Lock())
    started = monotonic()
    acquired = False
    try:
        while True:
            if stop_event is not None and stop_event.is_set():
                raise RequestQueueStopped()
            remaining = deadline_remaining(deadline)
            if not sequential:
                break
            if lock.acquire(timeout=min(0.1, remaining) if remaining is not None else 0.1):
                acquired = True
                break
        if stop_event is not None and stop_event.is_set():
            raise RequestQueueStopped()
        deadline_remaining(deadline)
        yield monotonic() - started
    finally:
        if acquired:
            lock.release()
