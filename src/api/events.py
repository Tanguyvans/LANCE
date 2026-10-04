"""Bounded, per-operation SSE history with an independent cursor per viewer."""
from __future__ import annotations

import asyncio
from collections import deque
import json
from uuid import uuid4


class EventJournal:
    """Publish on the owning event loop (workers use call_soon_threadsafe).

    Readers never consume one another's events. The retained window also covers
    events published before a browser connects and short disconnections. No
    subscriber queue or background task survives a disconnected reader.
    """

    def __init__(self, max_events: int = 1000):
        if max_events < 1:
            raise ValueError("Event history must retain at least one event")
        self._events: deque[tuple[int, str]] = deque(maxlen=max_events)
        self._operation_id = uuid4().hex
        self._sequence = 0
        self._closed = False
        self._changed = asyncio.Event()

    @property
    def latest_id(self) -> str | None:
        return self._event_id(self._sequence) if self._sequence else None

    def _event_id(self, sequence: int) -> str:
        return f"{self._operation_id}:{sequence}"

    def put_nowait(self, event: dict) -> None:
        if self._closed:
            return
        if event.get("type") != "__done__":
            # Freeze the payload before the producing worker can reuse it.
            payload = json.dumps(event)
            self._sequence += 1
            self._events.append((self._sequence, payload))
        if event.get("type") == "__done__" or (
            event.get("type") == "teardown_done" and event.get("manual") is True
        ):
            self._closed = True
        self._changed.set()
        self._changed = asyncio.Event()

    async def stream(self, after: str | None = None):
        cursor = self._events[0][0] - 1 if self._events else 0
        if after:
            operation, separator, sequence = after.partition(":")
            if separator and operation == self._operation_id and len(sequence) <= 20 and sequence.isdecimal():
                requested = int(sequence)
                if requested <= self._sequence:
                    cursor = requested

        while True:
            changed = self._changed
            if self._events and cursor < self._events[0][0] - 1:
                cursor = self._events[0][0] - 1
                yield {"id": self._event_id(cursor), "data": json.dumps({
                    "type": "warn",
                    "message": "Suivi interrompu : une partie des événements a expiré. Consultez les journaux du run pour l'historique complet.",
                })}
            pending = [(seq, data) for seq, data in self._events if seq > cursor]
            for seq, data in pending:
                cursor = seq
                yield {"id": self._event_id(seq), "data": data}
            # Events can arrive while the caller sends the previous item.
            if cursor < self._sequence:
                continue
            if self._closed:
                return
            try:
                await asyncio.wait_for(changed.wait(), timeout=30)
            except asyncio.TimeoutError:
                yield {"event": "ping", "data": "{}"}
