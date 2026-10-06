"""Live dashboard subscribers use synthetic events, never a model or lab."""
import asyncio
import json
from pathlib import Path
import shutil
import subprocess
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.api.events import EventJournal
from src.api.routes import pipeline


def test_two_dashboards_receive_every_event_and_both_finish(monkeypatch):
    async def check():
        monkeypatch.setattr(pipeline, "_state", dict(pipeline._state, running=False, teardown_running=False))
        monkeypatch.setattr(pipeline, "threading", SimpleNamespace(Thread=Mock(), Event=threading.Event))
        await pipeline.start_pipeline(pipeline.StartRequest(model="offline", provider="local"))
        first = await pipeline.stream_events()
        second = await pipeline.stream_events()
        events = [
            {"type": "phase_start", "phase": 1},
            {"type": "phase_done", "phase": 1},
            {"type": "pipeline_done", "status": "completed"},
        ]

        async def receive(response):
            return [json.loads(item["data"]) async for item in response.body_iterator]

        tasks = [asyncio.create_task(receive(response)) for response in (first, second)]
        for event in [*events, {"type": "__done__"}]:
            pipeline._state["queue"].put_nowait(event)
            await asyncio.sleep(0)
        seen = await asyncio.wait_for(asyncio.gather(*tasks), timeout=1)
        assert seen == [events, events]

    asyncio.run(check())


@pytest.mark.parametrize("terminal", [
    {"type": "__done__"},
    {"type": "teardown_done", "manual": True, "success": False},
])
def test_late_viewers_and_reconnections_receive_retained_events(terminal):
    async def check():
        journal = EventJournal()
        journal.put_nowait({"type": "phase_start", "phase": 1})
        first_id = journal.latest_id
        journal.put_nowait({"type": "error", "message": "controlled error"})
        journal.put_nowait(terminal)
        full = [item async for item in journal.stream()]
        resumed = [item async for item in journal.stream(first_id)]
        assert resumed == full[1:]
        assert json.loads(full[0]["data"])["type"] == "phase_start"
        assert json.loads(resumed[0]["data"])["type"] == "error"
        assert len(full) == (2 if terminal["type"] == "__done__" else 3)
        assert [item async for item in journal.stream(journal.latest_id)] == []

    asyncio.run(check())


def test_old_operation_cursor_cannot_skip_the_next_operation():
    async def check():
        old, new = EventJournal(), EventJournal()
        old.put_nowait({"type": "phase_start"})
        new.put_nowait({"type": "pipeline_start"})
        new.put_nowait({"type": "__done__"})
        seen = [json.loads(item["data"]) async for item in new.stream(old.latest_id)]
        assert seen == [{"type": "pipeline_start"}]

    asyncio.run(check())


def test_history_overflow_is_reported_and_does_not_lose_terminal_event():
    async def check():
        journal = EventJournal(max_events=2)
        journal.put_nowait({"type": "phase_start"})
        cursor = journal.latest_id
        for phase in range(2, 6):
            journal.put_nowait({"type": "phase_done", "phase": phase})
        journal.put_nowait({"type": "pipeline_done"})
        journal.put_nowait({"type": "__done__"})
        seen = [json.loads(item["data"]) async for item in journal.stream(cursor)]
        assert [item["type"] for item in seen] == ["warn", "phase_done", "pipeline_done"]
        assert seen[1]["phase"] == 5

    asyncio.run(check())


def test_disconnecting_one_viewer_does_not_cancel_the_other():
    async def check():
        journal = EventJournal()
        first, second = journal.stream(), journal.stream()
        cancelled = asyncio.create_task(anext(first))
        remaining = asyncio.create_task(anext(second))
        await asyncio.sleep(0)
        cancelled.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled
        journal.put_nowait({"type": "phase_start"})
        assert json.loads((await asyncio.wait_for(remaining, 1))["data"]) == {"type": "phase_start"}
        journal.put_nowait({"type": "__done__"})
        assert [item async for item in second] == []

    asyncio.run(check())


def test_http_sse_reconnect_accepts_query_and_last_event_id(monkeypatch):
    from fastapi.testclient import TestClient
    from src.api.main import app

    journal = EventJournal()
    journal.put_nowait({"type": "phase_start"})
    cursor = journal.latest_id
    journal.put_nowait({"type": "pipeline_done"})
    journal.put_nowait({"type": "__done__"})
    monkeypatch.setitem(pipeline._state, "queue", journal)
    with TestClient(app) as client:
        for kwargs in ({"params": {"after": cursor}}, {"headers": {"Last-Event-ID": cursor}}):
            response = client.get("/api/pipeline/stream", **kwargs)
            assert response.status_code == 200
            assert "text/event-stream" in response.headers["content-type"]
            assert "pipeline_done" in response.text
            assert "phase_start" not in response.text
            assert f"id: {journal.latest_id}" in response.text


@pytest.mark.parametrize("status", [
    {"running": True, "event_cursor": "run:1"},
    {"running": False, "event_cursor": "run:2"},
    None,
], ids=["active", "finished-while-offline", "server-unavailable"])
def test_dashboard_reconnects_from_its_cursor_even_if_run_finished(status):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for dashboard integration")
    source = Path(__file__).resolve().parents[1] / "src/static/app.js"
    script = r"""
const vm = require('node:vm'), fs = require('node:fs'), assert = require('node:assert/strict');
const instances = [], timers = [], seen = [];
const context = vm.createContext({
  console, document: {addEventListener() {}, getElementById: () => ({}), documentElement: {}},
  getComputedStyle: () => ({getPropertyValue: () => ''}),
  EventSource: class {constructor(url) {this.url=url;instances.push(this);} close() {}},
  setTimeout(callback) {timers.push(callback);return timers.length;}, clearTimeout() {},
});
vm.runInContext(fs.readFileSync(process.argv[1], 'utf8'), context);
context.status = JSON.parse(process.argv[2]);
context.seen = seen;
vm.runInContext('handleEvent = ev => seen.push(ev); addLog = () => {}; fetchJSON = async () => status;', context);
(async () => {
  vm.runInContext('startSSE()', context);
  const message = {lastEventId:'run:1',data:JSON.stringify({type:'phase_start'})};
  instances[0].onmessage(message);
  instances[0].onmessage(message);
  assert.equal(seen.length, 1);
  await instances[0].onerror();
  assert.equal(timers.length, 1);
  timers[0]();
  assert.equal(instances[1].url, '/api/pipeline/stream?after=run%3A1');
  vm.runInContext('startSSE()', context);
  assert.equal(instances[2].url, '/api/pipeline/stream');
})().catch(error => {console.error(error);process.exitCode=1;});
"""
    result = subprocess.run([node, "-e", script, str(source), json.dumps(status)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
