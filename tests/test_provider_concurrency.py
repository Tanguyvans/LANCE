from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic

import pytest

from src.agent.core.provider_concurrency import request_slot, RequestQueueStopped


def test_same_server_waits_but_other_server_can_enter():
    entered = Event()
    started = Event()

    def contender():
        started.set()
        with request_slot("http://shared.test:11434/another-api"):
            entered.set()

    with ThreadPoolExecutor() as pool:
        with request_slot("http://shared.test:11434/v1"):
            future = pool.submit(contender)
            assert started.wait(1)
            assert not entered.wait(0.05)
            with request_slot("http://other.test:11434/v1"):
                pass
        future.result(timeout=1)
    assert entered.is_set()


def test_wait_can_be_stopped():
    stopped = Event()
    with ThreadPoolExecutor() as pool:
        with request_slot("http://stop.test"):
            future = pool.submit(lambda: enter_stoppable(stopped))
            stopped.set()
            with pytest.raises(RequestQueueStopped):
                future.result(timeout=1)


def enter_stoppable(stopped):
    with request_slot("http://stop.test", stop_event=stopped):
        pytest.fail("cancelled request must not be sent")


def test_deadline_and_error_release():
    with request_slot("http://deadline.test"):
        with pytest.raises(TimeoutError):
            with request_slot("http://deadline.test", deadline=monotonic() + 0.02):
                pytest.fail("deadline ignored")
    with pytest.raises(ValueError):
        with request_slot("http://deadline.test"):
            raise ValueError("provider failure")
    with request_slot("http://deadline.test", deadline=monotonic() + 1):
        pass


def test_parallel_is_explicit_opt_out():
    with request_slot("http://parallel.test"):
        with request_slot("http://parallel.test", sequential=False):
            pass


def test_registry_migration_and_mode_validation(tmp_path, monkeypatch):
    from src.db import database as db
    monkeypatch.setenv("LANCE_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(db, "_db_path", lambda: tmp_path / "test.db")
    db.init_db()
    db.upsert_provider("test", base_url="http://test")
    assert db.get_provider("test")["request_mode"] == "sequential"
    db.upsert_provider("test", request_mode="parallel")
    db.init_db()
    assert db.get_provider("test")["request_mode"] == "parallel"
    with pytest.raises(ValueError):
        db.upsert_provider("test", request_mode="invalid")


def test_provider_wait_does_not_send_http_and_can_stop():
    from unittest.mock import MagicMock
    from src.agent.provider import LLMProvider

    provider = LLMProvider.__new__(LLMProvider)
    provider.provider = "local"
    provider.model = "test"
    provider.request_mode = "sequential"
    provider.client = MagicMock()
    provider.client.base_url = "http://integration.test/v1"
    provider.client.with_options.return_value = provider.client
    stop = Event()
    with ThreadPoolExecutor() as pool:
        with request_slot("http://integration.test/v1"):
            future = pool.submit(provider.chat_with_tools, "system", "hello", [], stop_event=stop)
            stop.set()
            assert "stopped" in future.result(timeout=2)
    provider.client.chat.completions.create.assert_not_called()
