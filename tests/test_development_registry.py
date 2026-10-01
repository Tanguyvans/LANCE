"""Development instances inherit settings once, never stable run history."""
import importlib.util
from pathlib import Path
import sqlite3


def test_new_registry_copies_settings_only_and_preserves_later_changes(tmp_path, monkeypatch):
    from src.db.database import init_db, upsert_provider
    source = tmp_path / "stable.db"
    destination = tmp_path / "dev.db"
    monkeypatch.setenv("LANCE_DB_PATH", str(source))
    init_db()
    upsert_provider(name="test-private", base_url="http://model.test/v1", default_model="qwen", kind="local")
    with sqlite3.connect(source) as connection:
        connection.execute("INSERT INTO runs (run_dir) VALUES ('stable-run')")
    monkeypatch.setenv("LANCE_DB_PATH", str(destination))
    script = Path(__file__).resolve().parents[1] / "scripts/deployment/seed-registry.py"
    spec = importlib.util.spec_from_file_location("deployment_seed", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.initialize(source)
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT base_url FROM providers WHERE name='test-private'").fetchone() == ("http://model.test/v1",)
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (0,)
        connection.execute("UPDATE providers SET base_url='http://dev.test' WHERE name='test-private'")
    module.initialize(source)
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT base_url FROM providers WHERE name='test-private'").fetchone() == ("http://dev.test",)
    with sqlite3.connect(source) as connection:
        assert connection.execute("SELECT count(*) FROM runs").fetchone() == (1,)
