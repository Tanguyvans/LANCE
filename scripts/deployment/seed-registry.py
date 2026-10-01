"""Initialize a private DB, copying only model/provider settings on first use."""
from pathlib import Path
import sqlite3
import sys

# Executed by path from the deployed checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parents[2] / ".env")
from src.db.database import _db_path, init_db
from src.db.seed import seed_models, seed_providers


def initialize(source: Path) -> None:
    destination = _db_path()
    first = not destination.exists()
    init_db()
    if first:
        seed_providers()
        seed_models()
    if not first or not source.is_file() or source.resolve() == destination.resolve():
        return
    with sqlite3.connect(f"{source.as_uri()}?mode=ro", uri=True) as original:
        with sqlite3.connect(destination) as target:
            for table in ("providers", "models"):
                source_columns = {row[1] for row in original.execute(f'PRAGMA table_info("{table}")')}
                columns = [row[1] for row in target.execute(f'PRAGMA table_info("{table}")') if row[1] in source_columns]
                names = ",".join('"' + name.replace('"', '""') + '"' for name in columns)
                rows = original.execute(f'SELECT {names} FROM "{table}"').fetchall()
                target.executemany(f'INSERT OR REPLACE INTO "{table}" ({names}) VALUES ({",".join("?" for _ in columns)})', rows)


if __name__ == "__main__":
    initialize(Path(sys.argv[1]).resolve())
