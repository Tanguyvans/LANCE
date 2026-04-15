#!/bin/bash
set -e

INIT_FLAG="/app/data/.initialized"

if [ ! -f "$INIT_FLAG" ]; then
    echo "[init] First run: ingesting skills into knowledge store..."
    python3 -c "
from src.agent.knowledge.ingest import ingest_skills
count = ingest_skills()
print(f'[init] Ingested {count} skill chunks into ChromaDB')
"
    touch "$INIT_FLAG"
    echo "[init] Knowledge store ready."
fi

exec uvicorn src.api.main:app --host 0.0.0.0 --port 8000
