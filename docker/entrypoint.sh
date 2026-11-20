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

# Bind host. Defaults to 127.0.0.1 (fail-closed): the dashboard — whose scan
# launch is unauthenticated — stays off the LAN in the host-mode default and is
# reached over an SSH tunnel. Bridge networking MUST set LANCE_BIND_HOST=0.0.0.0,
# otherwise the published port maps to a loopback-only app (see docker-compose.yml).
exec uvicorn src.api.main:app --host "${LANCE_BIND_HOST:-127.0.0.1}" --port 8000
