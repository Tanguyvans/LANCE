# Install smoke test (Level 1)

A dry run of the partner deployment, **without a target network or a GPU**. It
proves the container boots offline, reconciles the provider from `.env`, embeds
locally (no cloud), serves the dashboard, and reports healthy. Takes ~10 minutes.
For the real audit on a network, see Level 2 in the deployment discussion.

## 0. Prerequisites

- A **Linux host with Docker** + the Compose plugin.
- An **Ollama** reachable from that host. CPU is fine for this test. Pull a small
  chat model and the embedding model **on the Ollama host**:

  ```bash
  ollama pull qwen2.5:3b          # any small chat model is fine for the smoke
  ollama pull nomic-embed-text    # embeddings (runs on CPU)
  ```

> If Ollama runs on another machine, use its IP in the `.env` URLs below (e.g.
> `http://100.66.221.22:11434/v1` for corsair) instead of `localhost`.

## 1. Get the image

**Offline (what the partner does):** build the bundle once on a machine that can
reach GHCR, copy it over, and load it:

```bash
scripts/deployment/build-offline-bundle.sh        # produces dist/lance-latest-amd64.tar.gz + .sha256
# copy both files to the test host, then:
sha256sum -c lance-latest-amd64.tar.gz.sha256
gunzip -c lance-latest-amd64.tar.gz | docker load
```

**Quick (online):** `docker pull ghcr.io/tanguyvans/lance:latest`

## 2. Configure

In a fresh working directory with the repo's `docker-compose.yml`:

```bash
cp .env.example .env
```

Edit `.env`:

```ini
LANCE_ADMIN_TOKEN=$(head -c24 /dev/urandom | base64)   # any strong value
LANCE_BIND_HOST=127.0.0.1
AGENT_PROVIDER=ollama-umons
LANCE_MOE_BASE_URL=http://localhost:11434/v1     # or the Ollama host IP
LANCE_MOE_MODEL=qwen2.5:3b                       # must match step 0
LANCE_EMBEDDINGS=ollama
LANCE_EMBED_MODEL=nomic-embed-text
# leave VOYAGE_API_KEY unset — this is the point of the test
```

## 3. Start

```bash
docker compose up -d
docker compose logs -f        # Ctrl-C once it is serving
```

## 4. Pass criteria

| Check | Command | Expected |
| --- | --- | --- |
| Boots with **no Voyage key** | `docker compose logs` | `[init] Ingested N skill chunks`, **no** `VOYAGE_API_KEY not set` error |
| Provider reconciled from `.env` | `docker compose logs \| grep reconcile` | `[reconcile] provider 'ollama-umons' -> http://…` |
| Container **healthy** | `docker compose ps` | status `healthy` (after ~1–3 min) |
| Dashboard up | `curl -fsS http://127.0.0.1:8000/ -o /dev/null -w '%{http_code}\n'` | `200` |
| Model registered | `curl -s http://127.0.0.1:8000/api/models` | lists `qwen2.5:3b`, marked recommended |
| Embeddings are **local** | on the Ollama host: `ollama ps` while a run embeds | `nomic-embed-text` loaded; no call leaves the host |
| **Off the LAN** | from another machine: `curl http://<host-ip>:8000/` | refused / times out (bound to 127.0.0.1) |

All green → the C1–C4 profile works end to end. Reach the dashboard over an SSH
tunnel (`ssh -L 8000:localhost:8000 <user>@<host>`).

## 5. Optional — prove full offline

Re-run step 3 on a host with **no internet** (or block egress). It must still
boot and serve: the only remote dependency (Voyage) is gone, embeddings are local,
and nuclei templates are baked into the image.

## 6. Teardown

```bash
docker compose down
```

To reset to a first-run state (re-ingest), also remove the data volume:
`rm -rf ./data` (this re-triggers the local ingest on next boot).
