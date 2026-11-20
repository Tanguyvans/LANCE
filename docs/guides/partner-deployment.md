# LANCE — partner deployment guide

LANCE is an LLM-driven IoT security-audit tool. In this deployment **you run it on
your own host, on your own network**. Nothing leaves your network: the LLM runs on
your Ollama, embeddings run locally, and there is no call back to UMONS. We ship
you a self-contained container image; you run it on one Linux GPU host.

## 1. What you provide

| Item | Requirement |
| --- | --- |
| Host | One **Linux** machine with a **GPU**, placed on the network segment to audit |
| Runtime | **Docker** + the Docker Compose plugin |
| LLM | **Ollama** on that host (GPU), with the models below pulled |
| CPU/RAM | Modest for the harness itself; the GPU is for the LLM |
| Internet | **Not required** — the deployment runs fully offline |

The harness and the LLM can share the one GPU host (simplest), as long as it sits
on the target segment. Host networking is used so the scanner can reach the
targets directly.

## 2. Pull the models on Ollama

A chat model for the agent, and the embedding model for the knowledge store:

```bash
ollama pull qwen2.5:14b          # or your preferred served chat model
ollama pull nomic-embed-text     # embeddings — required, runs locally
```

Use any model Ollama serves; note the exact tag — you set it in `.env` below.

## 3. Load the image (offline)

We deliver a tarball (`lance-<tag>-amd64.tar.gz`) and its `.sha256`:

```bash
sha256sum -c lance-<tag>-amd64.tar.gz.sha256     # verify integrity
gunzip -c lance-<tag>-amd64.tar.gz | docker load # restores ghcr.io/tanguyvans/lance:latest
```

No registry access is needed. The image is `amd64`.

## 4. Configure `.env`

Copy the template and edit the few lines that matter:

```bash
cp .env.example .env
```

```ini
# Dashboard admin token — set a strong random value (required for admin actions)
LANCE_ADMIN_TOKEN=<random-32+-chars>

# Dashboard stays on localhost; reach it over an SSH tunnel (see §6). Do not put
# it on the LAN: the scan-launch endpoint is unauthenticated.
LANCE_BIND_HOST=127.0.0.1

# Your Ollama endpoint + served chat model (reconciled into LANCE at every boot)
AGENT_PROVIDER=ollama-umons
LANCE_MOE_BASE_URL=http://localhost:11434/v1
LANCE_MOE_MODEL=qwen2.5:14b
# LANCE_API_TIMEOUT_S=300          # widen for heavy local models

# Embeddings run locally on your Ollama — no cloud
LANCE_EMBEDDINGS=ollama
LANCE_EMBED_MODEL=nomic-embed-text
```

`LANCE_MOE_MODEL` must match a tag you pulled in §2, or the agent gets a 404.

## 5. Start

```bash
docker compose up -d
docker compose logs -f        # first boot ingests the knowledge store locally
```

The compose file defaults to `network_mode: host` (Linux) so the scanner can emit
SYN scans and reach Ollama at `localhost:11434`.

## 6. Reach the dashboard

It is bound to `127.0.0.1:8000` on the host. From your workstation, tunnel in:

```bash
ssh -L 8000:localhost:8000 <user>@<host>
# then open http://localhost:8000
```

## 7. Scope and Rules of Engagement

- Every audit is launched with an **authorized target CIDR** (e.g. `10.20.0.0/24`).
  LANCE **enforces this at tool-execution time**: every scan/exploit tool is
  confined to that CIDR and refuses any target outside it (fail-closed). It cannot
  touch hosts you did not authorize.
- Before any run, we agree in writing on the **perimeter** (which subnet/hosts and
  ports) and the **time window** — a short Rules of Engagement that both sides sign.
- Keep the dashboard off the LAN (§6). Scan launch is unauthenticated by default,
  so the localhost bind is the primary control. For extra app-layer hardening set
  `LANCE_REQUIRE_LAUNCH_AUTH=1` — launches then require a Bearer admin token.
  (Launching from the dashboard button with this on needs a pending client update;
  until then launch via the API with the token.)

## 8. What we deliver to you

- The image bundle (`lance-<tag>-amd64.tar.gz` + `.sha256`).
- `docker-compose.yml` and `.env.example` (in the repository).
- This guide.

You provide the host, the GPU/Ollama with the models, and the signed RoE.
