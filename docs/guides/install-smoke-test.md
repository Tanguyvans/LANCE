# Installation & Test Guidelines (A–Z)

Step-by-step guide to install LANCE on a **fresh Linux host** and verify that
everything works end to end — first with a **10-minute smoke test** (no GPU or
target network needed), then against an **authorized lab/physical target**.

For partner specifications, air-gapped Ollama model transfer, and Rules of
Engagement, see [`partner-deployment.md`](partner-deployment.md). For the
`nato-master` two-host rehearsal on `192.168.100.0/24`, see
[`level2-network-test.md`](level2-network-test.md).

---

## Checklist Overview

- [ ] **Step 0:** Docker + Compose + Ollama installed, 2 models pulled (chat + embeddings)
- [ ] **Step 1:** LANCE image loaded (online `docker pull` or offline `.tar.gz` bundle)
- [ ] **Step 2:** `.env` created and filled in
- [ ] **Step 3:** Container booted (`docker compose up -d`) and initial ChromaDB ingest done
- [ ] **Step 4:** Automated verification passes (`scripts/deployment/verify-install.sh`)
- [ ] **Step 5:** Dashboard reached via SSH tunnel + first read-only scan + first LANCE audit on an authorized target (`/32` or lab VLAN)

---

## Step 0 — Prepare the Linux host (Docker + Ollama)

Requirements: a **Linux** machine (recommended so `network_mode: host` supports
raw SYN scans, `ip neigh`, and `localhost:11434`).

### 0.1 Verify Docker + Compose
```bash
docker --version
docker compose version
```
If Docker is not installed yet on Ubuntu/Debian:
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker "$USER"   # log out and back in after this
```

### 0.2 Prepare Ollama + the 2 required models
Choose one of the two shapes:

**Option A — Ollama on the same Linux host (recommended single-host setup):**
```bash
curl -fsSL https://ollama.com/install.sh | sh   # skip if already installed

# 1) Pick ONE chat model suited to your hardware:
ollama pull qwen2.5:3b           # ~1.9 GB — CPU-only smoke test
# ollama pull qwen2.5:7b         # ~4.7 GB — fast 16 GB GPU test (100% VRAM)
# ollama pull qwen2.5:14b        # ~9.0 GB — recommended 16 GB GPU audit
# ollama pull qwen3.5:27b        # ~17 GB  — 24+ GB GPU audit

# 2) Pull the mandatory local embedding model (~274 MB, runs fine on CPU):
ollama pull nomic-embed-text

# Confirm both models are listed:
ollama list
```

**Option B — Ollama on a separate GPU host (two-host setup):**
- Pull the chat model and `nomic-embed-text` on that GPU host.
- Make sure Ollama listens on the host IP (`OLLAMA_HOST=0.0.0.0:11434`) and that
  TCP port `11434` is firewalled to allow **only** the LANCE host IP.
- Confirm reachability from the LANCE host:
  ```bash
  curl -fsS http://<gpu-host-ip>:11434/v1/models
  ```

---

## Step 1 — Get the config files and Docker image

### Option A — Quick online test (from `dev/1` or `main`)
```bash
git clone -b dev/1 --single-branch https://github.com/Tanguyvans/LANCE.git
cd LANCE

# If the GHCR package is private, log in first with a GitHub PAT (read:packages):
# echo "<GITHUB_PAT>" | docker login ghcr.io -u Tanguyvans --password-stdin

docker pull ghcr.io/tanguyvans/lance:dev-1
docker tag ghcr.io/tanguyvans/lance:dev-1 ghcr.io/tanguyvans/lance:latest
```
*(Once merged to `main`, replace `:dev-1` with `:latest` and drop the `docker tag` line.)*

### Option B — Full offline partner install (no internet on the target host)
1. On a machine with Docker + internet, build the bundle:
   ```bash
   scripts/deployment/build-offline-bundle.sh dev-1   # or `latest` after merge to main
   ```
2. Copy these files to a fresh folder on the target Linux host:
   - `dist/lance-<tag>-amd64.tar.gz`
   - `dist/lance-<tag>-amd64.tar.gz.sha256`
   - `docker-compose.yml`
   - `.env.example`
   - `scripts/deployment/verify-install.sh` (optional, for Step 4)
3. On the target host, verify the checksum and load the image:
   ```bash
   sha256sum -c lance-<tag>-amd64.tar.gz.sha256
   gunzip -c lance-<tag>-amd64.tar.gz | docker load
   # If <tag> is not `latest`, tag it so docker-compose.yml finds it:
   docker tag ghcr.io/tanguyvans/lance:<tag> ghcr.io/tanguyvans/lance:latest
   ```

---

## Step 2 — Configure `.env`

```bash
cp .env.example .env
```

Edit `.env` (keep `#` comments on their own lines — never append `# ...` at the
end of a `KEY=value` line):

```ini
LANCE_MODE=audit
LANCE_ALLOWED_CIDR=192.168.50.0/24
LANCE_EXCLUDED_IPS=192.168.50.1,192.168.50.10
AGENT_PROVIDER=ollama
LANCE_LLM_BASE_URL=http://localhost:11434/v1
LANCE_LLM_MODEL=qwen2.5:14b
LANCE_EMBEDDINGS=ollama
LANCE_EMBED_MODEL=nomic-embed-text
LANCE_BIND_HOST=127.0.0.1
LANCE_ADMIN_TOKEN=
```

- **`LANCE_ALLOWED_CIDR` / `LANCE_EXCLUDED_IPS`:** set these to your authorized
  target subnet and any critical infrastructure IPs (router, hypervisor, and the
  LANCE host itself) that must never be scanned. Leave commented only if you want
  to pick any CIDR per run.
- **Two-host Ollama:** replace `localhost` in `LANCE_LLM_BASE_URL` with `<gpu-host-ip>`.
  (Embeddings reuse `LANCE_LLM_BASE_URL` automatically; only set `LANCE_EMBED_BASE_URL`
  if embeddings live on a different host.)
- **`LANCE_ADMIN_TOKEN`:** can stay empty for a quick local smoke test; for a partner
  deployment, set a strong random string (`openssl rand -hex 24`).
- Leave `VOYAGE_API_KEY` unset — embeddings must stay 100% local.

---

## Step 3 — Start LANCE

```bash
docker compose up -d
docker compose logs -f
```

Wait 1–3 minutes on first boot while the container ingests the security skills
into ChromaDB using `nomic-embed-text`. Press `Ctrl-C` once you see `Uvicorn
running on http://127.0.0.1:8000`.

---

## Step 4 — Verify the installation (Level 1 pass criteria)

Run the automated check script from the directory containing `docker-compose.yml`:

```bash
scripts/deployment/verify-install.sh
```

Or run the checks manually:

| Check | Command | Expected |
| --- | --- | --- |
| Boots with **no Voyage key** | `docker compose logs` | `[init] Ingested N skill chunks`, **no** `VOYAGE_API_KEY not set` error |
| Provider reconciled from `.env` | `docker compose logs \| grep reconcile` | `[reconcile] provider 'ollama' -> http://…` |
| Container **healthy** | `docker compose ps` | status `healthy` |
| Dashboard responds locally | `curl -fsS http://127.0.0.1:8000/ -o /dev/null -w '%{http_code}\n'` | `200` |
| Model registered | `curl -s http://127.0.0.1:8000/api/models` | lists your `LANCE_LLM_MODEL`, marked recommended |
| Network tools in container | `docker compose exec -T nato-iot sh -c "which nmap ip traceroute"` | all three paths printed |
| Embeddings are **local** | on the Ollama host: `ollama ps` during ingest/run | `nomic-embed-text` loaded; zero cloud calls |
| **Off the LAN** | from another machine: `curl http://<host-ip>:8000/` | connection refused / timeout (`127.0.0.1` bind) |

All green → the container installation is validated end to end.

---

## Step 5 — Open the dashboard & run your first network test

### 5.1 Reach the dashboard over an SSH tunnel
From your workstation (laptop):
```bash
ssh -L 8000:localhost:8000 <user>@<lance-host>
```
Open `http://localhost:8000` in your browser.

### 5.2 Progressive test on an authorized physical device or lab VLAN
Stay strictly inside your authorized perimeter (a dedicated lab VLAN or a single
test device as `<TARGET_IP>/32`):

1. **Check routing from the LANCE host first:**
   ```bash
   ping -c 2 <TARGET_IP>
   nmap -n -sn <TARGET_IP>/32
   ```
2. **Pass 1 — Read-only Scripts (safe, non-intrusive):**
   In the dashboard, select **Scripts**, set target `<TARGET_IP>/32` (or lab CIDR),
   and run `discovery-v1`, then `service-inventory-v1`. Verify the device and its
   open ports appear.
3. **Pass 2 — LANCE Agent (`Analysis only (1–3)` then `Full audit (1–6)`):**
   Select **LANCE Agent**, verify your Ollama model is pre-selected, set the exact
   authorized CIDR (`<TARGET_IP>/32` or lab VLAN), and optionally expand **Scope
   exclusions & network structure (optional)** to add per-run excluded IPs or paste
   a grey-box YAML topology (click **Preview** to render it before launching).
   Start with **Analysis only (1–3)**, then run **Full audit (1–6)** to verify
   active proof checks and report generation.
4. **Scope & exclusion guardrail check:**
   Confirm that targeting an IP in `LANCE_EXCLUDED_IPS` (or outside
   `LANCE_ALLOWED_CIDR`) is immediately rejected with HTTP `403`, and that
   `tool_calls.jsonl` contains zero active probes against excluded hosts.

---

## Step 6 — Optional offline proof & teardown

- **Prove full air-gap:** disconnect egress / internet on the test host, reset
  the data volume (`rm -rf ./data`), and re-run Step 3 + Step 4. Boot, ingest,
  and dashboard must still pass completely offline.
- **Stop the container:**
  ```bash
  docker compose down
  ```
- **Reset to a clean first-boot state** (forces provider re-init and ChromaDB
  re-ingest):
  ```bash
  docker compose down && rm -rf ./data
  ```

---

## Step 7 — Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `unauthorized` on `docker pull` | Private GHCR package | Run `docker login ghcr.io` with a GitHub PAT (`read:packages`), or use the offline `.tar.gz` bundle. |
| `[init]` fails with connection refused to `:11434` | Ollama not running, or two-host Ollama bound to `127.0.0.1` | Start `ollama` (`sudo systemctl status ollama`). On a separate GPU host, set `OLLAMA_HOST=0.0.0.0:11434` and allow TCP `11434` from the LANCE host IP. |
| Agent gets `404 model not found` | Tag in `LANCE_LLM_MODEL` does not match `ollama list` | Run `ollama pull <tag>` on the Ollama host or update `LANCE_LLM_MODEL` in `.env`, then `docker compose up -d`. |
| `address already in use` on port `8000` | Another service uses port `8000` (host mode) | Stop the conflicting service, or switch to bridge mode in `docker-compose.yml` with e.g. `127.0.0.1:8080:8000` and `LANCE_BIND_HOST=0.0.0.0`. |
| Strange provider/model name with `#` inside | Inline `# comment` placed at the end of a `KEY=val` line in `.env` | Move comments onto their own `# ...` lines above the variable, then `docker compose up -d`. |
| Running on macOS / Windows Docker Desktop | `network_mode: host` is Linux-only | Comment out `network_mode: host` in `docker-compose.yml`, uncomment `ports:` + `extra_hosts:`, set `LANCE_BIND_HOST=0.0.0.0` and `LANCE_LLM_BASE_URL=http://host.docker.internal:11434/v1`. (Raw SYN scans are unavailable in bridge mode.) |
| `arp_scan` returns 0 hosts on a physical target | Target is on another L3 subnet (no ARP across routers) | Normal across routed subnets — `nmap_discovery` / `nmap_scan` still discover the target as long as L3 routing works (Step 5.2). |
