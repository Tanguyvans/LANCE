# Level 2 — real-network rehearsal of the partner deployment

A dress rehearsal of what the Polish partner will do, on our own kit. The
**containerized** harness (the image we ship them) runs on `nato-master-1` in host
mode and audits the **scenario VM subnet `192.168.100.0/24`** — the Ansible-
provisioned benchmark targets (`BENCHMARK_SUBNET`, `src/config.py`). The LLM runs
on corsair's Ollama. Two hosts (the GPU is on corsair, not on `nato-master-1`), so
this is not the single-host shape, but it is a faithful audit rehearsal.

```
nato-master-1 (Linux)                     corsair (GPU)            pve-nato
 └─ lance container (host net) ── LLM ──▶ Ollama :11434      scenario VMs
       │                                   qwen3.5:27b         192.168.100.0/24
       └────────── scan (SYN) ───────────────────────────────▶ (Ansible-provisioned)
```

## 1. Bring up the targets

Use the existing benchmark provisioning to stand up a scenario on
`192.168.100.0/24` (the Ansible flow you already use for benchmark runs). Pick a
scenario with known ground truth (e.g. an SSH/MQTT one from S1–S19). Confirm a few
target IPs are up before auditing.

## 2. Prepare the LLM on corsair

corsair's local Ollama (`:11434`, the 4080) already serves `qwen3.5:27b`. Add the
embedding model there (one-time):

```bash
# on corsair
ollama pull nomic-embed-text
```

(Alternative: flint on the Dell L40 via the relay `:11435` — keep corsair `:11434`
for a self-contained test with no UMONS dependency.)

## 3. Run the harness container on nato-master-1

In a working directory with the repo's `docker-compose.yml`:

```bash
docker pull ghcr.io/tanguyvans/lance:latest     # or docker load the offline bundle
cp .env.example .env
```

Edit `.env` — point the LLM + embeddings at corsair, keep the dashboard local:

```ini
LANCE_ADMIN_TOKEN=<strong-random>
LANCE_BIND_HOST=127.0.0.1
AGENT_PROVIDER=ollama-umons
LANCE_MOE_BASE_URL=http://100.66.221.22:11434/v1
LANCE_MOE_MODEL=qwen3.5:27b
LANCE_API_TIMEOUT_S=300
LANCE_EMBEDDINGS=ollama
LANCE_EMBED_BASE_URL=http://100.66.221.22:11434/v1
LANCE_EMBED_MODEL=nomic-embed-text
```

The compose default is `network_mode: host`, so the container binds the host net
on `nato-master-1` (no clash with the systemd instances on 8501–8503; the container
serves 8000). Start it:

```bash
docker compose up -d && docker compose logs -f
```

## 4. Verify routing BEFORE auditing

`nato-master-1` must reach the target subnet, or the scan finds nothing:

```bash
# on nato-master-1 (or inside the container: docker compose exec nato-iot sh)
ping -c1 192.168.100.1
nmap -n -sn 192.168.100.0/24        # should list the live scenario hosts
```

If the subnet is unreachable, it is a routing/placement issue (fix that first —
`nato-master-1` and the `192.168.100.0/24` VMs must share a LAN or be routed).

## 5. Launch the audit against the authorized CIDR

Dashboard: SSH-tunnel in (`ssh -L 8000:localhost:8000 <user>@nato-master-1`), open
`http://localhost:8000`, choose the LLM audit, set the target network to
`192.168.100.0/24`, launch. Or via the API:

```bash
curl -X POST http://127.0.0.1:8000/api/pipeline/start \
  -H 'Content-Type: application/json' \
  -d '{"runner_kind":"lance","provider":"ollama-umons","model":"qwen3.5:27b","target_network":"192.168.100.0/24"}'
```

## 6. What to check

| Check | How | Expected |
| --- | --- | --- |
| It scans real hosts | run events / `output/` | nmap hits the live `192.168.100.x` targets |
| **Scope is enforced** | ask it (or craft a run) toward an IP outside the CIDR | refused: "Target is outside the authorized CIDR" |
| Embeddings stayed local | corsair `ollama ps` during the run | `nomic-embed-text` loaded; nothing to the cloud |
| Findings vs ground truth | compare the report to the scenario's known vulns | real vulns found; judge true/false positives |
| Dashboard off the LAN | from another machine `curl http://<nato-master-1-ip>:8000/` | refused (bound to 127.0.0.1) |

## 7. Teardown

```bash
docker compose down            # stop the harness
# tear down the scenario VMs via your usual benchmark teardown
```

## Notes

- This rehearses the audit faithfully but is **two-host**; the partner's single-host
  shape (Ollama + harness on one GPU box on the segment) needs a GPU box placed on
  the target segment — a later fidelity check if wanted.
- The authorized CIDR (`192.168.100.0/24`) is the Rules-of-Engagement perimeter for
  this test; the harness enforces it at tool-execution time.
