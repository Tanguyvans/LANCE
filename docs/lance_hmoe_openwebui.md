# LANCE HMoE with OpenWebUI

This guide records the local deployment used on `ilia-corsair-5000x`. It exposes
four QLoRA experts through one OpenAI-compatible API:

```text
OpenWebUI -> LANCE HMoE API -> Qwen2.5-0.5B-Instruct
                              + recon adapter
                              + vuln adapter
                              + exploit adapter
                              + secretary adapter
```

The API advertises five model IDs:

| Model ID | Purpose |
| --- | --- |
| `lance-moe` | Automatically routes each LANCE phase to an expert |
| `expert-recon` | Forces the reconnaissance adapter |
| `expert-vuln` | Forces the vulnerability-analysis adapter |
| `expert-exploit` | Forces the exploitation adapter |
| `expert-secretary` | Forces the graph/reporting adapter |

Only one OpenWebUI connection is required. The experts are PEFT adapters loaded by
Transformers; they are not separate Ollama models and will not appear in `ollama list`.

## Host paths

The current installation uses:

```text
Code:     /home/tanguy/LANCE
Python:   /home/leo/LANCE/env/bin/python
Adapters: /home/tanguy/LANCE/output/adapters/lance-qlora_moe_3b
API:      http://172.17.0.1:8001/v1
WebUI:    http://100.66.221.22:3000
```

Each adapter directory must contain `adapter_config.json` and
`adapter_model.safetensors`. `moe_server.py` falls back to the highest checkpoint
only when the final weights are absent.

## Permissions

The service runs as `tanguy`, so that user must be able to traverse the parent
directories and read all four adapters. Grant only the required access:

```bash
sudo setfacl -m u:tanguy:--x /home/leo
sudo setfacl -m u:tanguy:--x /home/leo/LANCE
sudo setfacl -m u:tanguy:--x /home/leo/LANCE/output
sudo setfacl -m u:tanguy:--x /home/leo/LANCE/output/adapters
sudo setfacl -R -m u:tanguy:rX /home/tanguy/LANCE/output/adapters/lance-qlora_moe_3b
```

Verify access without changing the files:

```bash
for expert in recon vuln exploit secretary; do
  test -r "/home/tanguy/LANCE/output/adapters/lance-qlora_moe_3b/$expert/adapter_model.safetensors" \
    && echo "$expert: readable" \
    || echo "$expert: inaccessible"
done
```

## Python dependencies

The current deployment reuses Leo's ML environment for PyTorch, Transformers,
PEFT, and bitsandbytes. FastAPI and Uvicorn are installed in a Tanguy-owned target:

```bash
mkdir -p /home/tanguy/.local/share/lance-hmoe/site-packages
/home/leo/LANCE/env/bin/python -m pip install \
  --target /home/tanguy/.local/share/lance-hmoe/site-packages \
  fastapi uvicorn
```

## Manual start

The API is intentionally bound to the Docker bridge, not to every network
interface. Confirm the bridge address before starting it:

```bash
ip -4 addr show docker0
```

On this host the address is `172.17.0.1`:

```bash
cd /home/tanguy/LANCE
PYTHONPATH=/home/tanguy/.local/share/lance-hmoe/site-packages \
  /home/leo/LANCE/env/bin/python src/agent/moe_server.py \
  --base-model Qwen/Qwen2.5-3B-Instruct \
  --adapters-dir /home/tanguy/LANCE/output/adapters/lance-qlora_moe_3b \
  --host 172.17.0.1 \
  --adapter-context-tokens 6144 \
  --port 8001
```

Do not bind this unauthenticated API to `0.0.0.0` unless authentication and
firewall rules are added first.

## Context and tool-loop safeguards for the 3B adapters

The server aligns its safe-compaction threshold with the 6144-token training
window. It reconstructs completed tool calls and outstanding structured
requirements from every request, injects a compact runtime state into the most
recent tool result, and removes large rejected deliverable drafts from the
model-visible history. When a tool contract returns `missing_requirements`, the
server emits the corresponding missing tool call deterministically before
allowing another completion attempt. The mechanism is stateless across requests
and therefore does not mix concurrent pipeline runs. For the Recon adapter, only
the five Phase-2 contract schemas are rendered into the model prompt
(`arp_scan`, `nmap_discovery`, `nmap_scan`, `read_deliverable`, and
`save_deliverable`); the caller keeps its complete executable tool registry.
Recon generation is also capped by the remaining 6144-token training window.

## Persistent systemd service

Install the versioned user unit:

```bash
install -Dm0644 deploy/systemd/lance-hmoe.service \
  /home/tanguy/.config/systemd/user/lance-hmoe.service
```

Enable and inspect the service:

```bash
systemctl --user daemon-reload
systemctl --user enable --now lance-hmoe.service
systemctl --user status lance-hmoe.service
journalctl --user -u lance-hmoe.service -f
```

The user service starts while Tanguy has a login session. To allow it to start at
boot without an active session, an administrator can additionally run:

```bash
sudo loginctl enable-linger tanguy
```

## Verification

Check the API from the host:

```bash
curl http://172.17.0.1:8001/health
curl http://172.17.0.1:8001/v1/models
```

Then check the same path from the OpenWebUI container:

```bash
docker exec open-webui python -c \
  "import urllib.request; print(urllib.request.urlopen('http://host.docker.internal:8001/v1/models').read().decode())"
```

The result must contain all five model IDs before configuring OpenWebUI.

## Access from a remote LANCE application

The dashboard on `nato-master` (`100.103.253.86:8501`) runs on a different host.
The HMoE process remains bound to `172.17.0.1` so OpenWebUI can reach it without
exposing the API on every interface. A socket-activated proxy publishes the same
process only on the GPU host's Tailscale address:

```text
nato-master -> 100.66.221.22:8001 -> 172.17.0.1:8001 -> HMoE
```

Install and enable the versioned proxy units on `ilia-corsair-5000x`:

```bash
install -Dm0644 deploy/systemd/lance-hmoe-tailnet.socket \
  /home/tanguy/.config/systemd/user/lance-hmoe-tailnet.socket
install -Dm0644 deploy/systemd/lance-hmoe-tailnet.service \
  /home/tanguy/.config/systemd/user/lance-hmoe-tailnet.service
systemctl --user daemon-reload
systemctl --user enable --now lance-hmoe-tailnet.socket
```

Verify the tailnet path:

```bash
curl http://100.66.221.22:8001/health
curl http://100.66.221.22:8001/v1/models
```

This listener is restricted to the Tailscale address, but the API itself has no
Bearer validation. Keep tailnet ACLs restricted and never forward port `8001`
from the public internet or LAN router.

When Tailscale Serve is enabled for the tailnet, it can replace the socket proxy
with a tailnet-only HTTPS endpoint:

```bash
tailscale serve --bg http://172.17.0.1:8001
```

## Register models in LANCE

For a LANCE application on the same host, use the Docker bridge address:

```bash
cd /home/tanguy/LANCE
python3 src/db/inject_moe.py --base-url http://172.17.0.1:8001/v1
```

For the application on `nato-master`, run the injection from its LANCE checkout
with the tailnet URL:

```bash
python3 src/db/inject_moe.py --base-url http://100.66.221.22:8001/v1
```

By default, the LANCE dashboard receives only `lance-moe`. The HMoE server routes
each phase to the correct expert. Direct expert IDs are useful for debugging and
can be added explicitly:

```bash
python3 src/db/inject_moe.py \
  --base-url http://100.66.221.22:8001/v1 \
  --include-experts
```

`LANCE_MOE_BASE_URL` can be used instead of the command-line option:

```bash
LANCE_MOE_BASE_URL=http://172.17.0.1:8001/v1 python3 src/db/inject_moe.py
```

## Connect OpenWebUI

Open `http://100.66.221.22:3000`, then go to:

```text
Admin settings -> Connections -> OpenAI-compatible APIs -> Add connection
```

Use these values:

| Field | Value |
| --- | --- |
| URL | `http://host.docker.internal:8001/v1` |
| Authentication | `Bearer` |
| API key | `not-needed` |
| API type | `Chat Completions` |
| Model IDs | Leave empty to discover all models |

Save the connection and refresh OpenWebUI. Activating the global OpenAI-compatible
API toggle is not enough: the local URL must also be added with the `+` button.

## Troubleshooting

### Models do not appear

1. Confirm that the local connection, not only the global toggle, was saved.
2. Leave the model-ID filter empty or add the five IDs explicitly.
3. Re-run both `/v1/models` verification commands above.
4. Refresh OpenWebUI after saving the connection.

### Connection refused

```bash
systemctl --user status lance-hmoe.service
ss -ltnp | grep 8001
journalctl --user -u lance-hmoe.service -n 100 --no-pager
```

Confirm that the service listens on the current `docker0` address and that the
OpenWebUI container resolves `host.docker.internal` to the host gateway.
For the remote LANCE application, also check
`systemctl --user status lance-hmoe-tailnet.socket`.

### An adapter is missing

Check the service log for `Loaded adapters`. It must list `recon`, `vuln`,
`exploit`, and `secretary`. If one is absent, verify its final weights, config,
and ACL permissions.

### Ollama does not show the experts

This is expected. Ollama serves its own model registry, while this setup uses the
OpenAI-compatible endpoint implemented by `src/agent/moe_server.py`.
