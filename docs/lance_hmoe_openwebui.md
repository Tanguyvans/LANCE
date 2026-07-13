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
Adapters: /home/leo/LANCE/output/adapters/lance-qlora_moe
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
sudo setfacl -R -m u:tanguy:rX /home/leo/LANCE/output/adapters/lance-qlora_moe
```

Verify access without changing the files:

```bash
for expert in recon vuln exploit secretary; do
  test -r "/home/leo/LANCE/output/adapters/lance-qlora_moe/$expert/adapter_model.safetensors" \
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
  --base-model Qwen/Qwen2.5-0.5B-Instruct \
  --adapters-dir /home/leo/LANCE/output/adapters/lance-qlora_moe \
  --host 172.17.0.1 \
  --port 8001
```

Do not bind this unauthenticated API to `0.0.0.0` unless authentication and
firewall rules are added first.

## Persistent systemd service

Create `~/.config/systemd/user/lance-hmoe.service`:

```ini
[Unit]
Description=LANCE Hybrid Mixture of Experts API
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/tanguy/LANCE
Environment=PYTHONPATH=/home/tanguy/.local/share/lance-hmoe/site-packages
Environment=PYTHONUNBUFFERED=1
Environment=TOKENIZERS_PARALLELISM=false
ExecStart=/home/leo/LANCE/env/bin/python /home/tanguy/LANCE/src/agent/moe_server.py --base-model Qwen/Qwen2.5-0.5B-Instruct --adapters-dir /home/leo/LANCE/output/adapters/lance-qlora_moe --host 172.17.0.1 --port 8001
Restart=on-failure
RestartSec=5
KillSignal=SIGINT
TimeoutStopSec=30

[Install]
WantedBy=default.target
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

## Register models in LANCE

The host-side LANCE registry uses the Docker bridge address because the API is
bound to that interface:

```bash
cd /home/tanguy/LANCE
python3 src/db/inject_moe.py --base-url http://172.17.0.1:8001/v1
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

### An adapter is missing

Check the service log for `Loaded adapters`. It must list `recon`, `vuln`,
`exploit`, and `secretary`. If one is absent, verify its final weights, config,
and ACL permissions.

### Ollama does not show the experts

This is expected. Ollama serves its own model registry, while this setup uses the
OpenAI-compatible endpoint implemented by `src/agent/moe_server.py`.
