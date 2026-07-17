FROM python:3.12-slim

WORKDIR /app

# Only worker-side reconnaissance clients are installed.  There is no Ansible,
# Proxmox configuration, benchmark catalogue, ground truth, or controller
# credential mounted at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates nmap openssh-client sshpass netcat-openbsd \
    mosquitto-clients mariadb-client redis-tools openssl traceroute \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY src/ /app/src/

# Remove control-plane, history and local evaluator code from the worker image.
# The remaining skill module imports knowledge lazily, while sealed tool
# resolution rejects every persistent knowledge/cache tool.
RUN rm -rf /app/src/api /app/src/static /app/src/static_v2 /app/src/db \
    /app/src/agent/knowledge /app/src/benchmark/evaluator.py

RUN useradd --create-home --uid 10001 benchmark-worker \
    && mkdir -p /work/output \
    && chown -R benchmark-worker:benchmark-worker /work

USER benchmark-worker

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    WORKER_OUTPUT_DIR=/work/output

# Runtime requirements enforced and tested by the private controller/launcher:
# a fresh --rm container, --read-only, --cap-drop=ALL,
# --security-opt=no-new-privileges, --log-driver=none, --ulimit core=0, a strict
# private network, and tmpfs mounts for /work, /tmp and HOME/XDG (which
# worker.py places below /work). The worker cgroup must disable swap
# (memory.swap.max=0; with Docker, set a memory limit and make --memory-swap
# equal to it). No writable persistent volume may be attached.

ENTRYPOINT ["python3", "-m", "src.agent.worker"]
