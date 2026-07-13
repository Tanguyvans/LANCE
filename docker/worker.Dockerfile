FROM python:3.12-slim

WORKDIR /app

# Only worker-side reconnaissance clients are installed.  There is no Ansible,
# Proxmox configuration, benchmark catalogue, ground truth, or controller
# credential mounted at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates nmap libcap2-bin openssh-client sshpass netcat-openbsd \
    mosquitto-clients mariadb-client redis-tools openssl traceroute \
    && setcap cap_net_raw+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY src/ /app/src/

RUN useradd --create-home --uid 10001 benchmark-worker \
    && mkdir -p /work/output \
    && chown -R benchmark-worker:benchmark-worker /work

USER benchmark-worker

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    WORKER_OUTPUT_DIR=/work/output

ENTRYPOINT ["python3", "-m", "src.agent.worker"]
