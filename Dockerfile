# Stage 1: build Python dependencies (compiles C extensions like hnswlib for ARM64)
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc g++ cmake \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt \
    && pip install --no-cache-dir --prefix=/install ssh-audit

# Stage 2: runtime image
FROM python:3.12-slim

WORKDIR /app

# System recon tools used by the agent pipeline (Phase 2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    mosquitto-clients \
    openssh-client \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled Python packages from builder
COPY --from=builder /install /usr/local

# Application source (benchmarks and tests excluded via .dockerignore)
COPY src/ ./src/
COPY infrastructure/ ./infrastructure/

# Override static files with the Docker-specific frontend (no benchmark, no scenario management)
COPY src/static_docker/index.html ./src/static/index.html
COPY src/static_docker/app.js ./src/static/app.js

# Persistent directories (mounted as volumes at runtime)
RUN mkdir -p data output/agent

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

ENTRYPOINT ["/entrypoint.sh"]
