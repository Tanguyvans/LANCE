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

# System recon and offensive tools used by the agent pipeline
# (Packages available in Debian 12 main. nikto/wpscan/exploitdb/enum4linux-ng
# are NOT in Debian main and are installed below via pip/git.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    mosquitto-clients \
    openssh-client \
    iputils-ping \
    sshpass \
    netcat-openbsd \
    mariadb-client \
    dnsutils \
    smbclient \
    openssl \
    sqlmap \
    gobuster \
    whatweb \
    default-jre-headless \
    perl \
    wget curl ca-certificates unzip git \
    && rm -rf /var/lib/apt/lists/*

# enum4linux-ng + netexec (nxc) via pip (not in Debian main repos)
RUN pip install --no-cache-dir --break-system-packages enum4linux-ng netexec 2>/dev/null \
    || pip install --no-cache-dir enum4linux-ng netexec \
    || true

# Nikto (Perl script) — clone from upstream, not packaged on Debian main
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto

# Exploit-DB (searchsploit) — clone from upstream, not packaged on Debian main
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /opt/exploitdb \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit

# Nuclei: download the official static binary (apt's nuclei lags upstream)
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      amd64) NUCLEI_ARCH=amd64 ;; \
      arm64) NUCLEI_ARCH=arm64 ;; \
      *) NUCLEI_ARCH=amd64 ;; \
    esac && \
    wget -q -O /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.5/nuclei_3.3.5_linux_${NUCLEI_ARCH}.zip" && \
    cd /tmp && unzip -q nuclei.zip && mv nuclei /usr/local/bin/ && \
    rm -f /tmp/nuclei.zip /tmp/LICENSE* /tmp/README* && \
    nuclei -update-templates -silent 2>/dev/null || true

# Ysoserial JAR for Java deserialization payloads (CVE-2023-46604, etc.)
RUN mkdir -p /opt/tools && \
    wget -q -O /opt/tools/ysoserial.jar \
      "https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar"
ENV YSOSERIAL_JAR=/opt/tools/ysoserial.jar

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
