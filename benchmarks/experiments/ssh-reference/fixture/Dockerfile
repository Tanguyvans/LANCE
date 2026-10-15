FROM python:3.12-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_*
COPY start.py /start.py
EXPOSE 22
ENTRYPOINT ["python3", "/start.py"]
