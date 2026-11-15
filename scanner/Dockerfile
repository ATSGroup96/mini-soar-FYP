# =============================================================================
# Mini-SOAR engine image — used by the scanner, soar worker and API gateway.
# Includes nmap (for python-nmap), libpcap (scapy) and the SSH client.
#
# Runs as root INSIDE the container because ARP discovery, SYN scans and OS
# detection need raw sockets. Scope is still enforced in code
# (common/allowlist.py) before any packet is sent.
# =============================================================================
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        libpcap0.8 \
        openssh-client \
        iproute2 \
        iputils-ping \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# CPU-only PyTorch first (the default PyPI wheel pulls GBs of CUDA libraries)
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.3.1

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
# optional: web push notifications (the engine works without it)
COPY requirements-push.txt /app/requirements-push.txt
RUN pip install --no-cache-dir -r /app/requirements-push.txt \
    || echo "pywebpush not installed: push notifications stay off"

COPY common/   /app/common/
COPY scanner/  /app/scanner/
COPY intel/    /app/intel/
COPY ml/       /app/ml/
COPY soar/     /app/soar/
COPY syslog/   /app/syslog/
COPY reports/  /app/reports/
COPY api/      /app/api/

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "scanner.cli"]
CMD ["--help"]
