# =============================================================================
# Mini-SOAR engine image — used by the scanner, soar worker and API gateway.
# Includes nmap (for python-nmap), libpcap (scapy), the SSH client, Nuclei
# (template checks) and NetExec (read-only SMB / RDP / WinRM posture checks).
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
        git \
    && rm -rf /var/lib/apt/lists/*

# --- Nuclei: the binary from ProjectDiscovery's official image + its templates
COPY --from=projectdiscovery/nuclei:latest /usr/local/bin/nuclei /usr/local/bin/nuclei
RUN nuclei -update-templates -silent -duc \
    || echo "nuclei templates not downloaded: Nuclei checks are skipped until they are"

# --- NetExec in its own environment (its many dependencies must not clash with
#     the engine's); the engine only ever runs its read-only checks
RUN python -m venv /opt/netexec \
    && /opt/netexec/bin/pip install --no-cache-dir git+https://github.com/Pennyw0rth/NetExec \
    || echo "NetExec not installed: SMB / RDP / WinRM posture checks are skipped"
ENV NETEXEC_PATH=/opt/netexec/bin/nxc

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
