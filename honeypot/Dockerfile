# =============================================================================
# Honeypot container — low-interaction fake SSH + HTTP decoys.
# Purely defensive: it only LOGS connection attempts and credentials tried,
# then looks the source IP up against AbuseIPDB / OTX. It never grants a shell.
# =============================================================================
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir \
        cryptography==42.0.8 \
        requests==2.32.3 \
        supabase==2.6.0 \
        python-dotenv==1.0.1 \
        rich==13.7.1 \
        paramiko==3.4.0

COPY honeypot/ /app/honeypot/
COPY common/   /app/common/

RUN useradd -m -u 10002 pot && chown -R pot:pot /app
USER pot

ENTRYPOINT ["python", "-m", "honeypot.run"]
