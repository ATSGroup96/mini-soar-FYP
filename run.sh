#!/usr/bin/env bash
# =============================================================================
#  Mini-SOAR / CAASM Platform - one-command launcher (Linux, e.g. Kali VM)
#  Scans/fixes only ever touch ALLOWED_RANGES in your .env.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "======================================================"
echo "  Mini-SOAR / CAASM Platform"
echo "======================================================"

command -v docker >/dev/null 2>&1 || { echo "[ERROR] Docker not installed."; exit 1; }
docker info >/dev/null 2>&1 || { echo "[ERROR] Docker not running (or user not in docker group - reboot after usermod)."; exit 1; }

if [ ! -f .env ]; then
  cp .env.example .env
  echo "[setup] Created .env from .env.example. Edit it, then run ./run.sh again:"
  echo "  ALLOWED_RANGES, DENY_HOSTS, AUTHORIZED_LAB_ONLY=true, AES_KEY_B64, HMAC_KEY,"
  echo "  SUPABASE_*, NEXT_PUBLIC_SUPABASE_*, NEXT_PUBLIC_API_URL=http://<this-VM-lab-IP>:8000"
  exit 0
fi

# --- sanity checks on .env ---------------------------------------------------
grep -q '^AUTHORIZED_LAB_ONLY=true' .env || { echo "[ERROR] Set AUTHORIZED_LAB_ONLY=true in .env"; exit 1; }
if grep -q 'GENERATE-A' .env; then
  echo "[ERROR] AES_KEY_B64 / HMAC_KEY are still placeholders in .env. Generate them:"
  echo '  python3 -c "import os,base64;print(base64.b64encode(os.urandom(32)).decode())"'
  echo '  python3 -c "import secrets;print(secrets.token_hex(32))"'
  exit 1
fi
if grep -q '^NEXT_PUBLIC_API_URL=http://localhost' .env; then
  echo "[WARN] NEXT_PUBLIC_API_URL uses localhost. If you open the dashboard from"
  echo "       another machine (e.g. Windows), set it to http://<this-VM-lab-IP>:8000"
fi
mkdir -p data audit reports/out secrets

ENGINE_PY=(docker compose run --rm --entrypoint python api)

echo "[build] Building containers (first time takes a while)..."
docker compose build

read -r -p "Download CVE intel (NVD full + EPSS + KEV) and train the ML model now? [y/N] " ans
if [[ "${ans:-N}" =~ ^[Yy]$ ]]; then
  "${ENGINE_PY[@]}" -m intel.cli init
  "${ENGINE_PY[@]}" -m intel.cli sync-all --full
  "${ENGINE_PY[@]}" -m intel.cli stats
  "${ENGINE_PY[@]}" -m ml.train
fi

echo "[up] Starting API, SOAR worker, honeypot and dashboard..."
docker compose up -d api soar honeypot dashboard

LABIP=$(ip -4 -o addr show 2>/dev/null | awk '$4 ~ /^192\.168\.56\./ {split($4,a,"/"); print a[1]; exit}')
LABIP=${LABIP:-<this-VM-IP>}
echo "======================================================"
echo "  Dashboard : http://${LABIP}:3000"
echo "  API       : http://${LABIP}:8000/health"
echo "  Honeypot  : SSH :2222   HTTP :8081"
echo "======================================================"
echo "Scope check : docker compose run --rm scanner show-scope"
echo "Scan        : docker compose run --rm scanner scan --scope env"
echo "Logs        : docker compose logs -f api      Stop: docker compose down"
