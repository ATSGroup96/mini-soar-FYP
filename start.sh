#!/usr/bin/env bash
# Mini-SOAR — daily start. Usage:
#   ./start.sh          start everything + health check
#   ./start.sh scan     ...and run one scan of the lab
#   ./start.sh update   ...after a new zip: rebuild, sync CVEs, scan
#   ./start.sh stop     stop all containers
#   ./start.sh enroll <ip> [admin]   prepare a target for auto-fix (asks the admin password once)
#   ./start.sh check  <ip>           test if a target is ready for auto-fix
set -uo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-}"     # empty = the whole authorized scope (Settings -> Network scope)
IFACE="${IFACE:-eth1}"   # the lab / host-only adapter of this engine machine
IP=$(ip -4 addr show "$IFACE" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1)
IP="${IP:-$(hostname -I 2>/dev/null | awk '{print $1}')}"
IP="${IP:-localhost}"
ok()   { echo -e "  \e[32m✔\e[0m $*"; }
bad()  { echo -e "  \e[31m✘\e[0m $*"; }

if [ "${1:-}" = "stop" ]; then docker compose down; exit 0; fi

echo "== Mini-SOAR =="
[ -f .env ] && ok ".env found" || { bad ".env missing — copy it back from your backup"; exit 1; }

# ./start.sh enroll <target-ip> [admin-user]   -> prepare a lab host for auto-fix
# ./start.sh check  <target-ip>                -> only test it, change nothing
if [ "${1:-}" = "enroll" ] || [ "${1:-}" = "check" ]; then
  MODE="$1"; T="${2:-}"; ADMIN="${3:-}"
  [ -n "$T" ] || { echo "usage: ./start.sh enroll <target-ip> [admin-user]"; exit 1; }
  KEY=$(grep -E '^SSH_PRIVATE_KEY_PATH=' .env | head -1 | cut -d= -f2- | tr -d ' "')   # a file path, not a secret
  KEY="${KEY:-./secrets/lab_id_rsa}"
  if [ "$MODE" = "enroll" ] && [ ! -f "$KEY" ]; then
    echo "-- no engine SSH key yet: creating $KEY (RSA, works with old servers too)"
    mkdir -p "$(dirname "$KEY")" && ssh-keygen -q -t rsa -b 2048 -m PEM -f "$KEY" -N "" -C mini-soar-engine
    chmod 600 "$KEY"
  fi
  if [ "$MODE" = "check" ]; then
    docker compose run --rm --entrypoint python api -m soar.enroll "$T" --check-only
  elif [ -n "$ADMIN" ]; then
    docker compose run --rm --entrypoint python api -m soar.enroll "$T" --admin-user "$ADMIN"
  else
    docker compose run --rm --entrypoint python api -m soar.enroll "$T"
  fi
  RC=$?
  # convenience: plain "ssh soar@<ip>" from this Kali works with the old-server options
  SSHU=$(grep -E '^SSH_USERNAME=' .env | head -1 | cut -d= -f2- | tr -d ' "')
  if [ $RC -eq 0 ] && ! grep -q "^Host $T\$" ~/.ssh/config 2>/dev/null; then
    mkdir -p ~/.ssh && chmod 700 ~/.ssh
    printf '\nHost %s\n  User %s\n  IdentityFile %s\n  PubkeyAcceptedAlgorithms +ssh-rsa\n  HostKeyAlgorithms +ssh-rsa\n' \
      "$T" "${SSHU:-soar}" "$(readlink -f "$KEY")" >> ~/.ssh/config
    chmod 600 ~/.ssh/config
    ok "added $T to ~/.ssh/config (now: ssh $T)"
  fi
  exit $RC
fi

if [ "${1:-}" = "update" ]; then
  echo "-- rebuilding (first time can take a few minutes)"
  docker compose build || { bad "build failed"; exit 1; }
fi

docker compose up -d >/dev/null 2>&1 && ok "containers started" || { bad "docker compose up failed"; exit 1; }

for i in $(seq 1 20); do
  curl -sf http://localhost:8000/health >/dev/null && break; sleep 1
done
curl -sf http://localhost:8000/health >/dev/null && ok "API healthy" || bad "API not answering (docker compose logs api)"

if [ -n "$TARGET" ]; then
  ping -c1 -W2 "${TARGET%%/*}" >/dev/null 2>&1 && ok "target $TARGET reachable" || bad "target $TARGET not reachable (is the VM on?)"
fi
docker compose run --rm scanner show-scope 2>/dev/null | head -8

if [ "${1:-}" = "update" ]; then
  echo "-- syncing CVEs for the software found in the lab"
  docker compose run --rm --entrypoint python api -m intel.cli sync-cpe
fi

if [ "${1:-}" = "scan" ] || [ "${1:-}" = "update" ]; then
  if [ -n "$TARGET" ]; then
    echo "-- scanning $TARGET (about 1-3 minutes)"
    docker compose run --rm scanner scan --targets "$TARGET"
  else
    echo "-- scanning the whole authorized scope (a few minutes for a /24)"
    docker compose run --rm scanner scan
  fi
fi

echo
echo "Dashboard: http://$IP:3000"
