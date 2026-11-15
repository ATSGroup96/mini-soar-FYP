"""
Run the SSH + HTTP honeypots together (the honeypot container entrypoint).

  python -m honeypot.run
"""
from __future__ import annotations

import threading

from common import syslog_logger as slog
from . import ssh_honeypot, http_honeypot


def main() -> None:
    slog.send("honeypots starting (fake SSH:2222, HTTP:8081)", slog.NOTICE)
    threads = [
        threading.Thread(target=ssh_honeypot.serve, daemon=True),
        threading.Thread(target=http_honeypot.serve, daemon=True),
    ]
    for t in threads:
        t.start()
    print("Honeypots running. Ctrl-C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("stopping honeypots")


if __name__ == "__main__":
    main()
