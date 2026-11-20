"""
Run one engine service with its output in logs/<name>.log (used by start.ps1
in NETWORK_MODE=native on Windows, where there is no Docker to collect logs).

    python -m common.svc api      uvicorn api.main:app --host 0.0.0.0 --port 8000
    python -m common.svc soar     soar.worker

stdout and stderr both go to the same file (appended, line-buffered), so
`start.ps1 logs api` shows prints, uvicorn access logs and tracebacks together.
"""
from __future__ import annotations

import os
import runpy
import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: python -m common.svc <log-name> <module> [args...]")
        return 1
    name, module, rest = argv[0], argv[1], argv[2:]
    os.makedirs("logs", exist_ok=True)
    log = open(os.path.join("logs", f"{name}.log"), "a", buffering=1,
               encoding="utf-8", errors="replace")
    sys.stdout = sys.stderr = log
    print(f"===== {time.strftime('%Y-%m-%d %H:%M:%S')} starting {module} {' '.join(rest)} =====")
    sys.argv = [module] + rest
    try:
        runpy.run_module(module, run_name="__main__", alter_sys=True)
    except SystemExit as e:
        return int(e.code or 0) if isinstance(e.code, int) or e.code is None else 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
