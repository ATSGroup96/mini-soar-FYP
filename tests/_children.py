"""
Functions that tests run in a SEPARATE process (file lock, parallel audit writers).

A child process does not load conftest.py, so the same safety step is repeated
here before anything from the project is imported: python-dotenv is switched
off, which means the real .env (and its keys) is never read by a test process.
"""
import os
import time

import dotenv

dotenv.load_dotenv = lambda *a, **k: False  # type: ignore[assignment]
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""


def hold_lock(path: str, seconds: float, ready) -> None:
    from common.filelock import file_lock
    with file_lock(path):
        ready.set()
        time.sleep(seconds)


def audit_writer(folder: str, who: int, n: int) -> None:
    os.chdir(folder)
    from common import audit
    for i in range(n):
        audit.log_event(f"proc{who}", "parallel.write", detail={"i": i}, mirror_cloud=False)
