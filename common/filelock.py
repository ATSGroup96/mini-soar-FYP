"""
Cross-platform exclusive file lock (Linux: fcntl, Windows: msvcrt).

Used for "one scan at a time" (data/.scan.lock) and for the audit hash chain
(audit/.lock), because the scanner, API and SOAR worker are separate
processes that share these files - in Docker containers on Linux, or as plain
processes on Windows (NETWORK_MODE=native).

    with file_lock("data/.scan.lock", blocking=False):   # raises LockBusy
        ...
"""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path


class LockBusy(RuntimeError):
    """The lock is held by another process (non-blocking mode only)."""


@contextmanager
def file_lock(path, blocking: bool = True, poll: float = 0.05):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+")
    locked = False
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            while True:
                try:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                    locked = True
                    break
                except OSError:
                    if not blocking:
                        raise LockBusy(str(path))
                    time.sleep(poll)
        else:
            import fcntl
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(fh, flags)
                locked = True
            except BlockingIOError:
                raise LockBusy(str(path))
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    import msvcrt
                    fh.seek(0)
                    msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fh, fcntl.LOCK_UN)
            except OSError:
                pass
        fh.close()
