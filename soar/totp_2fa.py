"""
TOTP (Google Authenticator) two-factor for approving remediations.

Enrollment returns a provisioning URI + QR the admin scans once. Thereafter a
remediation can only execute if a fresh 6-digit code verifies. Secrets are
AES-encrypted before being stored (see common.crypto), never kept in plaintext.
"""
from __future__ import annotations

import io
import base64

import pyotp

from common.config import get_settings
from common.crypto import encrypt, decrypt


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_name: str) -> str:
    issuer = get_settings().totp_issuer
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def qr_png_base64(uri: str) -> str:
    """Return a base64 PNG data URI of the enrollment QR for the dashboard."""
    import qrcode
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def verify(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP code. valid_window=1 tolerates ~30s clock skew."""
    if not (secret and code):
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=valid_window)


def matched_step(secret: str, code: str, valid_window: int = 1, now: float | None = None):
    """The 30-second time step the code belongs to (None = wrong code). Stored
    after a successful use, so the same code can never be used twice."""
    import hmac
    import time as _time
    if not (secret and code):
        return None
    code = code.strip()
    totp = pyotp.TOTP(secret)
    t = int(now if now is not None else _time.time())
    step = t // totp.interval
    for s in range(step - valid_window, step + valid_window + 1):
        if hmac.compare_digest(totp.at(s * totp.interval), code):
            return s
    return None


# --- secret storage helpers (encrypt-at-rest) --------------------------------
def seal_secret(secret: str) -> str:
    return encrypt(secret.encode())


def open_secret(sealed: str) -> str:
    return decrypt(sealed).decode()


# --- recovery (run on the engine machine) ------------------------------------
def reset(email: str) -> bool:
    """
    Remove a user's 2FA so they can enrol again (lost phone, deleted entry).
    Only possible on the engine machine, which holds the service key:
        python -m soar.totp_2fa reset someone@example.com
    """
    from common.audit import log_event
    from common.db import get_service_client
    client = get_service_client()
    if not client:
        raise RuntimeError("Supabase is not configured")
    rows = client.table("profiles").select("id,email").eq("email", email).execute().data
    if not rows:
        return False
    client.table("profiles").update(
        {"totp_secret": None, "totp_enrolled": False}).eq("id", rows[0]["id"]).execute()
    log_event("admin-cli", "totp.reset", email)
    return True


def main(argv: list[str] | None = None) -> int:
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) == 2 and argv[0] == "reset":
        try:
            done = reset(argv[1])
        except RuntimeError as e:
            print(e)
            return 1
        print(f"2FA removed for {argv[1]}. Open Settings -> Enroll TOTP 2FA and scan the new QR."
              if done else f"No user with email {argv[1]}.")
        return 0 if done else 1
    print("usage: python -m soar.totp_2fa reset <email>")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
