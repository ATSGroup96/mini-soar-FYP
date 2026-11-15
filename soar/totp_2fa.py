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


# --- secret storage helpers (encrypt-at-rest) --------------------------------
def seal_secret(secret: str) -> str:
    return encrypt(secret.encode())


def open_secret(sealed: str) -> str:
    return decrypt(sealed).decode()
