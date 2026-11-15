"""
AES-256-GCM encryption + HMAC-SHA256 signing for scan results.

Every scan bundle is stored encrypted (AES-256-GCM) together with an HMAC
signature. The signature is checked whenever a stored bundle is read back
(scanner/uplink.py: load_bundle / verify_stored_bundles), so a file that was
edited, swapped or produced with another key is rejected.
"""
from __future__ import annotations

import os
import json
import time
import hmac
import base64
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import get_settings


def _aes_key() -> bytes:
    key = get_settings().aes_key
    if len(key) != 32:
        raise ValueError(
            "AES_KEY_B64 must decode to exactly 32 bytes. "
            "Generate one with: python -c \"import os,base64;"
            "print(base64.b64encode(os.urandom(32)).decode())\""
        )
    return key


def encrypt(plaintext: bytes, aad: bytes = b"") -> str:
    """AES-256-GCM encrypt -> base64( nonce(12) || ciphertext || tag )."""
    key = _aes_key()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce + ct).decode()


def decrypt(blob_b64: str, aad: bytes = b"") -> bytes:
    key = _aes_key()
    raw = base64.b64decode(blob_b64)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def encrypt_json(obj) -> str:
    return encrypt(json.dumps(obj, separators=(",", ":")).encode())


def decrypt_json(blob_b64: str):
    return json.loads(decrypt(blob_b64).decode())


# ----------------------------------------------------------------------------
# HMAC request signing
# ----------------------------------------------------------------------------
def sign_payload(body: bytes, timestamp: int | None = None) -> dict:
    """
    Produce headers proving the payload came from the trusted scanner and was
    not modified or replayed. Receiver recomputes the HMAC over ts + body.
    """
    key = get_settings().hmac_key.encode()
    if not key:
        raise ValueError("HMAC_KEY is not set.")
    ts = str(timestamp or int(time.time()))
    mac = hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Soar-Timestamp": ts, "X-Soar-Signature": mac}


def verify_signature(body: bytes, timestamp: str, signature: str,
                     max_skew_seconds: int | None = 300) -> bool:
    """
    True only if the signature was made with our HMAC key over this exact
    timestamp + body. `max_skew_seconds` rejects old (replayed) messages; pass
    None when checking a bundle stored on disk, where age does not matter.
    """
    key = get_settings().hmac_key.encode()
    if not key:
        return False  # no key configured -> nothing can be trusted
    try:
        age = abs(int(time.time()) - int(timestamp))
    except (TypeError, ValueError):
        return False
    if max_skew_seconds is not None and age > max_skew_seconds:
        return False  # replay / stale
    expected = hmac.new(key, str(timestamp).encode() + b"." + body,
                        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, str(signature or ""))
