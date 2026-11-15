"""
Web Push sender (PWA push notifications).

The dashboard stores each browser's push subscription in public.push_subscriptions
(Settings -> "Enable push on this device"). Whenever the engine raises a
notification, this module sends it to every stored subscription, so the alert
shows up even when the dashboard tab is closed.

Needs (all optional - without them push is simply skipped, nothing breaks):
  * the `pywebpush` package (requirements-push.txt; the launcher installs it)
  * a VAPID key pair in .env:
        VAPID_PRIVATE_KEY=...               (engine only, keep secret)
        NEXT_PUBLIC_VAPID_PUBLIC_KEY=...    (dashboard)
        VAPID_SUBJECT=mailto:you@example.com
    Create the pair once with:   python -m common.webpush gen-keys
"""
from __future__ import annotations

import base64
import json
import os
import sys

DEFAULT_SUBJECT = "mailto:admin@mini-soar.local"
# push services answer 404/410 when a browser unsubscribed: forget that device
_GONE = (404, 410)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_vapid_keys() -> dict:
    """New P-256 key pair in the formats the browser and pywebpush expect."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    private = key.private_numbers().private_value.to_bytes(32, "big")
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return {"VAPID_PRIVATE_KEY": _b64url(private),
            "NEXT_PUBLIC_VAPID_PUBLIC_KEY": _b64url(public)}


def _private_key() -> str:
    return (os.environ.get("VAPID_PRIVATE_KEY", "") or "").strip()


def is_configured() -> bool:
    """True when a VAPID private key is set and pywebpush can be imported."""
    if not _private_key():
        return False
    try:
        import pywebpush  # noqa: F401
    except Exception:
        return False
    return True


def send_to_all(client, title: str, body: str = "", link: str = "/dashboard") -> dict:
    """
    Push one message to every subscribed browser. Never raises: a push problem
    must not break a scan or a remediation. Returns {"sent", "failed", "removed"}.
    """
    result = {"sent": 0, "failed": 0, "removed": 0}
    if client is None or not is_configured():
        return result
    try:
        from pywebpush import webpush, WebPushException
        subs = client.table("push_subscriptions").select("*").execute().data or []
    except Exception:
        return result
    payload = json.dumps({"title": title, "body": body or "", "link": link or "/dashboard"})
    claims = {"sub": (os.environ.get("VAPID_SUBJECT", "") or "").strip() or DEFAULT_SUBJECT}
    for sub in subs:
        info = {"endpoint": sub.get("endpoint"),
                "keys": {"p256dh": sub.get("p256dh"), "auth": sub.get("auth")}}
        try:
            webpush(subscription_info=info, data=payload,
                    vapid_private_key=_private_key(), vapid_claims=dict(claims), ttl=3600)
            result["sent"] += 1
        except WebPushException as e:
            status = getattr(getattr(e, "response", None), "status_code", None)
            if status in _GONE:
                try:
                    client.table("push_subscriptions").delete().eq(
                        "endpoint", sub.get("endpoint")).execute()
                    result["removed"] += 1
                except Exception:
                    pass
            else:
                result["failed"] += 1
        except Exception:
            result["failed"] += 1
    return result


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["gen-keys"]:
        print("# add these lines to .env (then rebuild / restart the dashboard):")
        for k, v in generate_vapid_keys().items():
            print(f"{k}={v}")
        print(f"VAPID_SUBJECT={DEFAULT_SUBJECT}")
        return 0
    if argv[:1] == ["test"]:
        from .db import get_service_client
        client = get_service_client()
        if not client:
            print("Supabase is not configured.")
            return 1
        if not is_configured():
            print("Push is not set up: VAPID_PRIVATE_KEY missing or pywebpush not installed.")
            return 1
        print(send_to_all(client, "Mini-SOAR test", "Push notifications work.", "/dashboard"))
        return 0
    print("usage: python -m common.webpush gen-keys | test")
    return 1


if __name__ == "__main__":
    sys.exit(main())
