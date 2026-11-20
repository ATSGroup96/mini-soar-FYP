"""
Who is calling the API? (server-side check of the dashboard login)

The dashboard signs in with Supabase Auth and sends the user's access token as
"Authorization: Bearer <token>" with every API call. The gateway never trusts
a user id written in the request body: it asks Supabase who the token belongs
to, then loads that user's role from public.profiles.

Two ways to check a token:
  * SUPABASE_JWT_SECRET set in .env (Supabase -> Project Settings -> API ->
    JWT secret, legacy HS256 projects): checked locally, no network call.
  * otherwise: GET <SUPABASE_URL>/auth/v1/user with the token (Supabase
    answers 401 for a fake, expired or signed-out token).
A good answer is remembered for a short time so the dashboard stays fast.
"""
from __future__ import annotations

import hashlib
import threading
import time

from .config import get_settings, _get

CACHE_SECONDS = 60
ROLES = ("viewer", "analyst", "admin")

_cache: dict[str, tuple[str, float]] = {}
_lock = threading.Lock()


class AuthError(Exception):
    """status 401 = not signed in, 403 = signed in but not allowed, 503 = no cloud."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _verify_local(token: str, secret: str) -> str:
    import jwt   # PyJWT (installed with the supabase package)
    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"], audience="authenticated")
    except Exception as e:
        raise AuthError(401, f"invalid or expired login ({type(e).__name__})")
    if not claims.get("sub"):
        raise AuthError(401, "login token has no user")
    return str(claims["sub"])


def _verify_remote(token: str) -> str:
    import requests
    s = get_settings()
    key = s.supabase_anon_key or s.supabase_service_role_key
    if not s.supabase_url or not key:
        raise AuthError(503, "Supabase not configured")
    try:
        r = requests.get(f"{s.supabase_url.rstrip('/')}/auth/v1/user", timeout=10,
                         headers={"apikey": key, "Authorization": f"Bearer {token}"})
    except Exception as e:
        raise AuthError(503, f"cannot reach Supabase to check the login ({type(e).__name__})")
    if r.status_code != 200:
        raise AuthError(401, "invalid or expired login, sign in again")
    uid = (r.json() or {}).get("id")
    if not uid:
        raise AuthError(401, "login token has no user")
    return str(uid)


def verify_token(token: str) -> str:
    """User id of a valid Supabase access token (raises AuthError)."""
    secret = _get("SUPABASE_JWT_SECRET")
    if secret:
        try:
            import jwt  # noqa: F401
        except ImportError:
            secret = ""                     # PyJWT missing: ask Supabase instead
    return _verify_local(token, secret) if secret else _verify_remote(token)


def user_id_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise AuthError(401, "not signed in (missing Authorization: Bearer token)")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise AuthError(401, "not signed in")
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    with _lock:
        hit = _cache.get(digest)
        if hit and hit[1] > now:
            return hit[0]
    uid = verify_token(token)
    with _lock:
        if len(_cache) > 1000:
            _cache.clear()
        _cache[digest] = (uid, now + CACHE_SECONDS)
    return uid


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def profile_for(client, user_id: str) -> dict:
    rows = client.table("profiles").select("*").eq("id", user_id).execute().data
    if not rows:
        raise AuthError(403, "this login has no Mini-SOAR profile")
    return rows[0]


def require(client, authorization: str | None, role: str = "viewer") -> dict:
    """The caller's profile, if signed in with at least `role`."""
    if client is None:
        raise AuthError(503, "Supabase not configured")
    prof = profile_for(client, user_id_from_header(authorization))
    have = ROLES.index(prof.get("role")) if prof.get("role") in ROLES else -1
    if have < ROLES.index(role):
        raise AuthError(403, f"this needs the '{role}' role (you are '{prof.get('role')}')")
    return prof
