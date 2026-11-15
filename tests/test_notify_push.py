"""Notifications + web push, the launcher helpers, and project hygiene checks."""
import ast
import base64
import json
import sys
import types
from pathlib import Path

import pytest

from common import webpush
from common.notify import notify

ROOT = Path(__file__).resolve().parent.parent


# ---- notifications -----------------------------------------------------------
def test_notify_stores_a_row(supa):
    out = notify(supa, "high", "Rogue device", "192.168.56.50 appeared", "/assets")
    assert out["stored"] is True
    assert supa.rows("notifications")[0] == dict(supa.rows("notifications")[0], level="high",
                                                 title="Rogue device", link="/assets")


def test_notify_never_raises(supa):
    supa.fail_tables.add("notifications")
    assert notify(supa, "high", "x")["stored"] is False
    assert notify(None, "high", "x")["stored"] is False


def test_unknown_level_becomes_info(supa):
    notify(supa, "shouting", "x")
    assert supa.rows("notifications")[0]["level"] == "info"


# ---- web push ----------------------------------------------------------------
@pytest.fixture
def fake_pywebpush(monkeypatch, set_env):
    """Stand-in for the pywebpush package: records what would be sent."""
    sent = []

    class WebPushException(Exception):
        def __init__(self, msg, response=None):
            super().__init__(msg)
            self.response = response

    def webpush_fn(subscription_info, data, vapid_private_key, vapid_claims, ttl=0):
        ep = subscription_info["endpoint"]
        if "gone" in ep:
            raise WebPushException("410", response=types.SimpleNamespace(status_code=410))
        if "broken" in ep:
            raise WebPushException("500", response=types.SimpleNamespace(status_code=500))
        sent.append({"endpoint": ep, "data": json.loads(data), "key": vapid_private_key,
                     "claims": vapid_claims, "keys": subscription_info["keys"]})

    mod = types.ModuleType("pywebpush")
    mod.webpush, mod.WebPushException = webpush_fn, WebPushException
    monkeypatch.setitem(sys.modules, "pywebpush", mod)
    set_env(VAPID_PRIVATE_KEY="test-private-key", VAPID_SUBJECT="mailto:soc@lab.local")
    return sent


def subscribe(supa, endpoint):
    supa.add("push_subscriptions", user_id="u1", endpoint=endpoint, p256dh="P", auth="A")


def test_push_is_skipped_when_not_configured(supa):
    subscribe(supa, "https://push.example/ok")
    assert webpush.is_configured() is False
    assert webpush.send_to_all(supa, "t", "b") == {"sent": 0, "failed": 0, "removed": 0}


def test_push_goes_to_every_subscription(supa, fake_pywebpush):
    subscribe(supa, "https://push.example/phone")
    subscribe(supa, "https://push.example/laptop")
    out = notify(supa, "high", "Rogue device", "192.168.56.50 appeared", "/assets")
    assert out["push"] == {"sent": 2, "failed": 0, "removed": 0}
    msg = fake_pywebpush[0]
    assert msg["data"] == {"title": "Rogue device", "body": "192.168.56.50 appeared", "link": "/assets"}
    assert msg["key"] == "test-private-key" and msg["claims"] == {"sub": "mailto:soc@lab.local"}
    assert msg["keys"] == {"p256dh": "P", "auth": "A"}


def test_low_level_notifications_are_not_pushed(supa, fake_pywebpush):
    subscribe(supa, "https://push.example/phone")
    notify(supa, "info", "Remediation applied and verified")
    notify(supa, "low", "Software version changed")
    assert fake_pywebpush == [] and len(supa.rows("notifications")) == 2


def test_dead_subscription_is_removed_and_errors_do_not_stop_others(supa, fake_pywebpush):
    for ep in ("https://push.example/gone", "https://push.example/broken", "https://push.example/ok"):
        subscribe(supa, ep)
    out = webpush.send_to_all(supa, "t", "b")
    assert out == {"sent": 1, "failed": 1, "removed": 1}
    assert sorted(s["endpoint"] for s in supa.rows("push_subscriptions")) == [
        "https://push.example/broken", "https://push.example/ok"]


def test_generated_vapid_keys_have_the_right_shape():
    keys = webpush.generate_vapid_keys()

    def raw(v):
        return base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    assert len(raw(keys["VAPID_PRIVATE_KEY"])) == 32
    pub = raw(keys["NEXT_PUBLIC_VAPID_PUBLIC_KEY"])
    assert len(pub) == 65 and pub[0] == 4                 # uncompressed P-256 point
    assert webpush.generate_vapid_keys() != keys


def test_gen_keys_command(capsys):
    assert webpush.main(["gen-keys"]) == 0
    out = capsys.readouterr().out
    assert "VAPID_PRIVATE_KEY=" in out and "NEXT_PUBLIC_VAPID_PUBLIC_KEY=" in out
    assert webpush.main([]) == 1


# ---- launcher helpers --------------------------------------------------------
def test_sync_lab_runs_all_feeds_and_survives_one_failure(monkeypatch):
    from intel import cli, sync_cpe, sync_epss, sync_kev
    monkeypatch.setattr(sync_kev, "sync", lambda: 1100)
    monkeypatch.setattr(sync_cpe, "sync", lambda cpes=None: 42)

    def epss_down():
        raise RuntimeError("no internet")
    monkeypatch.setattr(sync_epss, "sync", epss_down)
    r = cli.sync_lab()
    assert r["kev"] == {"ok": True, "rows": 1100} and r["cpe"] == {"ok": True, "rows": 42}
    assert r["epss"]["ok"] is False and "no internet" in r["epss"]["error"]
    assert cli.main(["sync-lab"]) == 1
    monkeypatch.setattr(sync_epss, "sync", lambda: 250000)
    assert cli.main(["sync-lab"]) == 0


def test_intel_status_counts():
    from intel import cli
    s = cli.intel_status()
    assert (s["cves"], s["kev"], s["epss"]) == (0, 0, 0) and s["last_sync"] == {}


def test_train_if_missing_skips_existing_model(capsys):
    from ml import train
    from ml.model import META_PATH, MODEL_DIR, MODEL_PATH
    MODEL_DIR.mkdir(parents=True)
    MODEL_PATH.write_bytes(b"x")
    META_PATH.write_text("{}")
    assert train.main(["--if-missing"]) == 0
    assert "already trained" in capsys.readouterr().out


def test_train_without_torch_says_so(capsys):
    from ml import model, train
    if model._HAVE_TORCH:
        pytest.skip("PyTorch is installed here")
    assert train.main(["--if-missing"]) == 1
    assert "formula stays in use" in capsys.readouterr().out


def test_service_runner_writes_log(tmp_path, monkeypatch):
    import runpy
    from common import svc
    monkeypatch.setattr(sys, "stdout", sys.stdout)
    monkeypatch.setattr(sys, "stderr", sys.stderr)
    monkeypatch.setattr(sys, "argv", list(sys.argv))
    monkeypatch.setattr(runpy, "run_module", lambda *a, **k: print("service says hello"))
    assert svc.main(["demo", "some.module", "--flag"]) == 0
    sys.stdout.flush()
    text = (tmp_path / "logs" / "demo.log").read_text()
    assert "starting some.module --flag" in text and "service says hello" in text
    sys.stdout.close()                       # the log file (Windows cannot delete an open file)


# ---- project hygiene ---------------------------------------------------------
PY_FILES = [p for p in ROOT.rglob("*.py")
            if not {".venv", "node_modules", ".next", ".git"} & set(p.parts)]


def test_every_python_file_compiles():
    for p in PY_FILES:
        ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
    assert len(PY_FILES) > 60


# start of a Supabase JWT / a private key file (split so this file does not match itself)
SECRET_MARKERS = ("eyJ" + "hbGciOi", "BEGIN RSA " + "PRIVATE KEY", "BEGIN OPENSSH " + "PRIVATE KEY")


def test_no_secret_is_committed_in_source():
    """Keys belong in .env only (which git ignores)."""
    bad = []
    for p in PY_FILES + list((ROOT / "dashboard").glob("lib/*.ts")):
        text = p.read_text(encoding="utf-8", errors="replace")
        if any(marker in text for marker in SECRET_MARKERS):
            bad.append(str(p.relative_to(ROOT)))
    assert bad == []
    ignore = (ROOT / ".gitignore").read_text()
    for line in (".env", "secrets/", "data/", "logs/", ".venv/"):
        assert line in ignore


def test_env_example_lists_every_setting_without_values():
    example = (ROOT / ".env.example").read_text()
    for key in ("ALLOWED_RANGES", "AUTHORIZED_LAB_ONLY", "SUPABASE_SERVICE_ROLE_KEY", "AES_KEY_B64",
                "HMAC_KEY", "SSH_USERNAME", "NETWORK_MODE", "VAPID_PRIVATE_KEY",
                "NEXT_PUBLIC_VAPID_PUBLIC_KEY", "SCAN_HOST_TIMEOUT", "FORCE_DRY_RUN"):
        assert f"{key}=" in example
    assert "eyJ" not in example


def test_schema_and_migration_define_the_new_tables():
    for f in ("supabase/schema.sql", "supabase/migrations/004_trend_changes.sql"):
        sql = (ROOT / f).read_text()
        for table in ("risk_history", "asset_changes"):
            assert f"create table if not exists public.{table}" in sql
            assert f"alter table public.{table}" in sql and "enable row level security" in sql


def test_requirements_pin_every_package():
    for line in (ROOT / "requirements.txt").read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            assert "==" in line, f"unpinned requirement: {line}"
    # push is optional, so its package lives in its own file
    assert "pywebpush==" in (ROOT / "requirements-push.txt").read_text()
    assert "pywebpush" not in (ROOT / "requirements.txt").read_text()
