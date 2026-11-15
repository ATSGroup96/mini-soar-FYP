"""Safety guard: authorization gate, allowlist, dashboard scope rules."""
import ipaddress

import pytest

from common import allowlist, config, scope_store
from common.allowlist import ScopeError
from common.config import AuthorizationError


# ---- settings ----------------------------------------------------------------
def test_settings_are_read_from_env():
    s = config.get_settings()
    assert [str(n) for n in s.allowed_ranges] == ["192.168.56.0/24", "127.0.0.1/32"]
    assert s.deny_hosts == ["192.168.56.1"]
    assert s.authorized_lab_only is True
    assert len(s.aes_key) == 32
    assert s.ssh_username == "soar"


def test_bad_aes_key_becomes_empty(set_env):
    set_env(AES_KEY_B64="GENERATE-A-32-BYTE-BASE64-KEY")
    assert config.get_settings().aes_key == b""


# ---- authorization gate (fails closed) ---------------------------------------
def test_gate_passes_with_lab_switch_and_ranges():
    config.assert_authorized_to_run()


def test_gate_refuses_without_master_switch(set_env):
    set_env(AUTHORIZED_LAB_ONLY="false")
    with pytest.raises(AuthorizationError, match="AUTHORIZED_LAB_ONLY"):
        config.assert_authorized_to_run()


def test_gate_refuses_without_ranges(set_env):
    set_env(ALLOWED_RANGES="")
    with pytest.raises(AuthorizationError, match="no allowed range"):
        config.assert_authorized_to_run()


# ---- allowlist ---------------------------------------------------------------
@pytest.mark.parametrize("ip,expected", [
    ("192.168.56.101", True),      # inside the lab range
    ("192.168.56.1", False),       # deny list wins (the engine PC)
    ("192.168.57.5", False),       # next network
    ("8.8.8.8", False),            # internet
    ("not-an-ip", False),          # garbage never passes
    ("", False),
])
def test_is_in_scope(ip, expected):
    assert allowlist.is_in_scope(ip) is expected


def test_assert_in_scope_raises_outside():
    with pytest.raises(ScopeError):
        allowlist.assert_in_scope("10.0.0.5")
    allowlist.assert_in_scope("192.168.56.101")


def test_filter_targets_drops_and_audits(audit_actions):
    kept = allowlist.filter_targets(["192.168.56.101", "8.8.8.8", "192.168.56.1"])
    assert kept == ["192.168.56.101"]
    assert "scope.reject" in audit_actions()


def test_filter_targets_needs_authorization(set_env):
    set_env(AUTHORIZED_LAB_ONLY="false")
    with pytest.raises(AuthorizationError):
        allowlist.filter_targets(["192.168.56.101"])


def test_expand_scope_lists_hosts_without_denied():
    hosts = allowlist.expand_scope()
    assert "192.168.56.101" in hosts
    assert "192.168.56.1" not in hosts          # denied
    assert "192.168.56.0" not in hosts          # network address
    assert "192.168.56.255" not in hosts        # broadcast
    assert len(hosts) == 253 + 1                # 254 usable - 1 denied + 127.0.0.1


def test_engine_own_ip_is_always_denied(monkeypatch):
    monkeypatch.setattr(scope_store, "engine_interfaces",
                        lambda: [{"iface": "eth1", "ip": "192.168.56.50",
                                  "network": "192.168.56.0/24", "private": True}])
    scope_store._cache.update(t=0.0, v=None)
    assert allowlist.is_in_scope("192.168.56.50") is False


def test_engine_host_ips_setting_is_denied(set_env):
    set_env(ENGINE_HOST_IPS="192.168.56.77/24")
    assert allowlist.is_in_scope("192.168.56.77") is False


# ---- dashboard scope rules ---------------------------------------------------
def test_validate_accepts_private_24():
    nets, deny = scope_store.validate(["192.168.110.0/24"], ["192.168.110.1", " "])
    assert nets == [ipaddress.ip_network("192.168.110.0/24")]
    assert deny == ["192.168.110.1"]


@pytest.mark.parametrize("ranges,deny,msg", [
    (["8.8.8.0/24"], [], "private"),            # public range
    (["10.0.0.0/8"], [], "too big"),            # bigger than /22
    (["banana"], [], "not a valid network"),
    ([], [], "at least one"),
    (["192.168.1.0/24"], ["x.y"], "deny list"),
    (["fd00::/64"], [], "IPv4"),
])
def test_validate_rejects(ranges, deny, msg):
    with pytest.raises(ValueError, match=msg):
        scope_store.validate(ranges, deny)


def test_validate_respects_ceiling(set_env):
    set_env(SCOPE_CEILING="192.168.56.0/24")
    with pytest.raises(ValueError, match="SCOPE_CEILING"):
        scope_store.validate(["10.1.1.0/24"], [])


def test_dashboard_scope_overrides_env(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard")
    supa.add("scope_config", id=1, allowed_ranges=["192.168.110.0/24"],
             deny_hosts=["192.168.110.9"], authorized=True, authorization_note="own lab")
    sc = scope_store.effective_scope(force=True)
    assert sc["source"] == "dashboard"
    assert [str(n) for n in sc["allowed_ranges"]] == ["192.168.110.0/24"]
    assert allowlist.is_in_scope("192.168.110.20")
    assert not allowlist.is_in_scope("192.168.56.101")     # the .env range no longer counts


def test_dashboard_scope_needs_authorized_flag(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard")
    supa.add("scope_config", id=1, allowed_ranges=["192.168.110.0/24"],
             deny_hosts=[], authorized=False, authorization_note="")
    with pytest.raises(AuthorizationError, match="not marked as authorized"):
        config.assert_authorized_to_run()


def test_dashboard_cannot_beat_env_master_switch(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard", AUTHORIZED_LAB_ONLY="false")
    supa.add("scope_config", id=1, allowed_ranges=["192.168.110.0/24"],
             deny_hosts=[], authorized=True, authorization_note="own lab")
    assert scope_store.effective_scope(force=True)["authorized"] is False


def test_dashboard_row_with_oversized_range_is_ignored(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard")
    supa.add("scope_config", id=1, allowed_ranges=["10.0.0.0/8", "192.168.110.0/24"],
             deny_hosts=[], authorized=True, authorization_note="own lab")
    sc = scope_store.effective_scope(force=True)
    assert [str(n) for n in sc["allowed_ranges"]] == ["192.168.110.0/24"]


def test_falls_back_to_env_when_cloud_is_down(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard")
    supa.fail_tables.add("scope_config")
    sc = scope_store.effective_scope(force=True)
    assert sc["source"] == "env"
    assert allowlist.is_in_scope("192.168.56.101")


def test_save_scope_needs_a_note_when_authorizing(supa, set_env):
    set_env(SCOPE_SOURCE="dashboard")
    with pytest.raises(ValueError, match="who authorized"):
        scope_store.save_scope(["192.168.110.0/24"], [], True, "x", "user-1")
    sc = scope_store.save_scope(["192.168.110.0/24"], ["192.168.110.1"], True,
                                "Own VirtualBox lab", "user-1")
    assert sc["authorized"] is True
    assert supa.rows("scope_config")[0]["updated_by"] == "user-1"


def test_windows_adapter_parsing_skips_virtual_and_loopback():
    text = ("VirtualBox Host-Only Network|192.168.56.1|24\n"
            "Wi-Fi|192.168.1.23|24\n"
            "Loopback Pseudo-Interface 1|127.0.0.1|8\n"
            "vEthernet (WSL)|172.20.0.1|20\n"
            "Ethernet 2|169.254.10.10|16\n"
            "garbage line\n")
    got = scope_store._parse_windows_ip_lines(text)
    assert [(i["iface"], i["ip"]) for i in got] == [
        ("VirtualBox Host-Only Network", "192.168.56.1"), ("Wi-Fi", "192.168.1.23")]
    assert got[0]["network"] == "192.168.56.0/24"
