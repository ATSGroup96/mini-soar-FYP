"""ML risk scoring: features, expert formula, explanations, grades, training."""
import numpy as np
import pytest

from ml import bootstrap_data, features, risk_score
from ml.features import FEATURE_NAMES


def vec(**kw):
    base = dict(cvss=5.0, epss=0.01, epss_percentile=0.5, in_kev=0, has_default_cred=0,
                internet_facing=0, service_criticality=0.5, version_confirmed=1,
                asset_exposure=0.2, rogue_asset=0)
    base.update(kw)
    return [float(base[n]) for n in FEATURE_NAMES]


# ---- features ----------------------------------------------------------------
def test_feature_vector_layout(host):
    v = host["vulnerabilities"][1]                       # CVE on port 22 (default cred there)
    f = dict(zip(FEATURE_NAMES, features.vuln_to_features(v, host)))
    assert f["cvss"] == 7.5 and f["epss"] == 0.10 and f["in_kev"] == 0.0
    assert f["has_default_cred"] == 1.0
    assert f["service_criticality"] == 0.9               # ssh
    assert f["version_confirmed"] == 1.0
    assert f["asset_exposure"] == 4 / 20
    assert f["rogue_asset"] == 0.0


def test_features_handle_missing_values():
    f = features.vuln_to_features({"cve_id": "X"}, None)
    assert len(f) == len(FEATURE_NAMES) == 10
    assert f[0] == 0.0 and f[6] == 0.3                    # unknown service -> low criticality


def test_exposure_is_capped(host):
    host["services"] = [{"port": p} for p in range(50)]
    assert features.vuln_to_features({"port": 1}, host)[8] == 1.0


@pytest.mark.parametrize("name,crit", [("ssh", 0.9), ("RDP", 1.0), ("telnet", 0.95),
                                       ("http", 0.5), ("unknown-thing", 0.3), (None, 0.3)])
def test_service_criticality(name, crit):
    assert features.service_criticality(name) == crit


# ---- expert formula ----------------------------------------------------------
def oracle(**kw):
    return float(bootstrap_data.oracle_risk(np.array([vec(**kw)], dtype=np.float32))[0])


def test_oracle_known_value():
    # (5/10*40) + (0.01*25) + (0.5*8) + (0.2*4) = 25.05
    assert oracle() == pytest.approx(25.05, abs=0.01)


def test_oracle_is_deterministic_and_bounded():
    assert oracle() == oracle()
    assert oracle(cvss=10, epss=1, in_kev=1, has_default_cred=1, internet_facing=1,
                  service_criticality=1, asset_exposure=1, rogue_asset=1) == 100.0
    assert oracle(cvss=0, epss=0, service_criticality=0, asset_exposure=0) == 0.0


def test_exploit_signals_raise_the_score():
    base = oracle()
    assert oracle(in_kev=1) == pytest.approx(base + 20, abs=0.01)
    assert oracle(has_default_cred=1) == pytest.approx(base + 18, abs=0.01)
    assert oracle(epss=0.9) > base
    assert oracle(cvss=9.8) > base


def test_unconfirmed_version_is_discounted():
    assert oracle(version_confirmed=0) == pytest.approx(oracle() * 0.75, abs=0.01)


def test_kev_low_cvss_outranks_high_cvss_no_exploit():
    """The point of the project: real exploit data beats CVSS alone."""
    assert oracle(cvss=6.5, in_kev=1, epss=0.9) > oracle(cvss=9.0, in_kev=0, epss=0.001)


def test_training_data_is_reproducible():
    x1, y1 = bootstrap_data.make_dataset(500, seed=7)
    x2, y2 = bootstrap_data.make_dataset(500, seed=7)
    assert x1.shape == (500, 10) and y1.shape == (500,)
    assert np.array_equal(x1, x2) and np.array_equal(y1, y2)
    assert 0 <= y1.min() and y1.max() <= 100
    assert 0 <= x1[:, 0].min() and x1[:, 0].max() <= 10


# ---- scoring + explanations --------------------------------------------------
@pytest.mark.parametrize("score,grade", [(0, "A"), (19.9, "A"), (20, "B"), (39.9, "B"),
                                         (40, "C"), (59.9, "C"), (60, "D"), (79.9, "D"),
                                         (80, "F"), (100, "F")])
def test_grades(score, grade):
    assert risk_score.grade_from_score(score) == grade


def test_score_vector_falls_back_to_formula_without_model():
    score, reasons = risk_score.score_vector(vec(cvss=9.8, in_kev=1, epss=0.9))
    assert score == pytest.approx(oracle(cvss=9.8, in_kev=1, epss=0.9), abs=0.1)
    assert reasons and len(reasons) <= 5
    top = {r["feature"] for r in reasons}
    assert {"in_kev", "cvss", "epss"} <= top
    assert all(abs(r["contribution"]) >= 0.5 for r in reasons)
    assert reasons == sorted(reasons, key=lambda r: abs(r["contribution"]), reverse=True)


def test_score_host_sets_host_risk_to_worst_finding(host):
    risk_score.score_host(host)
    scores = [v["ml_risk_score"] for v in host["vulnerabilities"]]
    assert host["risk_score"] == max(scores)
    assert host["risk_grade"] == risk_score.grade_from_score(max(scores))
    assert scores[0] > scores[1]                          # KEV backdoor above the other CVE
    assert any("KEV" in r for r in host["vulnerabilities"][0]["ml_reasons"])


def test_score_host_keeps_watchlist_reason(host):
    host["vulnerabilities"][0]["ml_reasons"] = ["on CVE watchlist"]
    risk_score.score_host(host)
    assert host["vulnerabilities"][0]["ml_reasons"][0] == "on CVE watchlist"


def test_rescoring_does_not_pile_up_reasons(host):
    risk_score.score_host(host)
    first = list(host["vulnerabilities"][0]["ml_reasons"])
    risk_score.score_host(host)
    assert host["vulnerabilities"][0]["ml_reasons"] == first


def test_host_with_only_default_password_still_has_risk(host):
    host["vulnerabilities"] = []
    risk_score.score_host(host)
    assert host["risk_score"] == 65.0 and host["risk_grade"] == "D"


def test_clean_host_is_grade_a():
    h = {"ip": "192.168.56.9", "services": [{"port": 80, "service_name": "http"}],
         "vulnerabilities": []}
    risk_score.score_host(h)
    assert (h["risk_score"], h["risk_grade"]) == (0.0, "A")


# ---- training (needs PyTorch; runs on the project PC) ------------------------
def test_training_learns_the_formula():
    pytest.importorskip("torch")
    from ml import train
    meta = train.train(n=4000, epochs=25)
    assert meta["metrics"]["val_mae"] < 6.0
    from ml.model import MODEL_PATH, META_PATH
    assert MODEL_PATH.exists() and META_PATH.exists()
    risk_score._load.cache_clear()
    score, reasons = risk_score.score_vector(vec(cvss=9.8, in_kev=1, epss=0.9))
    assert abs(score - oracle(cvss=9.8, in_kev=1, epss=0.9)) < 12
    assert reasons


def test_model_status_reports_fallback():
    status = risk_score.model_status()
    assert status["engine"] == "formula" and status["trained"] is False
