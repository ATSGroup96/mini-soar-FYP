"""
Explainable risk scoring.

Loads the trained MLP and scores each vulnerability 0..100. Explanations are
produced by ABLATION: for each feature we recompute the score with that feature
reset to its dataset mean; the drop (or rise) is that feature's contribution.
This is model-agnostic, deterministic, and easy to defend in a viva.

If PyTorch or a trained model is unavailable, it falls back to the transparent
oracle risk function so the platform still produces sensible scores.

Public API:
  score_vector(vec)          -> (score, [ {feature, contribution, why}, ... ])
  score_host(host_result)    -> mutates host_result vulns + sets risk grade
  grade_from_score(score)    -> 'A'..'F'
"""
from __future__ import annotations

import json
from functools import lru_cache

import numpy as np

from .features import FEATURE_NAMES, FEATURE_EXPLANATION, vuln_to_features
from .model import MODEL_PATH, META_PATH, _HAVE_TORCH


@lru_cache(maxsize=1)
def _load():
    """Return (predict_fn, mean, std) or (None, mean, std) for oracle fallback."""
    mean = np.zeros(len(FEATURE_NAMES), dtype=np.float32)
    std = np.ones(len(FEATURE_NAMES), dtype=np.float32)
    if META_PATH.exists():
        meta = json.loads(META_PATH.read_text())
        mean = np.array(meta["mean"], dtype=np.float32)
        std = np.array(meta["std"], dtype=np.float32)

    if _HAVE_TORCH and MODEL_PATH.exists():
        import torch
        from .model import RiskMLP
        model = RiskMLP(len(FEATURE_NAMES))
        model.load_state_dict(torch.load(MODEL_PATH, map_location="cpu"))
        model.eval()

        def predict(batch: np.ndarray) -> np.ndarray:
            xs = (batch - mean) / std
            with torch.no_grad():
                return model(torch.tensor(xs.astype(np.float32))).numpy()
        return predict, mean, std

    # fallback: oracle
    from .bootstrap_data import oracle_risk

    def predict(batch: np.ndarray) -> np.ndarray:
        return oracle_risk(batch)
    return predict, mean, std


def grade_from_score(score: float) -> str:
    if score >= 80:
        return "F"
    if score >= 60:
        return "D"
    if score >= 40:
        return "C"
    if score >= 20:
        return "B"
    return "A"


def score_vector(vec: list[float]) -> tuple[float, list[dict]]:
    predict, mean, std = _load()
    v = np.array(vec, dtype=np.float32).reshape(1, -1)
    full = float(predict(v)[0])

    # ablation explanations
    contribs: list[dict] = []
    for i, name in enumerate(FEATURE_NAMES):
        ablated = v.copy()
        ablated[0, i] = mean[i]
        delta = full - float(predict(ablated)[0])
        if abs(delta) >= 0.5:
            contribs.append({
                "feature": name,
                "contribution": round(delta, 1),
                "why": FEATURE_EXPLANATION.get(name, name),
            })
    contribs.sort(key=lambda c: abs(c["contribution"]), reverse=True)
    return round(max(0.0, min(100.0, full)), 1), contribs[:5]


def score_host(host_result: dict) -> dict:
    """
    Score every vuln on a host, attach ml_risk_score + ml_reasons, and set the
    host's overall risk_score (max of its vulns) and risk_grade.
    """
    vulns = host_result.get("vulnerabilities", [])
    host_max = 0.0
    for v in vulns:
        score, reasons = score_vector(vuln_to_features(v, host_result))
        v["ml_risk_score"] = score
        existing = v.get("ml_reasons") or []
        v["ml_reasons"] = existing + [
            f"{r['why']} ({'+' if r['contribution'] >= 0 else ''}{r['contribution']})"
            for r in reasons
        ]
        host_max = max(host_max, score)

    # a host with default creds but no matched CVE still carries real risk
    if not vulns and any(s.get("has_default_cred") for s in host_result.get("services", [])):
        host_max = max(host_max, 65.0)

    host_result["risk_score"] = round(host_max, 1)
    host_result["risk_grade"] = grade_from_score(host_max)
    return host_result
