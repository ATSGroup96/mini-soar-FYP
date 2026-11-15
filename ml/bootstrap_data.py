"""
Synthetic bootstrap dataset for the risk-scoring model.

Real labelled "how bad was this in practice" data does not exist for a student
lab, so we bootstrap: sample realistic feature vectors and label them with a
transparent domain risk function (the "oracle"). The neural net then learns to
approximate that function, and the ablation-based explainer at score time
recovers per-feature contributions. This is a defensible approach for an FYP —
the oracle encodes expert priors (KEV and default creds dominate), and the NN
generalizes smoothly between them.
"""
from __future__ import annotations

import numpy as np

from .features import FEATURE_NAMES

N_FEATURES = len(FEATURE_NAMES)


def oracle_risk(f: np.ndarray, noise: float = 0.0,
                rng: np.random.Generator | None = None) -> np.ndarray:
    """
    Transparent ground-truth risk in 0..100. DETERMINISTIC by default so it can
    be used directly as a score-time fallback and for what-if comparisons.
    Noise is added only when generating the training set (noise>0).
    f columns follow FEATURE_NAMES.
    """
    cvss, epss, epssp, kev, dcred, inet, crit, vconf, expo, rogue = [
        f[:, i] for i in range(N_FEATURES)
    ]
    # base: severity scaled, strongly amplified by real-world exploit signals
    base = (cvss / 10.0) * 40.0
    exploit = epss * 25.0 + kev * 20.0          # KEV + EPSS = "actually exploited"
    access = dcred * 18.0 + crit * 8.0 + inet * 6.0
    context = expo * 4.0 + rogue * 6.0
    confidence = np.where(vconf > 0.5, 1.0, 0.75)  # unconfirmed version -> discount
    score = (base + exploit + access + context) * confidence
    if noise:
        rng = rng or np.random.default_rng()
        score = score + rng.normal(0, noise, size=score.shape)
    return np.clip(score, 0, 100)


def sample_features(n: int, rng: np.random.Generator) -> np.ndarray:
    cvss = rng.beta(2, 2, n) * 10
    # epss is heavily skewed toward 0 in reality
    epss = rng.beta(0.6, 8, n)
    epssp = rng.beta(2, 2, n)
    kev = (rng.random(n) < 0.08).astype(float)          # ~8% on KEV
    dcred = (rng.random(n) < 0.12).astype(float)
    inet = (rng.random(n) < 0.25).astype(float)
    crit = rng.random(n)
    vconf = (rng.random(n) < 0.7).astype(float)
    expo = rng.random(n)
    rogue = (rng.random(n) < 0.15).astype(float)
    # correlate: KEV CVEs tend to have higher EPSS
    epss = np.clip(epss + kev * rng.beta(4, 2, n) * 0.5, 0, 1)
    return np.stack([cvss, epss, epssp, kev, dcred, inet, crit,
                     vconf, expo, rogue], axis=1).astype(np.float32)


def make_dataset(n: int = 20000, seed: int = 42):
    rng = np.random.default_rng(seed)
    X = sample_features(n, rng)
    # training labels carry small noise so the net learns a smooth surface
    y = oracle_risk(X, noise=2.5, rng=rng).astype(np.float32)
    return X, y


if __name__ == "__main__":
    X, y = make_dataset(5)
    for i in range(5):
        print(dict(zip(FEATURE_NAMES, X[i].round(3))), "=> risk", round(float(y[i]), 1))
