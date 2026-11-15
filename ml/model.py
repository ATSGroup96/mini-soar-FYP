"""
PyTorch risk-scoring model — a small MLP regressor (features -> risk 0..100).

Kept intentionally small: it trains in seconds on CPU (no GPU needed for the
lab) and is easy to explain via feature ablation at score time.
"""
from __future__ import annotations

from pathlib import Path

try:
    import torch
    import torch.nn as nn
    _HAVE_TORCH = True
except Exception:
    _HAVE_TORCH = False
    nn = object  # type: ignore

MODEL_DIR = Path("./data/model")
MODEL_PATH = MODEL_DIR / "risk_mlp.pt"
META_PATH = MODEL_DIR / "risk_meta.json"


if _HAVE_TORCH:
    class RiskMLP(nn.Module):
        def __init__(self, n_features: int):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(n_features, 32), nn.ReLU(),
                nn.Linear(32, 16), nn.ReLU(),
                nn.Linear(16, 1),
            )

        def forward(self, x):
            return self.net(x).squeeze(-1)
