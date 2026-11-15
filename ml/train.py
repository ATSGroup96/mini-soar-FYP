"""
Train the risk-scoring MLP on the synthetic bootstrap dataset.

  python -m ml.train               # train + save to ./data/model/
  python -m ml.train --n 40000 --epochs 60

Saves:
  data/model/risk_mlp.pt    — weights
  data/model/risk_meta.json — feature mean/std (standardization) + metrics
"""
from __future__ import annotations

import json
import argparse

import numpy as np

from .features import FEATURE_NAMES
from .bootstrap_data import make_dataset
from .model import MODEL_DIR, MODEL_PATH, META_PATH, _HAVE_TORCH


def train(n: int = 20000, epochs: int = 40, seed: int = 42) -> dict:
    if not _HAVE_TORCH:
        raise RuntimeError("PyTorch not installed. `pip install torch`.")
    import torch
    from torch.utils.data import TensorDataset, DataLoader
    from .model import RiskMLP

    torch.manual_seed(seed)
    X, y = make_dataset(n, seed)

    # standardize features
    mean = X.mean(axis=0)
    std = X.std(axis=0) + 1e-6
    Xs = (X - mean) / std

    # train/val split
    from sklearn.model_selection import train_test_split
    Xtr, Xva, ytr, yva = train_test_split(Xs, y, test_size=0.2, random_state=seed)

    tr = DataLoader(TensorDataset(torch.tensor(Xtr), torch.tensor(ytr)),
                    batch_size=256, shuffle=True)

    model = RiskMLP(len(FEATURE_NAMES))
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = torch.nn.SmoothL1Loss()

    for ep in range(1, epochs + 1):
        model.train()
        tot = 0.0
        for xb, yb in tr:
            opt.zero_grad()
            loss = loss_fn(model(xb), yb)
            loss.backward()
            opt.step()
            tot += loss.item() * len(xb)
        if ep % 10 == 0 or ep == 1:
            model.eval()
            with torch.no_grad():
                pv = model(torch.tensor(Xva))
                mae = torch.mean(torch.abs(pv - torch.tensor(yva))).item()
            print(f"  epoch {ep:3d}  train_loss={tot/len(Xtr):.3f}  val_MAE={mae:.2f}")

    # final metrics
    model.eval()
    with torch.no_grad():
        pv = model(torch.tensor(Xva)).numpy()
    mae = float(np.mean(np.abs(pv - yva)))
    rmse = float(np.sqrt(np.mean((pv - yva) ** 2)))

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), MODEL_PATH)
    meta = {
        "feature_names": FEATURE_NAMES,
        "mean": mean.tolist(), "std": std.tolist(),
        "metrics": {"val_mae": round(mae, 3), "val_rmse": round(rmse, 3),
                    "n_train": len(Xtr), "n_val": len(Xva)},
    }
    META_PATH.write_text(json.dumps(meta, indent=2))
    print(f"Saved model -> {MODEL_PATH}")
    print(f"Validation: MAE={mae:.2f}  RMSE={rmse:.2f} (risk scale 0..100)")
    return meta


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--epochs", type=int, default=40)
    train(ap.parse_args().n, ap.parse_args().epochs)
