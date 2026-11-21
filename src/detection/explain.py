"""Per-window explanations: SHAP TreeExplainer on the IsolationForest, with a permutation fallback."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .features import FEATURES
from .iforest import AnomalyModel


def _shap_values(unit, X_scaled: np.ndarray) -> np.ndarray:
    import shap
    return shap.TreeExplainer(unit.forest).shap_values(X_scaled)


def _fallback_values(unit, X_scaled: np.ndarray) -> np.ndarray:
    """Occlusion: how much the anomaly score drops when one feature is replaced by the training median (0 after scaling)."""
    base = -unit.forest.score_samples(X_scaled)
    out = np.zeros_like(X_scaled)
    for j in range(X_scaled.shape[1]):
        Xp = X_scaled.copy()
        Xp[:, j] = 0.0
        out[:, j] = -(-unit.forest.score_samples(Xp) - base)       # positive => feature pushes toward anomaly
    return out


def explain(model: AnomalyModel, feats: pd.DataFrame, top_k: int = 5) -> list[list[dict]]:
    """Returns, per row, up to top_k reasons: {feature, value, contribution}. Positive contribution = pushes toward anomalous."""
    results: list[list[dict]] = [[] for _ in range(len(feats))]
    keys = model._key(feats).to_numpy()
    for k, unit in model.units.items():
        idx = np.where(keys == k)[0]
        if len(idx) == 0:
            continue
        X = unit.scaler.transform(feats.iloc[idx][FEATURES].to_numpy(float))
        try:
            vals = -_shap_values(unit, X)          # SHAP on the sklearn score: negative = more anomalous, so flip the sign
        except Exception:                          # noqa: BLE001 - shap/sklearn version quirks
            vals = _fallback_values(unit, X)
        raw = feats.iloc[idx][FEATURES].to_numpy(float)
        for r, i in enumerate(idx):
            order = np.argsort(-vals[r])[:top_k]
            results[i] = [{"feature": FEATURES[j], "value": round(float(raw[r, j]), 3), "contribution": round(float(vals[r, j]), 4)}
                          for j in order if vals[r, j] > 0]
    return results


def format_reasons(reasons: list[dict]) -> str:
    return ", ".join(f"{r['feature']}={r['value']} ({r['contribution']:+.2f})" for r in reasons)
