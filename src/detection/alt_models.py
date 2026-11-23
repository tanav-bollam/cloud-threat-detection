"""Alternative behavioural-anomaly models with the same interface as AnomalyModel (fit / score / calibrate / flag / threshold_for), so the
evaluation pipeline can compare them with the IsolationForest unchanged. scikit-learn only (no deep-learning dependency).

  kind="lof":         LocalOutlierFactor(novelty=True): how much less dense a window's neighbourhood is than its neighbours' neighbourhoods.
  kind="autoencoder": a small MLP trained to reproduce its input through a narrow bottleneck; the anomaly score is the reconstruction error.

Neither provides SHAP reasons (the dashboard's 'why was this flagged' needs the tree model), which is part of the comparison.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from .features import FEATURES
from .iforest import AnomalyModel, _Unit


@dataclass
class AltAnomalyModel(AnomalyModel):
    kind: str = "lof"                  # lof | autoencoder
    n_neighbors: int = 35
    bottleneck: int = 8
    max_iter: int = 300

    def fit(self, feats: pd.DataFrame) -> "AltAnomalyModel":
        if self.mode != "global":
            raise ValueError("alternative models are trained globally (per-group did not help the IsolationForest)")
        X = feats[FEATURES].to_numpy(float)
        sc = StandardScaler().fit(X)
        Xs = np.clip(sc.transform(X), -10, 10)                     # tame the heavy tails so one extreme window does not dominate training
        if self.kind == "lof":
            Xs = np.unique(Xs.round(6), axis=0)                    # LOF is degenerate on exact duplicates (reachability distance 0 -> scores of 1e8-1e9 that tie), so fit on distinct windows
            est = LocalOutlierFactor(n_neighbors=min(self.n_neighbors, len(Xs) - 1), novelty=True, n_jobs=-1).fit(Xs)
        elif self.kind == "autoencoder":
            h = len(FEATURES)
            est = MLPRegressor(hidden_layer_sizes=(h, self.bottleneck, h), activation="relu", max_iter=self.max_iter, early_stopping=True,
                               validation_fraction=0.1, n_iter_no_change=15, random_state=self.random_state).fit(Xs, Xs)
        else:
            raise ValueError(f"unknown kind {self.kind}")
        self.units = {"all": _Unit(sc, est)}
        self.train_medians = feats[FEATURES].median()
        return self

    def score(self, feats: pd.DataFrame) -> np.ndarray:
        u = self.units["all"]
        Xs = np.clip(u.scaler.transform(feats[FEATURES].to_numpy(float)), -10, 10)
        if self.kind == "lof":
            return -u.forest.score_samples(Xs)                     # higher = more anomalous
        return np.mean((u.forest.predict(Xs) - Xs) ** 2, axis=1)   # reconstruction error
