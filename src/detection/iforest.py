"""IsolationForest behavioural anomaly layer (+ calibration and window->alert conversion)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .features import FEATURES, WINDOW_MIN
from .rules_engine import Alert


def group_of(identity_type: str) -> str:
    return "AssumedRole" if identity_type == "AssumedRole" else "IAMUser"      # Root falls back to the human model


@dataclass
class _Unit:
    scaler: StandardScaler
    forest: IsolationForest
    threshold: float = 0.0


@dataclass
class AnomalyModel:
    mode: str = "global"
    n_estimators: int = 300
    max_samples: int | str = 512
    random_state: int = 7
    units: dict = field(default_factory=dict)
    train_medians: Optional[pd.Series] = None

    def _key(self, feats: pd.DataFrame) -> pd.Series:
        if self.mode == "global":
            return pd.Series("all", index=feats.index)
        return feats["identity_type"].map(group_of)

    def fit(self, feats: pd.DataFrame) -> "AnomalyModel":
        self.units = {}
        keys = self._key(feats)
        for k in keys.unique():
            X = feats.loc[keys == k, FEATURES].to_numpy(float)
            sc = StandardScaler().fit(X)
            fo = IsolationForest(n_estimators=self.n_estimators, max_samples=min(self.max_samples, len(X)) if isinstance(self.max_samples, int) else self.max_samples,
                                 random_state=self.random_state, n_jobs=-1).fit(sc.transform(X))
            self.units[k] = _Unit(sc, fo)
        self.train_medians = feats[FEATURES].median()
        return self

    def score(self, feats: pd.DataFrame) -> np.ndarray:
        """Anomaly score; higher = more anomalous (negated sklearn score_samples)."""
        out = np.zeros(len(feats))
        keys = self._key(feats).to_numpy()
        for k, u in self.units.items():
            m = keys == k
            if m.any():
                out[m] = -u.forest.score_samples(u.scaler.transform(feats.loc[m, FEATURES].to_numpy(float)))
        return out

    def calibrate(self, val_feats: pd.DataFrame, target_windows_per_day: float, days: float) -> dict:
        """Set each unit's threshold so a benign validation period flags ~target windows/day (shared across units by volume)."""
        scores = self.score(val_feats)
        keys = self._key(val_feats).to_numpy()
        total_budget = target_windows_per_day * days
        info = {}
        for k, u in self.units.items():
            m = keys == k
            share = m.sum() / max(len(val_feats), 1)
            budget = max(1, int(round(total_budget * share)))
            s = np.sort(scores[m])
            u.threshold = float(s[-budget]) if len(s) >= budget else float(s[0]) if len(s) else 0.0
            u.threshold = np.nextafter(u.threshold, np.inf) if budget < len(s) else u.threshold
            info[k] = {"threshold": round(u.threshold, 4), "val_windows": int(m.sum()), "budget": budget}
        return info

    def flag(self, feats: pd.DataFrame, scores: Optional[np.ndarray] = None) -> np.ndarray:
        scores = self.score(feats) if scores is None else scores
        keys = self._key(feats).to_numpy()
        thr = np.array([self.units[k].threshold if k in self.units else np.inf for k in keys])
        return scores >= thr

    def threshold_for(self, feats: pd.DataFrame) -> np.ndarray:
        keys = self._key(feats).to_numpy()
        return np.array([self.units[k].threshold if k in self.units else np.inf for k in keys])

    def save(self, path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path) -> "AnomalyModel":
        return joblib.load(path)


def windows_to_alerts(feats: pd.DataFrame, scores: np.ndarray, flagged: np.ndarray, events: pd.DataFrame,
                      reasons: Optional[dict] = None, thresholds: Optional[np.ndarray] = None) -> list[Alert]:
    """Merge consecutive/overlapping flagged windows per identity into one alert. `events` provides the matched event ids."""
    f = feats.assign(score=scores, flagged=flagged)
    thr_s = pd.Series(thresholds, index=feats.index) if thresholds is not None else None
    f = f[f["flagged"]].sort_values(["identity", "wstart"])
    if f.empty:
        return []
    ev_by_id = {i: (g["event_time"].to_numpy(), g["event_id"].to_numpy(), g["source_ip"].to_numpy()) for i, g in events.groupby("identity")}
    alerts: list[Alert] = []
    win = pd.Timedelta(minutes=WINDOW_MIN)
    for ident, g in f.groupby("identity"):
        prev = None
        rows: list = []
        runs = []
        for r in g.itertuples():
            if prev is not None and r.wstart > prev + win:
                runs.append(rows); rows = []
            rows.append(r); prev = r.wstart
        runs.append(rows)
        times, ids, ips = ev_by_id[ident]
        for rows in runs:
            start, end = rows[0].wstart, rows[-1].wstart + win
            lo, hi = np.searchsorted(times, np.datetime64(start)), np.searchsorted(times, np.datetime64(end))
            mids = list(ids[lo:hi])
            if not mids:
                continue
            best = max(rows, key=lambda r: r.score)
            margin = float(best.score - thr_s[best.Index]) if thr_s is not None else 0.0
            reason = (reasons or {}).get((ident, best.wstart), [])
            a = Alert(rule_id="ML001", title="Anomalous behaviour for identity", severity="MEDIUM", mitre_tactic="", mitre_technique="",
                      event_id=mids[0], event_time=pd.Timestamp(times[lo]).strftime("%Y-%m-%dT%H:%M:%SZ"), identity=ident,
                      source_ip=str(ips[lo]), description="IsolationForest flagged an unusual 15-minute behaviour window relative to this identity's baseline.",
                      event_name="", matched_event_ids=mids, detail=f"{len(rows)} flagged window(s), max score {best.score:.3f}",
                      detected_at=(start + win).strftime("%Y-%m-%dT%H:%M:%SZ"), source="anomaly", score=float(best.score), reasons=reason, margin=margin)
            alerts.append(a)
    return alerts
