"""Train the baselines + IsolationForest from benign-only data, calibrate thresholds on a benign validation week.

  python scripts/train.py --train data/train.duckdb --val data/val.duckdb
Reads no labels. Writes models/baseline.joblib and models/anomaly_{global,per_group}.joblib.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import joblib
import pandas as pd
import yaml

from src.detection.features import compute_windows, fit_baseline, load_events
from src.detection.iforest import AnomalyModel


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/train.duckdb")
    ap.add_argument("--val", default="data/val.duckdb")
    ap.add_argument("--out", default="models")
    a = ap.parse_args()
    cfg = yaml.safe_load(open("config/detector.yaml"))["anomaly"]
    out = Path(a.out)
    out.mkdir(exist_ok=True)

    t0 = time.time()
    tr = load_events(duckdb.connect(a.train, read_only=True))
    start = tr["event_time"].min().normalize()
    cutoff = start + pd.Timedelta(days=cfg["baseline_days"])
    print(f"train events {len(tr):,}  {tr['event_time'].min()} -> {tr['event_time'].max()}  baseline until {cutoff}")

    early = fit_baseline(tr[tr["event_time"] < cutoff])
    train_feats = compute_windows(tr, early, min_start=cutoff)
    print(f"training windows: {len(train_feats):,} ({time.time()-t0:.0f}s)")

    full = fit_baseline(tr)
    joblib.dump(full, out / "baseline.joblib")

    va = load_events(duckdb.connect(a.val, read_only=True))
    val_days = (va["event_time"].max() - va["event_time"].min()).total_seconds() / 86400
    val_feats = compute_windows(va, full)
    print(f"validation windows: {len(val_feats):,} over {val_days:.1f} days")

    for mode in ("global", "per_group"):
        m = AnomalyModel(mode=mode, n_estimators=cfg["n_estimators"], max_samples=cfg["max_samples"], random_state=cfg["random_state"]).fit(train_feats)
        info = m.calibrate(val_feats, cfg["target_fp_windows_per_day"], val_days)
        flagged = int(m.flag(val_feats).sum())
        m.save(out / f"anomaly_{mode}.joblib")
        print(f"[{mode}] thresholds {info}; benign validation flagged windows: {flagged} ({flagged/val_days:.1f}/day)")
    print(f"done in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
