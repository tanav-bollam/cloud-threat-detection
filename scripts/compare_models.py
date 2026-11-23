"""IsolationForest vs LOF vs a small autoencoder on the same data, windows and alert budget.

  python scripts/evaluate.py --cache      # first (provides the rules/IP layer alerts and the trained IsolationForest)
  python scripts/compare_models.py        # -> reports/model_comparison.json

All models are trained on the same benign training windows, calibrated on the same benign validation week to the same number of flagged windows
per day, and scored on the same held-out test week. Threshold-free ranking quality (AUROC / average precision over windows that overlap an
injected attack) is reported next to the thresholded results, so the comparison does not just reflect where each threshold landed.
This script reads the ground-truth labels: it is evaluation code.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import joblib
import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import average_precision_score, roc_auc_score

from scripts.evaluate import summarize_combo
from src.detection.alt_models import AltAnomalyModel
from src.detection.features import FEATURES, compute_windows, fit_baseline, load_events
from src.detection.iforest import AnomalyModel, windows_to_alerts
from src.detection.scoring import load_config


def malicious_window_keys(con) -> set:
    """(identity, wstart) of every 15-minute sliding window (5-minute step) that contains at least one injected malicious event."""
    rows = con.execute("SELECT e.identity, e.event_time FROM events e JOIN labels l USING (event_id) WHERE l.is_malicious").fetchall()
    keys = set()
    for ident, t in rows:
        b = pd.Timestamp(t).floor("5min")
        for g in range(3):
            keys.add((ident, b - pd.Timedelta(minutes=5 * g)))
    return keys


def alerts_for(model, feats, events):
    sc = model.score(feats)
    fl = model.flag(feats, sc)
    return windows_to_alerts(feats, sc, fl, events, None, model.threshold_for(feats)), sc, fl


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    t_start = time.time()
    cfg = load_config()
    acfg = yaml.safe_load(open("config/detector.yaml", encoding="utf-8"))["anomaly"]
    target = acfg["target_fp_windows_per_day"]
    base = joblib.load("models/baseline.joblib")
    tl_all, vl_all = joblib.load("reports/layers_cache.joblib")
    tcon, vcon = duckdb.connect("data/test.duckdb", read_only=True), duckdb.connect("data/val.duckdb", read_only=True)
    tev, vev = load_events(tcon), load_events(vcon)
    days = (tev["event_time"].max() - tev["event_time"].min()).total_seconds() / 86400
    vdays = (vev["event_time"].max() - vev["event_time"].min()).total_seconds() / 86400

    print("building training windows (same recipe as scripts/train.py) ...", flush=True)
    tr = load_events(duckdb.connect("data/train.duckdb", read_only=True))
    cutoff = tr["event_time"].min().normalize() + pd.Timedelta(days=acfg["baseline_days"])
    train_feats = compute_windows(tr, fit_baseline(tr[tr["event_time"] < cutoff]), min_start=cutoff)
    test_feats, val_feats = compute_windows(tev, base), compute_windows(vev, base)
    del tr

    models: dict[str, object] = {"IsolationForest": AnomalyModel.load("models/anomaly_global.joblib")}
    train_s = {"IsolationForest": None}
    for name, kind in (("LOF", "lof"), ("Autoencoder", "autoencoder")):
        t0 = time.time()
        m = AltAnomalyModel(kind=kind, random_state=acfg["random_state"]).fit(train_feats)
        m.calibrate(val_feats, target, vdays)
        models[name] = m
        train_s[name] = round(time.time() - t0, 1)
        print(f"{name}: trained and calibrated in {train_s[name]}s", flush=True)

    mal = malicious_window_keys(tcon)
    y = np.array([(i, w) in mal for i, w in zip(test_feats["identity"], test_feats["wstart"])])
    print(f"{int(y.sum())} of {len(y):,} test windows overlap an injected attack", flush=True)

    out = {"target_flagged_windows_per_day": target, "training_windows": len(train_feats), "test_windows": len(test_feats), "attack_windows": int(y.sum()),
           "features": len(FEATURES), "models": {}}
    for name, m in models.items():
        t0 = time.time()
        sc_t = m.score(test_feats)
        per10k = (time.time() - t0) / max(len(test_feats), 1) * 10_000
        a_t, _, fl_t = alerts_for(m, test_feats, tev)
        a_v, _, fl_v = alerts_for(m, val_feats, vev)
        tl = {"rules": tl_all["rules"], "ip": tl_all["ip"], "anomaly": a_t}
        vl = {"rules": vl_all["rules"], "ip": vl_all["ip"], "anomaly": a_v}
        only = summarize_combo(("anomaly",), tl, vl, base, tcon, vcon, days, vdays, cfg)
        comb = summarize_combo(("rules", "anomaly", "ip"), tl, vl, base, tcon, vcon, days, vdays, cfg)
        out["models"][name] = {
            "auroc": round(float(roc_auc_score(y, sc_t)), 4), "average_precision": round(float(average_precision_score(y, sc_t)), 4),
            "val_flagged_windows_per_day": round(float(fl_v.sum()) / vdays, 2), "test_flagged_windows": int(fl_t.sum()),
            "anomaly_only": {"incident_recall": only["test_week"]["injection_recall"], "recall_by_scenario": only["test_week"]["recall_by_scenario"],
                             "incident_precision": only["test_week"]["incident_precision"], "event_precision": only["event_level"]["precision"], "event_recall": only["event_level"]["recall"],
                             "fp_incidents_per_day": only["benign_week"]["fp_incidents_per_day"], "ttd_p50_s": only["ttd_p50_s"], "ttd_p95_s": only["ttd_p95_s"]},
            "combined": {"incident_recall": comb["test_week"]["injection_recall"], "fp_incidents_per_day": comb["benign_week"]["fp_incidents_per_day"],
                         "fp_high_or_critical_per_day": comb["benign_week"]["fp_high_or_critical_per_day"], "incident_precision": comb["test_week"]["incident_precision"]},
            "train_seconds": train_s[name], "score_seconds_per_10k_windows": round(per10k, 3), "explanations": "SHAP top reasons" if name == "IsolationForest" else "none (no tree structure)"}
        print(f"{name:16} AUROC {out['models'][name]['auroc']} AP {out['models'][name]['average_precision']} | anomaly-only recall {only['test_week']['injection_recall']} "
              f"| combined recall {comb['test_week']['injection_recall']} FP/day {comb['benign_week']['fp_incidents_per_day']}", flush=True)
    out["seconds"] = round(time.time() - t_start)
    Path("reports").mkdir(exist_ok=True)
    json.dump(out, open("reports/model_comparison.json", "w"), indent=1)
    print(f"done in {out['seconds']}s -> reports/model_comparison.json")


if __name__ == "__main__":
    main()
