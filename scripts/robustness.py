"""Stealth robustness study: how does recall fall as the attacker blends in?

  python scripts/robustness.py            -> reports/robustness.json

Stealth levels (graded, each adds to the previous; see src/generator/attacks.py:make_attacker):
  0.0  noisy attacker: foreign hosting IPs, offensive-tool user agents, normal pace
  0.3  + victim's own user agent
  0.6  + victim's usual region and a same-country residential IP
  0.9  + works during the victim's business hours
  all levels: attacker pace slowed by 1 + 20 * stealth
Benign traffic is identical at every level (same seeds); only the attacks change. The benign validation week's layer alerts are
reused from reports/layers_cache.joblib (run `scripts/evaluate.py --cache` first).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import joblib

from scripts.evaluate import COMBOS, compute_layers, summarize_combo
from src.detection.features import load_events
from src.detection.iforest import AnomalyModel
from src.detection.scoring import load_config
from src.generator.dataset import generate_dataset
from src.pipeline import storage

ATTACKS = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S1+S2+S3+S4+S5"]
LEVEL_NOTES = {0.0: "noisy attacker", 0.3: "+ victim's user agent", 0.6: "+ victim's region & same-country IP", 0.9: "+ business hours"}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", default="0.0,0.3,0.6,0.9")
    ap.add_argument("--models", default="models")
    ap.add_argument("--val", default="data/val.duckdb")
    ap.add_argument("--base-test", default="data/test.duckdb", help="reused as stealth 0.0")
    ap.add_argument("--count", type=int, default=6)
    ap.add_argument("--out", default="reports/robustness.json")
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    cfg = load_config()
    base = joblib.load(Path(a.models) / "baseline.joblib")
    model = AnomalyModel.load(Path(a.models) / "anomaly_global.joblib")
    _, vl_all = joblib.load("reports/layers_cache.joblib")
    vl = {"rules": vl_all["rules"], "ip": vl_all["ip"], "anomaly": vl_all["anomaly_global"]}
    vcon = duckdb.connect(a.val, read_only=True)
    vev = load_events(vcon)
    vdays = (vev["event_time"].max() - vev["event_time"].min()).total_seconds() / 86400
    levels = [float(x) for x in a.levels.split(",")]
    out = {"levels": levels, "notes": {str(k): v for k, v in LEVEL_NOTES.items()}, "attacks": ATTACKS, "count": a.count, "results": {}}
    for lv in levels:
        ts = time.time()
        if lv == 0.0 and Path(a.base_test).exists():
            path = Path(a.base_test)
        else:
            path = Path(f"data/robust_{lv}.duckdb")
            if path.exists():
                path.unlink()
            ds = generate_dataset(seed=303, world_seed=42, days=7, start="2025-01-06", attacks=ATTACKS, count=a.count, stealth=lv)
            con = storage.connect(path)
            storage.insert_events(con, ds.events)
            storage.insert_injections(con, ds.injections)
            con.close()
            del ds
        tcon = duckdb.connect(str(path), read_only=True)
        tev = load_events(tcon)
        days = (tev["event_time"].max() - tev["event_time"].min()).total_seconds() / 86400
        layers = compute_layers(tcon, tev, base, {"global": model}, True)
        tl = {"rules": layers["rules"], "ip": layers["ip"], "anomaly": layers["anomaly_global"]}
        res = {}
        for name, combo in COMBOS.items():
            s = summarize_combo(combo, tl, vl, base, tcon, vcon, days, vdays, cfg)
            res[name] = {"incident_recall": s["test_week"]["injection_recall"], "recall_by_scenario": s["test_week"]["recall_by_scenario"],
                         "event_recall": s["event_level"]["recall"], "ttd_p50_s": s["ttd_p50_s"], "ttd_p95_s": s["ttd_p95_s"],
                         "tp_incidents": s["test_week"]["tp_incidents"], "fp_incidents": s["test_week"]["fp_incidents"],
                         "injections": int(tcon.execute("select count(*) from injections").fetchone()[0])}
        tcon.close()
        out["results"][str(lv)] = res
        print(f"stealth {lv} ({LEVEL_NOTES.get(lv, '')}): " + "  ".join(f"{k}={v['incident_recall']}" for k, v in res.items()) + f"  [{time.time()-ts:.0f}s]", flush=True)
        if path.name.startswith("robust_") and not a.keep:
            path.unlink()
        Path(a.out).parent.mkdir(exist_ok=True)
        json.dump(out, open(a.out, "w"), indent=1, default=str)
    print(f"done in {time.time()-t0:.0f}s -> {a.out}")


if __name__ == "__main__":
    main()
