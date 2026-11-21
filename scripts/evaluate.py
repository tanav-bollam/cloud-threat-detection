"""Evaluate detection layers on the held-out test week; false positives measured on the benign validation week.

  python scripts/evaluate.py            -> reports/metrics.json
Combos: rules only / anomaly only (global, per_group) / rules + anomaly.
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
import pandas as pd

from src.detection.explain import format_reasons
from src.detection.features import load_events
from src.detection.iforest import AnomalyModel
from src.evaluation import event_level, score
from src.pipeline.batch import alerts_df, anomaly_alerts, rules_alerts


def summarize(alerts: pd.DataFrame, test_con, val_alerts: pd.DataFrame, val_days: float, days: float) -> dict:
    s = score(alerts, test_con, days)
    s.update({"event_level": event_level(alerts, test_con), "benign_week_fp_alerts_per_day": round(len(val_alerts) / val_days, 2),
              "benign_week_fp_alerts": len(val_alerts)})
    t = pd.Series(s.pop("ttd_seconds"))
    s["ttd_p50_s"] = float(t.median()) if len(t) else None
    s["ttd_p95_s"] = float(t.quantile(0.95)) if len(t) else None
    return s


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default="data/test.duckdb")
    ap.add_argument("--val", default="data/val.duckdb")
    ap.add_argument("--models", default="models")
    ap.add_argument("--out", default="reports/metrics.json")
    a = ap.parse_args()
    t0 = time.time()
    base = joblib.load(Path(a.models) / "baseline.joblib")
    tcon, vcon = duckdb.connect(a.test, read_only=True), duckdb.connect(a.val, read_only=True)
    tev, vev = load_events(tcon), load_events(vcon)
    days = (tev["event_time"].max() - tev["event_time"].min()).total_seconds() / 86400
    vdays = (vev["event_time"].max() - vev["event_time"].min()).total_seconds() / 86400

    r_test, r_val = alerts_df(rules_alerts(tcon)), alerts_df(rules_alerts(vcon))
    print(f"rules done ({time.time()-t0:.0f}s): test {len(r_test)} alerts, val {len(r_val)}")
    res = {"test_days": round(days, 2), "val_days": round(vdays, 2), "injections": int(tcon.execute("select count(*) from injections").fetchone()[0])}
    res["rules_only"] = summarize(r_test, tcon, r_val, vdays, days)
    samples = {}
    for mode in ("global", "per_group"):
        m = AnomalyModel.load(Path(a.models) / f"anomaly_{mode}.joblib")
        at, _, _ = anomaly_alerts(tev, base, m)
        av, _, _ = anomaly_alerts(vev, base, m, with_reasons=False)
        a_test, a_val = alerts_df(at), alerts_df(av)
        res[f"anomaly_{mode}"] = summarize(a_test, tcon, a_val, vdays, days)
        res[f"rules_plus_anomaly_{mode}"] = summarize(pd.concat([r_test, a_test], ignore_index=True), tcon,
                                                      pd.concat([r_val, a_val], ignore_index=True), vdays, days)
        samples[mode] = [(x.identity, x.detected_at, round(x.score, 3), format_reasons(x.reasons)) for x in sorted(at, key=lambda x: -x.score)[:5]]
    res["sample_top_anomalies"] = samples
    Path(a.out).parent.mkdir(exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, default=str)
    print(f"\n{'layer':<32}{'inj recall':>11}{'evt P':>8}{'evt R':>8}{'FP/day(val)':>13}{'TTD p50 s':>11}")
    for k, v in res.items():
        if isinstance(v, dict) and "overall_injection_recall" in v:
            print(f"{k:<32}{v['overall_injection_recall']:>11}{v['event_level']['precision']:>8}{v['event_level']['recall']:>8}"
                  f"{v['benign_week_fp_alerts_per_day']:>13}{v['ttd_p50_s']:>11}")
    print("\nper-scenario injection recall:")
    sc = sorted({s for k, v in res.items() if isinstance(v, dict) and "per_scenario" in v for s in v["per_scenario"]})
    print(f"{'layer':<32}" + "".join(f"{s:>6}" for s in sc))
    for k, v in res.items():
        if isinstance(v, dict) and "per_scenario" in v:
            print(f"{k:<32}" + "".join(f"{v['per_scenario'].get(s, {}).get('recall', '-'):>6}" for s in sc))
    print("\ntop anomalies (global):")
    for x in samples["global"]:
        print(" ", x)
    print(f"\nfinished in {time.time()-t0:.0f}s -> {a.out}")


if __name__ == "__main__":
    main()
