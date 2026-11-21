"""Evaluate detection layers on the held-out test week; false positives are measured on the benign validation week.

  python scripts/evaluate.py [--cache]    -> reports/metrics.json (global model) + reports/metrics_per_group.json

Layers: rules, anomaly (IsolationForest), ip. Ablation combos are scored at alert level and incident level, with per-scenario
precision/recall/F1. Everything in docs/RESULTS.md is generated from these files by scripts/make_results.py.
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
import yaml

from src.detection.explain import format_reasons
from src.detection.features import load_events
from src.detection.iforest import AnomalyModel
from src.detection.scoring import load_config
from src.evaluation import event_level, scenario_prf, score, score_incidents
from src.pipeline.batch import alerts_df, anomaly_alerts, combine, ip_alerts, rules_alerts

COMBOS = {
    "rules_only": ("rules",),
    "anomaly_only": ("anomaly",),
    "ip_only": ("ip",),
    "rules+ip": ("rules", "ip"),
    "rules+anomaly": ("rules", "anomaly"),
    "combined": ("rules", "anomaly", "ip"),
}
MODES = ("global", "per_group")


def compute_layers(con, events, base, models: dict, with_reasons: bool) -> dict:
    out = {"rules": rules_alerts(con), "ip": ip_alerts(events, base)}
    for mode, m in models.items():
        out[f"anomaly_{mode}"] = anomaly_alerts(events, base, m, with_reasons=with_reasons)[0]
    return out


def summarize_combo(combo, tl, vl, base, test_con, val_con, days, vdays, cfg) -> dict:
    t_alerts, t_inc = combine(tl, combo, base, cfg)
    v_alerts, v_inc = combine(vl, combo, base, cfg)
    adf = alerts_df(t_alerts)
    a = score(adf, test_con, days)
    ttd = pd.Series(a.pop("ttd_seconds"), dtype=float)
    return {
        "alerts": a["alerts"], "alert_injection_recall": a["overall_injection_recall"], "event_level": event_level(adf, test_con),
        "ttd_p50_s": float(ttd.median()) if len(ttd) else None, "ttd_p95_s": float(ttd.quantile(0.95)) if len(ttd) else None,
        "ttd_sim_s": [round(x, 1) for x in ttd.tolist()],
        "test_week": score_incidents(t_inc, test_con, days),
        "per_scenario": scenario_prf(adf, t_inc, test_con),
        "benign_week": {"incidents": len(v_inc), "fp_incidents_per_day": round(len(v_inc) / vdays, 2),
                        "fp_high_or_critical_per_day": round(sum(i.severity in ("HIGH", "CRITICAL") for i in v_inc) / vdays, 2),
                        "alerts_per_day": round(len(v_alerts) / vdays, 2),
                        "alerts_by_source": {s: sum(1 for x in v_alerts if x.source == s) for s in ("rule", "anomaly", "ip")}},
    }


def evaluate_week(test_db, val_db, models_dir, cache=None, modes=MODES) -> dict:
    cfg = load_config()
    base = joblib.load(Path(models_dir) / "baseline.joblib")
    models = {m: AnomalyModel.load(Path(models_dir) / f"anomaly_{m}.joblib") for m in modes}
    tcon, vcon = duckdb.connect(str(test_db), read_only=True), duckdb.connect(str(val_db), read_only=True)
    tev, vev = load_events(tcon), load_events(vcon)
    days = (tev["event_time"].max() - tev["event_time"].min()).total_seconds() / 86400
    vdays = (vev["event_time"].max() - vev["event_time"].min()).total_seconds() / 86400
    if cache and Path(cache).exists():
        tl_all, vl_all = joblib.load(cache)
    else:
        tl_all = compute_layers(tcon, tev, base, models, True)
        vl_all = compute_layers(vcon, vev, base, models, False)
        if cache:
            joblib.dump((tl_all, vl_all), cache)
    results = {}
    for mode in modes:
        tl = {"rules": tl_all["rules"], "ip": tl_all["ip"], "anomaly": tl_all[f"anomaly_{mode}"]}
        vl = {"rules": vl_all["rules"], "ip": vl_all["ip"], "anomaly": vl_all[f"anomaly_{mode}"]}
        res = {"mode": mode, "test_days": round(days, 2), "val_days": round(vdays, 2),
               "injections": int(tcon.execute("select count(*) from injections").fetchone()[0]),
               "detector_config": yaml.safe_load(open("config/detector.yaml", encoding="utf-8"))["anomaly"],
               "layers": {name: summarize_combo(combo, tl, vl, base, tcon, vcon, days, vdays, cfg) for name, combo in COMBOS.items()}}
        t_alerts, t_inc = combine(tl, COMBOS["combined"], base, cfg)
        res["sample_top_anomalies"] = [(x.identity, x.detected_at, round(x.score, 3), format_reasons(x.reasons))
                                       for x in sorted(tl["anomaly"], key=lambda x: -x.score)[:5]]
        res["sample_incidents"] = [{k: i.to_dict()[k] for k in ("incident_id", "title", "severity", "risk_score", "tactics", "sources", "n_alerts")}
                                   for i in sorted(t_inc, key=lambda i: -i.risk_score)[:8]]
        results[mode] = res
    return results


def print_summary(res: dict) -> None:
    L = res["layers"]
    print(f"\n[{res['mode']}] {'layer':<16}{'inc recall':>11}{'inc prec':>9}{'FP inc/day':>11}{'FP H+C/day':>11}{'evt P':>7}{'evt R':>7}{'TTD p50':>9}{'chains=1':>9}")
    for k, v in L.items():
        w, b = v["test_week"], v["benign_week"]
        print(f"{'':<5}{k:<16}{w['injection_recall']:>11}{w['incident_precision']:>9}{b['fp_incidents_per_day']:>11}{b['fp_high_or_critical_per_day']:>11}"
              f"{v['event_level']['precision']:>7}{v['event_level']['recall']:>7}{v['ttd_p50_s']:>9}{'  ' + str(w['chains_in_single_incident']) + '/' + str(w['chains']):>9}")
    print("\n  combined, per scenario (incident level):  " + "  ".join(f"{s}: P{v['incident']['precision']:.2f} R{v['incident']['recall']:.2f} F1 {v['incident']['f1']:.2f}"
                                                                     for s, v in L["combined"]["per_scenario"].items()))


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", default="data/test.duckdb")
    ap.add_argument("--val", default="data/val.duckdb")
    ap.add_argument("--models", default="models")
    ap.add_argument("--out-dir", default="reports")
    ap.add_argument("--cache", action="store_true", help="reuse/save per-layer alerts (reports/layers_cache.joblib)")
    a = ap.parse_args()
    t0 = time.time()
    out = Path(a.out_dir)
    out.mkdir(exist_ok=True)
    results = evaluate_week(a.test, a.val, a.models, cache=out / "layers_cache.joblib" if a.cache else None)
    for mode, res in results.items():
        json.dump(res, open(out / ("metrics.json" if mode == "global" else f"metrics_{mode}.json"), "w"), indent=1, default=str)
        print_summary(res)
    print(f"\nfinished in {time.time()-t0:.0f}s")


if __name__ == "__main__":
    main()
