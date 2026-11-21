"""Evaluate detection layers on the held-out test week; false positives are measured on the benign validation week.

  python scripts/evaluate.py            -> reports/metrics.json

Layers: rules, anomaly (IsolationForest), ip. Ablation combos are scored at alert level and incident level.
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
from src.detection.scoring import load_config
from src.evaluation import event_level, score, score_incidents
from src.pipeline.batch import alerts_df, anomaly_alerts, combine, ip_alerts, rules_alerts

COMBOS = {
    "rules_only": ("rules",),
    "anomaly_only": ("anomaly",),
    "ip_only": ("ip",),
    "rules+ip": ("rules", "ip"),
    "rules+anomaly": ("rules", "anomaly"),
    "combined": ("rules", "anomaly", "ip"),
}


def layer_alerts(con, events, base, model, with_reasons):
    anom, _, _ = anomaly_alerts(events, base, model, with_reasons=with_reasons)
    return {"rules": rules_alerts(con), "anomaly": anom, "ip": ip_alerts(events, base)}


def summarize(layers, test_con, val_con, tl, vl, base, days, vdays, cfg):
    out = {}
    for name, combo in COMBOS.items():
        t_alerts, t_inc = combine(tl, combo, base, cfg)
        v_alerts, v_inc = combine(vl, combo, base, cfg)
        a = score(alerts_df(t_alerts), test_con, days)
        ttd = pd.Series(a.pop("ttd_seconds"))
        inc = score_incidents(t_inc, test_con, days)
        vinc = score_incidents(v_inc, val_con, vdays)          # benign week: every incident is a false positive
        out[name] = {
            "alerts": a["alerts"], "alert_injection_recall": a["overall_injection_recall"],
            "event_level": event_level(alerts_df(t_alerts), test_con),
            "ttd_p50_s": float(ttd.median()) if len(ttd) else None, "ttd_p95_s": float(ttd.quantile(0.95)) if len(ttd) else None,
            "test_week": inc,
            "benign_week": {"incidents": len(v_inc), "fp_incidents_per_day": round(len(v_inc) / vdays, 2),
                            "fp_high_or_critical_per_day": round(sum(i.severity in ("HIGH", "CRITICAL") for i in v_inc) / vdays, 2),
                            "alerts_per_day": round(len(v_alerts) / vdays, 2)},
        }
    return out


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", action="store_true", help="reuse/save per-layer alerts (reports/layers_cache.joblib)")
    ap.add_argument("--test", default="data/test.duckdb")
    ap.add_argument("--val", default="data/val.duckdb")
    ap.add_argument("--models", default="models")
    ap.add_argument("--mode", default="global", choices=["global", "per_group"])
    ap.add_argument("--out", default="reports/metrics.json")
    a = ap.parse_args()
    t0 = time.time()
    cfg = load_config()
    base = joblib.load(Path(a.models) / "baseline.joblib")
    model = AnomalyModel.load(Path(a.models) / f"anomaly_{a.mode}.joblib")
    tcon, vcon = duckdb.connect(a.test, read_only=True), duckdb.connect(a.val, read_only=True)
    tev, vev = load_events(tcon), load_events(vcon)
    days = (tev["event_time"].max() - tev["event_time"].min()).total_seconds() / 86400
    vdays = (vev["event_time"].max() - vev["event_time"].min()).total_seconds() / 86400

    cache = Path("reports/layers_cache.joblib")
    if a.cache and cache.exists():
        tl, vl = joblib.load(cache)
    else:
        tl = layer_alerts(tcon, tev, base, model, True)
        vl = layer_alerts(vcon, vev, base, model, False)
        if a.cache:
            joblib.dump((tl, vl), cache)
    print(f"layers done ({time.time()-t0:.0f}s): test " + ", ".join(f"{k}={len(v)}" for k, v in tl.items()) + " | val " + ", ".join(f"{k}={len(v)}" for k, v in vl.items()))
    res = {"mode": a.mode, "test_days": round(days, 2), "val_days": round(vdays, 2),
           "injections": int(tcon.execute("select count(*) from injections").fetchone()[0])}
    res["layers"] = summarize(None, tcon, vcon, tl, vl, base, days, vdays, cfg)
    t_alerts, t_inc = combine(tl, COMBOS["combined"], base, cfg)
    res["sample_top_anomalies"] = [(x.identity, x.detected_at, round(x.score, 3), format_reasons(x.reasons))
                                   for x in sorted(tl["anomaly"], key=lambda x: -x.score)[:5]]
    res["sample_incidents"] = [{k: i.to_dict()[k] for k in ("incident_id", "title", "severity", "risk_score", "tactics", "sources", "n_alerts")}
                               for i in sorted(t_inc, key=lambda i: -i.risk_score)[:8]]
    Path(a.out).parent.mkdir(exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, default=str)

    L = res["layers"]
    print(f"\n{'layer':<16}{'inc recall':>11}{'inc prec':>9}{'FP inc/day':>11}{'FP H+C/day':>11}{'evt P':>7}{'evt R':>7}{'TTD p50':>9}{'chains=1':>9}")
    for k, v in L.items():
        w, b = v["test_week"], v["benign_week"]
        print(f"{k:<16}{w['injection_recall']:>11}{w['incident_precision']:>9}{b['fp_incidents_per_day']:>11}{b['fp_high_or_critical_per_day']:>11}"
              f"{v['event_level']['precision']:>7}{v['event_level']['recall']:>7}{v['ttd_p50_s']:>9}{'  ' + str(w['chains_in_single_incident']) + '/' + str(w['chains']):>9}")
    sc = sorted(L["combined"]["test_week"]["recall_by_scenario"])
    print("\nincident-level recall per scenario:\n" + f"{'layer':<16}" + "".join(f"{s:>6}" for s in sc))
    for k, v in L.items():
        print(f"{k:<16}" + "".join(f"{v['test_week']['recall_by_scenario'].get(s, '-'):>6}" for s in sc))
    print("\ncombined: TP incidents by severity", L["combined"]["test_week"]["tp_by_severity"], "| FP by severity", L["combined"]["test_week"]["fp_by_severity"])
    print("sample incidents:")
    for i in res["sample_incidents"][:5]:
        print(" ", i["incident_id"], i["severity"], i["risk_score"], i["title"][:90], i["sources"])
    print(f"\nfinished in {time.time()-t0:.0f}s -> {a.out}")


if __name__ == "__main__":
    main()
