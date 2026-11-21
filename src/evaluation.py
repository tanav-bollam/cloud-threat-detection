"""Scoring of alerts against ground truth. This is the ONLY module (besides scripts) allowed to read the labels table."""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable

import pandas as pd


def load_truth(con) -> tuple[dict, dict, pd.DataFrame]:
    """Returns (event_id -> (is_malicious, scenario_id, injection_id), injection_id -> set(malicious event ids), injections df)."""
    lab = con.execute("SELECT event_id, is_malicious, scenario_id, injection_id FROM labels WHERE scenario_id IS NOT NULL").fetchall()
    truth = {e: (m, s, i) for e, m, s, i in lab}
    inj_events: dict[str, set] = defaultdict(set)
    for e, m, s, i in lab:
        if m and i:
            inj_events[i].add(e)
    inj = con.execute("SELECT * FROM injections").fetchdf()
    return truth, inj_events, inj


def score(alerts: pd.DataFrame, con, days: float) -> dict:
    """alerts needs columns: event_id, matched_event_ids(list), rule_id/source."""
    truth, inj_events, inj = load_truth(con)
    first_alert: dict[str, pd.Timestamp] = {}
    detected: set[str] = set()
    tp_alerts = fp_alerts = 0
    fp_by_noise: dict[str, int] = defaultdict(int)
    benign_alert_events = set()
    for row in alerts.itertuples():
        ids = set(row.matched_event_ids) | {row.event_id}
        hit = False
        for inj_id, evs in inj_events.items():
            if ids & evs:
                detected.add(inj_id)
                hit = True
                t = pd.Timestamp(str(row.event_time).rstrip("Z"))
                if inj_id not in first_alert or t < first_alert[inj_id]:
                    first_alert[inj_id] = t
        if hit:
            tp_alerts += 1
        else:
            fp_alerts += 1
            t = truth.get(row.event_id)
            fp_by_noise[t[1] if t else "benign_baseline"] += 1
            benign_alert_events.add(row.event_id)
    per = {}
    for sid, g in inj.groupby("scenario_id"):
        ids = set(g.injection_id)
        per[sid] = {"injections": len(ids), "detected": len(ids & detected), "recall": round(len(ids & detected) / len(ids), 3)}
    ttd = []
    for r in inj.itertuples():
        if r.injection_id in first_alert:
            ttd.append(max(0.0, (first_alert[r.injection_id] - pd.Timestamp(r.start_time)).total_seconds()))
    return {"alerts": len(alerts), "true_positive_alerts": tp_alerts, "false_positive_alerts": fp_alerts,
            "fp_alerts_per_day": round(fp_alerts / days, 2), "fp_by_source": dict(fp_by_noise), "per_scenario": per,
            "overall_injection_recall": round(len(detected) / max(len(inj), 1), 3), "ttd_seconds": sorted(ttd)}
