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


def event_level(alerts: pd.DataFrame, con) -> dict:
    """Event-level precision/recall: an event is 'predicted' if it appears in any alert's matched events."""
    mal = {r[0]: r[1] for r in con.execute("SELECT event_id, scenario_id FROM labels WHERE is_malicious").fetchall()}
    pred: set = set()
    for row in alerts.itertuples():
        pred |= set(row.matched_event_ids) | {row.event_id}
    tp = len(pred & set(mal))
    per: dict = defaultdict(lambda: [0, 0])
    for e, s in mal.items():
        per[s][1] += 1
        per[s][0] += e in pred
    prec = tp / len(pred) if pred else 0.0
    rec = tp / len(mal) if mal else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4), "predicted_events": len(pred),
            "recall_by_scenario": {s: round(v[0] / v[1], 3) for s, v in sorted(per.items())}}


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
                t = pd.Timestamp(str(row.detected_at).rstrip("Z"))
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


def score_incidents(incidents: list, con, days: float) -> dict:
    """Incident-level metrics. An incident is a true positive if it overlaps any malicious event."""
    from collections import Counter
    mal = {r[0]: (r[1], r[2]) for r in con.execute("SELECT event_id, scenario_id, injection_id FROM labels WHERE is_malicious").fetchall()}
    inj = con.execute("SELECT injection_id, scenario_id, chain_id FROM injections").fetchdf()
    inj_events: dict = defaultdict(set)
    for e, (s, i) in mal.items():
        inj_events[i].add(e)
    tp = fp = 0
    detected: set = set()
    fp_sev: Counter = Counter()
    tp_sev: Counter = Counter()
    chain_incidents: dict = defaultdict(set)
    chain_of = dict(zip(inj.injection_id, inj.chain_id))
    for inc in incidents:
        ids = set(inc.matched_event_ids)
        hit = [i for i, evs in inj_events.items() if ids & evs]
        if hit:
            tp += 1
            tp_sev[inc.severity] += 1
            detected.update(hit)
            for i in hit:
                if chain_of.get(i):
                    chain_incidents[chain_of[i]].add(inc.incident_id)
        else:
            fp += 1
            fp_sev[inc.severity] += 1
    per = {}
    for sid, g in inj.groupby("scenario_id"):
        ids = set(g.injection_id)
        per[sid] = round(len(ids & detected) / len(ids), 3)
    n_chains = int(inj.chain_id.nunique())
    consolidated = sum(1 for v in chain_incidents.values() if len(v) == 1)
    high_fp = fp_sev["HIGH"] + fp_sev["CRITICAL"]
    return {"incidents": len(incidents), "tp_incidents": tp, "fp_incidents": fp,
            "incident_precision": round(tp / len(incidents), 3) if incidents else 0.0,
            "injection_recall": round(len(detected) / max(len(inj), 1), 3), "recall_by_scenario": per,
            "fp_incidents_per_day": round(fp / days, 2), "fp_high_or_critical_per_day": round(high_fp / days, 2),
            "fp_by_severity": dict(fp_sev), "tp_by_severity": dict(tp_sev),
            "chains": n_chains, "chains_in_single_incident": consolidated}
