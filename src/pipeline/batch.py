"""Batch (backfill) detection helpers shared by evaluation, the live worker and the dashboard."""
from __future__ import annotations

import json
from typing import Optional

import numpy as np
import pandas as pd

from src.detection.explain import explain
from src.detection.features import Baseline, compute_windows
from src.detection.iforest import AnomalyModel, windows_to_alerts
from src.detection.rules_engine import Alert, RulesEngine
from src.generator.world import load_yaml


def org_context() -> dict:
    org = load_yaml("org.yaml")["org"]
    return {"account_id": org["account_id"], "home_regions": list(org["home_regions"])}


def rules_alerts(con, disabled: Optional[set] = None, where: str = "", context: Optional[dict] = None, dedupe_s: Optional[float] = None) -> list[Alert]:
    eng = RulesEngine(context=context or org_context(), disabled=disabled, **({} if dedupe_s is None else {"dedupe_s": dedupe_s}))
    out: list[Alert] = []
    cur = con.execute(f"SELECT raw FROM events {where} ORDER BY event_time, event_id")
    while True:
        rows = cur.fetchmany(50_000)
        if not rows:
            break
        for (raw,) in rows:
            out.extend(eng.evaluate(json.loads(raw)))
    return out


def anomaly_alerts(events: pd.DataFrame, baseline: Baseline, model: AnomalyModel, with_reasons: bool = True, top_k: int = 5):
    feats = compute_windows(events, baseline)
    scores = model.score(feats)
    flagged = model.flag(feats, scores)
    reasons = {}
    if with_reasons and flagged.any():
        idx = np.where(flagged)[0]
        rs = explain(model, feats.iloc[idx], top_k)
        reasons = {(feats.at[i, "identity"], feats.at[i, "wstart"]): r for i, r in zip(idx, rs)}
    return windows_to_alerts(feats, scores, flagged, events, reasons, model.threshold_for(feats)), feats, scores


def alerts_df(alerts: list[Alert]) -> pd.DataFrame:
    cols = ["rule_id", "title", "severity", "event_id", "event_time", "detected_at", "identity", "source_ip", "matched_event_ids", "source", "score"]
    if not alerts:
        return pd.DataFrame(columns=cols)
    return pd.DataFrame([a.to_dict() for a in alerts])


# ------------------------------------------------------------------------------------------ IP layer, scoring, incidents
def ip_alerts(events: pd.DataFrame, baseline: Baseline, cfg: Optional[dict] = None) -> list[Alert]:
    from src.detection.ip_analysis import IpAnalyzer
    from src.detection.scoring import load_config
    cfg = cfg or load_config()
    return IpAnalyzer(cfg["ip"], baseline).evaluate_frame(events)


def org_known_ips(baseline: Baseline) -> set:
    return set(baseline.org_sets["ip"]["value"])


def combine(layer_alerts: dict, layers: tuple, baseline: Baseline, cfg: Optional[dict] = None, suppressions=None):
    """Merge the chosen layers' alerts -> score -> (optional suppression) -> group into incidents. Returns (alerts, incidents)."""
    import copy
    from src.detection.incidents import group_alerts
    from src.detection.scoring import load_config, score_alerts
    cfg = cfg or load_config()
    alerts = [copy.copy(a) for layer in layers for a in layer_alerts[layer]]
    alerts = score_alerts(alerts, cfg)
    if suppressions is not None:
        alerts, _ = suppressions.apply(alerts)
    return alerts, group_alerts(alerts, cfg, org_known_ips(baseline))
