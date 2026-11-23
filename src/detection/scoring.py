"""Combined risk scoring: rule severity + anomaly strength + IP signals -> per-alert risk and severity. All weights live in config."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable

import yaml

from .rules_engine import SEVERITY_ORDER, Alert

ROOT = Path(__file__).resolve().parents[2]
SEV_BY_RANK = {v: k for k, v in SEVERITY_ORDER.items()}


def load_config() -> dict:
    return yaml.safe_load((ROOT / "config" / "detector.yaml").read_text(encoding="utf-8"))


def alert_id(a: Alert) -> str:
    return "A-" + hashlib.sha1(f"{a.rule_id}|{a.event_id}|{a.identity}".encode()).hexdigest()[:12]


def sev_from_margin(margin: float, sc: dict) -> str:
    return "LOW" if margin < sc["anomaly"]["margin_low"] else "MEDIUM" if margin < sc["anomaly"]["margin_high"] else "HIGH"


def anomaly_tactic(reasons: list[dict], sc: dict) -> str:
    mapping = sc["anomaly_feature_tactics"]
    for r in reasons:
        if r["feature"] in mapping:
            return mapping[r["feature"]]
    return ""


def score_alert(a: Alert, sc: dict) -> Alert:
    pts = sc["severity_points"]
    w = sc["weights"]
    if a.source == "anomaly":
        a.severity = sev_from_margin(a.margin, sc)
        a.mitre_tactic = a.mitre_tactic or anomaly_tactic(a.reasons, sc)
        an = sc["anomaly"]
        frac = min(max(a.margin / an["margin_full"], 0.0), 1.0)
        a.risk = (pts["LOW"] + frac * (an["max_points"] - pts["LOW"])) * w["anomaly"]
    else:
        a.risk = pts[a.severity] * w["ip" if a.source == "ip" else "rule"]      # source "flow" (VPC flow correlation) is weighted like a rule
    a.risk = round(min(a.risk, 100.0), 1)
    a.alert_id = alert_id(a)
    return a


def score_alerts(alerts: Iterable[Alert], cfg: dict | None = None) -> list[Alert]:
    sc = (cfg or load_config())["scoring"]
    return [score_alert(a, sc) for a in alerts]


def severity_from_risk(risk: float, sc: dict) -> str:
    sev = "LOW"
    for name in ("MEDIUM", "HIGH", "CRITICAL"):
        if risk >= sc["severity_from_risk"][name]:
            sev = name
    return sev


def max_severity(*sevs: str) -> str:
    return SEV_BY_RANK[max(SEVERITY_ORDER[s] for s in sevs)]
