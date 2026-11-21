"""Group alerts into incidents: same identity OR same (non-org-known) source IP within a time gap, with severity, MITRE chain."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Iterable, Optional

import pandas as pd

from .rules_engine import SEVERITY_ORDER, Alert
from .scoring import load_config, max_severity, severity_from_risk

STATUSES = ("Open", "Investigating", "Resolved", "False Positive")


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: str
    risk_score: float
    first_seen: str
    last_seen: str
    identities: list[str]
    ips: list[str]
    tactics: list[str]                 # MITRE chain in order of first occurrence
    techniques: list[str]
    alert_ids: list[str]
    sources: list[str]                 # rule / anomaly / ip layers that contributed
    n_alerts: int
    matched_event_ids: list[str] = field(default_factory=list)
    status: str = "Open"

    def to_dict(self) -> dict:
        return asdict(self)


class _UF:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


def group_alerts(alerts: Iterable[Alert], cfg: Optional[dict] = None, org_known_ips: Optional[set] = None) -> list[Incident]:
    cfg = cfg or load_config()
    gap = cfg["incidents"]["gap_s"]
    high_gap = cfg["incidents"].get("high_severity_gap_s", gap)    # an identity/IP tied to a HIGH+ alert stays linked longer
    sc = cfg["scoring"]
    org_known_ips = org_known_ips or set()
    al = sorted(alerts, key=lambda a: (a.event_time, a.alert_id))
    if not al:
        return []
    ts = [pd.Timestamp(a.event_time.rstrip("Z")).timestamp() for a in al]
    uf = _UF(len(al))
    last: dict[tuple, tuple[float, int, int]] = {}                 # key -> (time, alert index, max severity rank so far)
    for i, a in enumerate(al):
        rank = SEVERITY_ORDER[a.severity]
        keys = [("id", a.identity)]
        if a.source_ip and a.source_ip not in org_known_ips and a.source_ip[0].isdigit():
            keys.append(("ip", a.source_ip))
        for k in keys:
            prev = last.get(k)
            if prev and ts[i] - prev[0] <= (high_gap if prev[2] >= SEVERITY_ORDER["HIGH"] else gap):
                uf.union(i, prev[1])
            last[k] = (ts[i], i, max(rank, prev[2]) if prev else rank)
    comps: dict[int, list[int]] = {}
    for i in range(len(al)):
        comps.setdefault(uf.find(i), []).append(i)
    out = []
    for idxs in comps.values():
        grp = [al[i] for i in idxs]
        out.append(_build(grp, sc))
    return sorted(out, key=lambda x: x.first_seen)


def _build(grp: list[Alert], sc: dict) -> Incident:
    grp = sorted(grp, key=lambda a: (a.event_time, a.alert_id))
    tactics: list[str] = []
    techniques: list[str] = []
    for a in grp:
        if a.mitre_tactic and a.mitre_tactic not in tactics:
            tactics.append(a.mitre_tactic)
        if a.mitre_technique and a.mitre_technique not in techniques:
            techniques.append(a.mitre_technique)
    sources = sorted({a.source for a in grp})
    risk = max(a.risk for a in grp) + sc["corroboration_bonus"] * (len(sources) - 1) + sc["tactic_bonus"] * max(len(tactics) - 1, 0)
    risk = round(min(risk, 100.0), 1)
    sev = max_severity(*[a.severity for a in grp])
    if len(tactics) >= sc["escalate_min_tactics"]:
        sev = max_severity(sev, "HIGH")
    sev = max_severity(sev, severity_from_risk(risk, sc))
    idents = sorted({a.identity for a in grp})
    ips = sorted({a.source_ip for a in grp if a.source_ip})
    top = max(grp, key=lambda a: (SEVERITY_ORDER[a.severity], a.risk))
    who = idents[0] if len(idents) == 1 else f"{idents[0]} +{len(idents)-1} more"
    title = (f"Multi-stage activity on {who}: " + " → ".join(tactics)) if len(tactics) >= 2 else f"{top.title} — {who}"
    matched: list[str] = []
    seen: set = set()
    for a in grp:
        for e in a.matched_event_ids:
            if e not in seen:
                seen.add(e); matched.append(e)
    iid = "INC-" + hashlib.sha1(grp[0].alert_id.encode()).hexdigest()[:8].upper()
    return Incident(iid, title, sev, risk, grp[0].event_time, max(a.detected_at for a in grp), idents, ips, tactics, techniques,
                    [a.alert_id for a in grp], sources, len(grp), matched)
