"""Sigma-inspired rules engine. Rules are YAML (rules/*.yaml); evaluation is streaming-friendly and stateful for
thresholds and sequences, so the same object works for batch backfill and the live worker.

Rule shape:
  id, title, severity, mitre_tactic, mitre_technique, description, false_positive_notes
  condition:
    event_name: [A, B]                         # shorthand for an eventName `in` match
    all: [{field: a.b.c, op: eq|ne|in|not_in|contains|regex|startswith|exists|gt|gte|lt|lte, value: ...}, ...]
    none: [...]                                # exclusions
    check: <name>                              # python predicate from rule_checks.CHECKS
    threshold: {count: N, window_s: S, group_by: [field,...], cooldown_s: optional}
    sequence:  {prior: {all: [...]}, prior_count: N, window_s: S, group_by: [field,...]}
The detector never reads ground truth; it only sees CloudTrail records.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

import yaml

from .rule_checks import CHECKS

ROOT = Path(__file__).resolve().parents[2]
SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_MISSING = object()


def get_path(rec: dict, path: str) -> Any:
    cur: Any = rec
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _cmp(op: str, got: Any, want: Any) -> bool:
    if op == "exists":
        return (got is not _MISSING and got is not None) == bool(want)
    if got is _MISSING or got is None:
        return op in ("ne", "not_in")
    if op == "eq":
        return got == want
    if op == "ne":
        return got != want
    if op == "in":
        return got in want
    if op == "not_in":
        return got not in want
    if op == "contains":
        return (want in got) if isinstance(got, (str, list, tuple)) else False
    if op == "startswith":
        return isinstance(got, str) and got.startswith(want)
    if op == "regex":
        return isinstance(got, str) and re.search(want, got, re.I) is not None
    try:
        return {"gt": got > want, "gte": got >= want, "lt": got < want, "lte": got <= want}[op]
    except (TypeError, KeyError):
        return False


def _parse_time(s: str) -> float:
    return datetime.fromisoformat(s.rstrip("Z")).timestamp()


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    event_id: str                  # triggering event
    event_time: str
    identity: str
    source_ip: str
    description: str
    event_name: str = ""
    matched_event_ids: list[str] = field(default_factory=list)
    detail: str = ""
    detected_at: str = ""          # when the detector could first know (rules: event time; windows: window end)
    source: str = "rule"           # rule | anomaly | ip
    score: float = 0.0
    reasons: list = field(default_factory=list)
    margin: float = 0.0            # anomaly alerts: score minus the calibrated threshold
    risk: float = 0.0              # 0-100, set by scoring
    alert_id: str = ""             # stable id, set by scoring

    def __post_init__(self) -> None:
        if not self.detected_at:
            self.detected_at = self.event_time

    def to_dict(self) -> dict:
        return asdict(self)


def identity_of(rec: dict) -> str:
    ui = rec["userIdentity"]
    if ui["type"] == "AssumedRole":
        return (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName") or ui["arn"]
    return ui.get("userName") or ui["arn"]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    false_positive_notes: str
    condition: dict
    enabled: bool = True

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(id=d["id"], title=d["title"], severity=d["severity"].upper(), mitre_tactic=d.get("mitre_tactic", ""),
                   mitre_technique=d.get("mitre_technique", ""), description=d.get("description", "").strip(),
                   false_positive_notes=d.get("false_positive_notes", "").strip(), condition=d["condition"],
                   enabled=d.get("enabled", True))


class RulesEngine:
    def __init__(self, rules: Optional[list[Rule]] = None, rules_dir: str | Path | None = None, context: Optional[dict] = None,
                 disabled: Optional[set[str]] = None):
        self.rules = rules if rules is not None else load_rules(rules_dir)
        self.ctx = {"account_id": "123456789012", "home_regions": ["us-east-1", "us-west-2"], **(context or {})}
        self.disabled = disabled or set()
        self._win: dict[tuple, deque] = defaultdict(deque)       # (rule_id, group) -> deque[(t, event_id)]
        self._prior: dict[tuple, deque] = defaultdict(deque)
        self._last_fire: dict[tuple, float] = {}
        self._by_name: dict[str, list[Rule]] = defaultdict(list)
        self._any: list[Rule] = []
        for r in self.rules:
            names = _event_names(r.condition)
            if names is None or "sequence" in r.condition:
                self._any.append(r)
            else:
                for n in names:
                    self._by_name[n].append(r)

    def reset(self) -> None:
        self._win.clear(); self._prior.clear(); self._last_fire.clear()

    # -------------------------------------------------------------------------------- matching
    def _match(self, cond: dict, rec: dict, include_check: bool = True) -> bool:
        if "event_name" in cond and rec["eventName"] not in cond["event_name"]:
            return False
        for c in cond.get("all", []):
            if not _cmp(c["op"], get_path(rec, c["field"]), c.get("value")):
                return False
        for c in cond.get("none", []):
            if _cmp(c["op"], get_path(rec, c["field"]), c.get("value")):
                return False
        if include_check and "check" in cond and not CHECKS[cond["check"]](rec, self.ctx):
            return False
        return True

    @staticmethod
    def _group(spec: dict, rec: dict) -> tuple:
        out = []
        for f in spec.get("group_by", []):
            out.append(identity_of(rec) if f == "identity" else str(get_path(rec, f)))
        return tuple(out)

    def _alert(self, rule: Rule, rec: dict, matched: list[str], detail: str = "") -> Alert:
        return Alert(rule.id, rule.title, rule.severity, rule.mitre_tactic, rule.mitre_technique, rec["eventID"], rec["eventTime"],
                     identity_of(rec), rec["sourceIPAddress"], rule.description, rec["eventName"], matched, detail)

    # -------------------------------------------------------------------------------- evaluation
    def evaluate(self, rec: dict) -> list[Alert]:
        """Evaluate one record (events must arrive in time order). Returns alerts fired by this event."""
        out: list[Alert] = []
        for rule in (*self._by_name.get(rec["eventName"], ()), *self._any):
            if rule.id in self.disabled or not rule.enabled:
                continue
            cond = rule.condition
            if "sequence" in cond:
                a = self._eval_sequence(rule, rec)
            elif "threshold" in cond:
                a = self._eval_threshold(rule, rec)
            else:
                a = self._alert(rule, rec, [rec["eventID"]]) if self._match(cond, rec) else None
            if a:
                out.append(a)
        return out

    def _eval_threshold(self, rule: Rule, rec: dict) -> Optional[Alert]:
        if not self._match(rule.condition, rec):
            return None
        th = rule.condition["threshold"]
        t = _parse_time(rec["eventTime"])
        key = (rule.id, self._group(th, rec))
        dq = self._win[key]
        dq.append((t, rec["eventID"]))
        while dq and dq[0][0] < t - th["window_s"]:
            dq.popleft()
        if len(dq) >= th["count"] and t - self._last_fire.get(key, -1e18) >= th.get("cooldown_s", th["window_s"]):
            self._last_fire[key] = t
            return self._alert(rule, rec, [e for _, e in dq], f"{len(dq)} events in {th['window_s']}s")
        return None

    def _eval_sequence(self, rule: Rule, rec: dict) -> Optional[Alert]:
        sq = rule.condition["sequence"]
        t = _parse_time(rec["eventTime"])
        key = (rule.id, self._group(sq, rec))
        dq = self._prior[key]
        while dq and dq[0][0] < t - sq["window_s"]:
            dq.popleft()
        fired = None
        # the trigger is checked before the event is added to prior so a failure can't trigger itself
        if self._match(rule.condition, rec) and len(dq) >= sq["prior_count"] and t - self._last_fire.get(key, -1e18) >= sq["window_s"]:
            self._last_fire[key] = t
            fired = self._alert(rule, rec, [e for _, e in dq] + [rec["eventID"]], f"{len(dq)} prior events in {sq['window_s']}s")
        if self._match(sq["prior"], rec):
            dq.append((t, rec["eventID"]))
        return fired

    def evaluate_many(self, records: Iterable[dict]) -> list[Alert]:
        out: list[Alert] = []
        for r in records:
            out.extend(self.evaluate(r))
        return out


def _event_names(cond: dict) -> Optional[list[str]]:
    return cond.get("event_name")


def load_rules(rules_dir: str | Path | None = None) -> list[Rule]:
    d = Path(rules_dir) if rules_dir else ROOT / "rules"
    rules: list[Rule] = []
    for f in sorted(d.glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8"))
        for item in (data if isinstance(data, list) else [data]):
            rules.append(Rule.from_dict(item))
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids)), "duplicate rule ids"
    return rules
