"""Analyst feedback: marking an alert 'False Positive' creates a suppression entry. Nothing is retrained automatically;
the suppression list simply filters future alerts, and `impact()` shows what it would have removed."""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional

from .rules_engine import Alert


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    identity: str = "*"
    source_ip: str = "*"
    note: str = ""

    def matches(self, a: Alert) -> bool:
        return (self.rule_id == a.rule_id and self.identity in ("*", a.identity) and self.source_ip in ("*", a.source_ip))


class SuppressionList:
    def __init__(self, entries: Optional[list[Suppression]] = None, path: str | Path | None = None):
        self.entries = list(entries or [])
        self.path = Path(path) if path else None
        if self.path and self.path.exists():
            self.entries = [Suppression(**d) for d in json.loads(self.path.read_text(encoding="utf-8"))]

    def add_from_alert(self, a: Alert, scope: str = "identity", note: str = "") -> Suppression:
        """scope: 'identity' (rule+identity), 'ip' (rule+ip) or 'rule' (everyone)."""
        s = Suppression(a.rule_id, a.identity if scope == "identity" else "*", a.source_ip if scope == "ip" else "*", note)
        if s not in self.entries:
            self.entries.append(s)
            self._save()
        return s

    def remove(self, s: Suppression) -> None:
        self.entries = [e for e in self.entries if e != s]
        self._save()

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps([asdict(e) for e in self.entries], indent=1), encoding="utf-8")

    def apply(self, alerts: Iterable[Alert]) -> tuple[list[Alert], list[Alert]]:
        kept, dropped = [], []
        for a in alerts:
            (dropped if any(s.matches(a) for s in self.entries) else kept).append(a)
        return kept, dropped

    def impact(self, alerts: Iterable[Alert]) -> dict:
        """What the current suppression list would have removed from this alert set, by entry."""
        alerts = list(alerts)
        per = {f"{s.rule_id}/{s.identity}/{s.source_ip}": sum(s.matches(a) for a in alerts) for s in self.entries}
        _, dropped = self.apply(alerts)
        return {"alerts_total": len(alerts), "would_suppress": len(dropped), "by_entry": per}
