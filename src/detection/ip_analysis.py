"""IP / access-pattern layer: impossible travel, one IP new for many identities, one identity on many IPs, blocklisted IPs.

Stateful and event-at-a-time (events in time order), like the rules engine, so batch backfill and the live worker share it.
Rows are flat event dicts: event_id, event_time, identity, source_ip. No ground truth is read.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict, deque
from pathlib import Path
from typing import Optional

import pandas as pd

from src.generator import geo

from .features import Baseline
from .rules_engine import Alert

META = {
    "IP001": ("Impossible travel", "HIGH", "Initial Access", "T1078.004",
              "The same identity appeared from two locations too far apart to travel between in the elapsed time."),
    "IP002": ("One IP new to many identities", "MEDIUM", "Initial Access", "T1078.004",
              "An IP address that none of these identities had used before touched several identities (credential stuffing / pivoting)."),
    "IP003": ("Identity active from many IPs", "MEDIUM", "Initial Access", "T1078.004",
              "A single identity was used from an unusually large number of distinct IPs in a short period."),
    "IP004": ("Blocklisted or anonymizing network", "MEDIUM", "Command and Control", "T1090",
              "Traffic came from an IP/ASN on the threat-intel blocklist (Tor exit / anonymizing VPN)."),
}


def _ts(t) -> float:
    return pd.Timestamp(t).timestamp()


def _iso(t) -> str:
    return pd.Timestamp(t).strftime("%Y-%m-%dT%H:%M:%SZ")


class IpAnalyzer:
    def __init__(self, cfg: dict, baseline: Optional[Baseline] = None):
        self.cfg = cfg
        self.known: dict[str, set] = {}
        self.org_known: dict[str, set] = {}
        if baseline is not None:
            for ident, g in baseline.sets["ip"].groupby("identity"):
                self.known[ident] = set(g["value"])
            for t, g in baseline.org_sets["ip"].groupby("identity_type"):
                self.org_known[t] = set(g["value"])
            self.types = baseline.identity_types
        else:
            self.types = {}
        self.blocked_asns = set(cfg.get("blocked_asns", []))
        self.blocked_nets = self._load_nets(cfg.get("blocked_cidr_file"))
        self.last: dict[str, tuple[str, float, str]] = {}            # identity -> (ip, t, event_id)
        self.ip_ids: dict[str, dict[str, float]] = defaultdict(dict)  # ip -> {identity: last t} for identities where ip is NEW
        self.id_ips: dict[str, deque] = defaultdict(deque)           # identity -> deque[(t, ip)]
        self.cool: dict[tuple, float] = {}
        self.block_seen: dict[tuple, float] = {}

    @staticmethod
    def _load_nets(path: Optional[str]) -> list:
        nets = []
        if path and Path(path).exists():
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                line = line.split("#")[0].strip()
                if line:
                    nets.append(ipaddress.ip_network(line, strict=False))
        return nets

    def reset(self) -> None:
        self.last.clear(); self.ip_ids.clear(); self.id_ips.clear(); self.cool.clear(); self.block_seen.clear()

    def _is_new_ip(self, ident: str, ip: str, itype: str) -> bool:
        if ident in self.known:
            return ip not in self.known[ident]
        return ip not in self.org_known.get(itype, set())

    def _cooled(self, key: tuple, t: float, cd: float) -> bool:
        if t - self.cool.get(key, -1e18) < cd:
            return False
        self.cool[key] = t
        return True

    def _alert(self, rid: str, row: dict, detail: str, matched: list[str]) -> Alert:
        title, sev, tactic, tech, desc = META[rid]
        return Alert(rule_id=rid, title=title, severity=sev, mitre_tactic=tactic, mitre_technique=tech, event_id=row["event_id"],
                     event_time=_iso(row["event_time"]), identity=row["identity"], source_ip=row["source_ip"], description=desc,
                     event_name=row.get("event_name", ""), matched_event_ids=matched, detail=detail, source="ip")

    def evaluate(self, row: dict) -> list[Alert]:
        out: list[Alert] = []
        ident, ip, t = row["identity"], row["source_ip"], _ts(row["event_time"])
        itype = row.get("identity_type") or self.types.get(ident, "IAMUser")
        if not ip[0].isdigit():                       # service principal names are not IPs
            return out
        g = geo.lookup(ip)
        c = self.cfg

        # IP001 impossible travel (consecutive events of the same identity)
        prev = self.last.get(ident)
        if prev and prev[0] != ip:
            km = geo.distance_km(prev[0], ip)
            hours = max((t - prev[1]) / 3600.0, 1.0 / 360.0)
            it = c["impossible_travel"]
            if km >= it["min_km"] and km / hours >= it["min_speed_kmh"] and self._cooled(("IP001", ident), t, it["cooldown_s"]):
                out.append(self._alert("IP001", row, f"{km:.0f} km in {hours*60:.1f} min ({km/hours:.0f} km/h) from {geo.lookup(prev[0]).country} to {g.country}",
                                       [prev[2], row["event_id"]]))
        self.last[ident] = (ip, t, row["event_id"])

        # IP002 an IP that is new to several identities
        if self._is_new_ip(ident, ip, itype):
            si = c["shared_ip"]
            d = self.ip_ids[ip]
            d[ident] = t
            for k in [k for k, v in d.items() if v < t - si["window_s"]]:
                del d[k]
            if len(d) >= si["min_identities"] and self._cooled(("IP002", ip), t, si["cooldown_s"]):
                out.append(self._alert("IP002", row, f"{len(d)} identities saw new IP {ip}: {', '.join(sorted(d))}", [row["event_id"]]))

        # IP003 one identity, many IPs
        mi = c["many_ips"]
        dq = self.id_ips[ident]
        dq.append((t, ip))
        while dq and dq[0][0] < t - mi["window_s"]:
            dq.popleft()
        distinct = {i for _, i in dq}
        if len(distinct) >= mi["min_ips"] and self._cooled(("IP003", ident), t, mi["cooldown_s"]):
            out.append(self._alert("IP003", row, f"{len(distinct)} distinct IPs in {mi['window_s']//60} min", [row["event_id"]]))

        # IP004 blocklist (once per identity+ip per hour)
        blocked = g.asn in self.blocked_asns or (self.blocked_nets and any(ipaddress.ip_address(ip) in n for n in self.blocked_nets))
        if blocked and t - self.block_seen.get((ident, ip), -1e18) >= 3600:
            self.block_seen[(ident, ip)] = t
            out.append(self._alert("IP004", row, f"{ip} ({g.org}, {g.asn})", [row["event_id"]]))
        return out

    def evaluate_frame(self, events: pd.DataFrame) -> list[Alert]:
        out: list[Alert] = []
        cols = ["event_id", "event_time", "identity", "identity_type", "source_ip", "event_name"]
        for row in events[cols].itertuples(index=False):
            out.extend(self.evaluate(dict(zip(cols, row))))
        return out
