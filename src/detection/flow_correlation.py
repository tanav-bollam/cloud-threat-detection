"""Correlate VPC Flow Logs with CloudTrail (stretch goal). Operates on a DuckDB connection that has `events` and `flows` tables.

  FL001  an instance launched by identity X makes sustained outbound connections to cryptocurrency-mining (stratum) ports   (T1496)
  FL002  a DeleteFlowLogs event is followed by SILENCE: the flow log it deleted stops producing records while other flow logs keep going   (T1685.002)
  FL003  a security group was opened to the world on a port, and the internet then actually reached that port                    (T1133)

Why correlate: CloudTrail says what an identity DID (launched instances, deleted a flow log, opened a port); flow logs say what the network then
saw. A launch plus mining traffic is far stronger than either alone, a deleted flow log is confirmed when records really stop, and an opened port
is more urgent when it is being probed. Each alert points back at the CloudTrail event it corroborates, so it joins the same incident.
Port-based mining detection is a heuristic (real pools use many ports; real detection adds threat-intel IPs and DNS); it is meant to show the
correlation, not to be a complete miner detector.
"""
from __future__ import annotations

import ipaddress
import json

import pandas as pd

from src.detection.rule_checks import open_to_world
from src.detection.rules_engine import Alert

MINING_PORTS = (3333, 4444, 5555, 7777, 14444, 14433)
META = {
    "FL001": ("Outbound connections to cryptocurrency-mining pool ports", "HIGH", "Impact", "T1496",
              "An instance made repeated outbound connections to ports used by cryptocurrency-mining pools (stratum). Correlated with the CloudTrail launch of the instance."),
    "FL002": ("VPC flow logging stopped: records ceased after DeleteFlowLogs", "HIGH", "Defense Impairment", "T1685.002",
              "A flow log was deleted and no further records arrived for it while other flow logs kept reporting, confirming that network visibility was lost."),
    "FL003": ("Internet probed a port that was just opened to the world", "MEDIUM", "Initial Access", "T1133",
              "A security group was opened to 0.0.0.0/0 on a port and accepted inbound connections from several internet hosts shortly afterwards."),
}


def _iso(t) -> str:
    return pd.Timestamp(t).strftime("%Y-%m-%dT%H:%M:%SZ")


def _alert(rid: str, event: dict, detected_at, detail: str, flow_time=None) -> Alert:
    title, sev, tactic, tech, desc = META[rid]
    return Alert(rule_id=rid, title=title, severity=sev, mitre_tactic=tactic, mitre_technique=tech, event_id=event["event_id"],
                 event_time=_iso(flow_time if flow_time is not None else event["event_time"]), identity=event["identity"], source_ip=event.get("source_ip") or "",
                 description=desc, event_name=event.get("event_name", ""), matched_event_ids=[event["event_id"]], detail=detail, detected_at=_iso(detected_at), source="flow")


def launch_registry(con) -> dict[str, dict]:
    """instanceId -> the successful RunInstances event that created it."""
    reg: dict[str, dict] = {}
    for eid, t, ident, region, ip, raw in con.execute(
            "SELECT event_id, event_time, identity, aws_region, source_ip, raw FROM events WHERE event_name = 'RunInstances' AND error_code IS NULL ORDER BY event_time").fetchall():
        for it in ((json.loads(raw).get("responseElements") or {}).get("instancesSet") or {}).get("items", []):
            reg[it["instanceId"]] = {"event_id": eid, "event_time": t, "identity": ident, "aws_region": region, "source_ip": ip, "event_name": "RunInstances"}
    return reg


def mining_alerts(con, window_min: int = 30, min_flows: int = 3, cooldown_h: int = 6) -> list[Alert]:
    reg = launch_registry(con)
    ports = ",".join(str(p) for p in MINING_PORTS)
    df = con.execute(f"SELECT instance_id, start_time, dstaddr, dstport FROM flows WHERE flow_direction = 'egress' AND action = 'ACCEPT' AND dstport IN ({ports}) "
                     "ORDER BY instance_id, start_time").fetchdf()
    out: list[Alert] = []
    for iid, g in df.groupby("instance_id"):
        times = pd.to_datetime(g["start_time"]).tolist()
        last_alert = None
        for i in range(min_flows - 1, len(times)):
            if (times[i] - times[i - min_flows + 1]).total_seconds() <= window_min * 60 and (last_alert is None or (times[i] - last_alert).total_seconds() > cooldown_h * 3600):
                last_alert = times[i]
                launch = reg.get(iid) or {"event_id": f"flow:{iid}", "event_time": times[i], "identity": iid, "source_ip": "", "event_name": ""}
                dst = g.iloc[i]
                after = (times[i] - pd.Timestamp(launch["event_time"])).total_seconds() / 60 if iid in reg else None
                detail = (f"{min_flows}+ flows to {dst['dstaddr']}:{int(dst['dstport'])} within {window_min} min from {iid}"
                          + (f", {after:.0f} min after {launch['identity']} launched it" if after is not None else " (launcher unknown: instance not in the CloudTrail window)"))
                out.append(_alert("FL001", launch, times[i], detail, flow_time=times[i]))
    return out


def flowlog_silence_alerts(con, silence_min: int = 30, min_prior_flows: int = 6) -> list[Alert]:
    out: list[Alert] = []
    last_flow = con.execute("SELECT max(start_time) FROM flows").fetchone()[0]
    if last_flow is None:
        return out
    for eid, t, ident, ip, raw in con.execute("SELECT event_id, event_time, identity, source_ip, raw FROM events WHERE event_name = 'DeleteFlowLogs' AND error_code IS NULL").fetchall():
        fid = (((json.loads(raw).get("requestParameters") or {}).get("DeleteFlowLogsRequest") or {}).get("FlowLogId") or {}).get("content")
        if not fid:
            continue
        t = pd.Timestamp(t)
        prior = con.execute("SELECT count(*) FROM flows WHERE flow_log_id = ? AND start_time >= ? AND start_time < ?", [fid, t - pd.Timedelta(hours=2), t]).fetchone()[0]
        after = con.execute("SELECT count(*) FROM flows WHERE flow_log_id = ? AND start_time >= ? AND start_time < ?", [fid, t, t + pd.Timedelta(minutes=silence_min)]).fetchone()[0]
        others = con.execute("SELECT count(*) FROM flows WHERE flow_log_id <> ? AND start_time >= ? AND start_time < ?", [fid, t, t + pd.Timedelta(minutes=silence_min)]).fetchone()[0]
        if prior >= min_prior_flows and after == 0 and others > 0 and pd.Timestamp(last_flow) >= t + pd.Timedelta(minutes=silence_min):
            out.append(_alert("FL002", {"event_id": eid, "event_time": t, "identity": ident, "source_ip": ip, "event_name": "DeleteFlowLogs"}, t + pd.Timedelta(minutes=silence_min),
                              f"{fid} produced {prior} records in the 2 h before deletion and none in the {silence_min} min after, while other flow logs kept reporting"))
    return out


def exposure_alerts(con, horizon_h: int = 3, min_sources: int = 2) -> list[Alert]:
    out: list[Alert] = []
    for eid, t, ident, ip, region, raw in con.execute("SELECT event_id, event_time, identity, source_ip, aws_region, raw FROM events WHERE event_name = 'AuthorizeSecurityGroupIngress' "
                                                       "AND error_code IS NULL ORDER BY event_time").fetchall():
        rec = json.loads(raw)
        if not open_to_world(rec, {}):
            continue
        rp = rec.get("requestParameters") or {}
        port = rp.get("fromPort") if rp.get("fromPort") is not None else next((p.get("fromPort") for p in ((rp.get("ipPermissions") or {}).get("items") or [])), None)
        if port is None:
            continue
        t = pd.Timestamp(t)
        rows = con.execute("SELECT start_time, srcaddr FROM flows WHERE region = ? AND flow_direction = 'ingress' AND action = 'ACCEPT' AND dstport = ? AND start_time >= ? AND start_time < ? "
                           "ORDER BY start_time", [region, int(port), t, t + pd.Timedelta(hours=horizon_h)]).fetchall()
        seen, hit_at = set(), None
        for st, src in rows:
            try:
                if ipaddress.ip_address(src).is_private:
                    continue
            except ValueError:
                continue
            seen.add(src)
            if len(seen) >= min_sources:
                hit_at = pd.Timestamp(st)
                break
        if hit_at is not None:
            out.append(_alert("FL003", {"event_id": eid, "event_time": t, "identity": ident, "source_ip": ip, "event_name": "AuthorizeSecurityGroupIngress"}, hit_at,
                              f"port {int(port)} opened to the world in {region}; {len(seen)}+ internet hosts connected within {(hit_at - t).total_seconds() / 60:.0f} min", flow_time=hit_at))
    return out


def flow_alerts(con) -> list[Alert]:
    """All flow-correlation alerts for the dataset in `con`."""
    n = con.execute("SELECT count(*) FROM flows").fetchone()[0]
    if not n:
        return []
    return mining_alerts(con) + flowlog_silence_alerts(con) + exposure_alerts(con)
