"""DuckDB storage. Labels live in a separate table and detectors must never read it."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

import duckdb
import pandas as pd

EVENTS_DDL = """
CREATE TABLE IF NOT EXISTS events (
  event_id VARCHAR PRIMARY KEY, event_time TIMESTAMP, event_source VARCHAR, event_name VARCHAR, aws_region VARCHAR,
  source_ip VARCHAR, user_agent VARCHAR, identity_type VARCHAR, identity VARCHAR, principal_id VARCHAR, identity_arn VARCHAR,
  access_key_id VARCHAR, account_id VARCHAR, mfa_authenticated BOOLEAN, error_code VARCHAR, read_only BOOLEAN,
  management_event BOOLEAN, event_type VARCHAR, bytes_out BIGINT, console_login VARCHAR, raw JSON)
"""
LABELS_DDL = """
CREATE TABLE IF NOT EXISTS labels (
  event_id VARCHAR PRIMARY KEY, is_malicious BOOLEAN, scenario_id VARCHAR, injection_id VARCHAR, technique VARCHAR, mitre_tactic VARCHAR)
"""
INJECTIONS_DDL = """
CREATE TABLE IF NOT EXISTS injections (
  injection_id VARCHAR PRIMARY KEY, scenario_id VARCHAR, chain_id VARCHAR, start_time TIMESTAMP, end_time TIMESTAMP,
  victim VARCHAR, attacker_ip VARCHAR, n_events INTEGER, stealth DOUBLE)
"""
ALERTS_DDL = """
CREATE TABLE IF NOT EXISTS alerts (
  alert_id VARCHAR PRIMARY KEY, rule_id VARCHAR, title VARCHAR, severity VARCHAR, risk DOUBLE, source VARCHAR, event_id VARCHAR,
  event_time TIMESTAMP, detected_at TIMESTAMP, ingested_wall TIMESTAMP, identity VARCHAR, source_ip VARCHAR, mitre_tactic VARCHAR,
  mitre_technique VARCHAR, description VARCHAR, detail VARCHAR, event_name VARCHAR, matched_event_ids VARCHAR, reasons VARCHAR,
  incident_id VARCHAR, status VARCHAR)
"""
INCIDENTS_DDL = """
CREATE TABLE IF NOT EXISTS incidents (
  incident_id VARCHAR PRIMARY KEY, title VARCHAR, severity VARCHAR, risk_score DOUBLE, first_seen TIMESTAMP, last_seen TIMESTAMP,
  identities VARCHAR, ips VARCHAR, tactics VARCHAR, techniques VARCHAR, alert_ids VARCHAR, sources VARCHAR, n_alerts INTEGER,
  status VARCHAR, notes VARCHAR)
"""
TTD_DDL = """
CREATE TABLE IF NOT EXISTS ttd (
  injection_id VARCHAR PRIMARY KEY, scenario_id VARCHAR, chain_id VARCHAR, injected_sim TIMESTAMP, injected_wall TIMESTAMP,
  first_alert_id VARCHAR, detected_by VARCHAR, first_alert_sim TIMESTAMP, ttd_sim_s DOUBLE, ttd_wall_s DOUBLE, pipeline_latency_ms DOUBLE)
"""
EVENT_COLS = ["event_id", "event_time", "event_source", "event_name", "aws_region", "source_ip", "user_agent", "identity_type", "identity",
              "principal_id", "identity_arn", "access_key_id", "account_id", "mfa_authenticated", "error_code", "read_only",
              "management_event", "event_type", "bytes_out", "console_login", "raw"]
LABEL_COLS = ["event_id", "is_malicious", "scenario_id", "injection_id", "technique", "mitre_tactic"]


def connect(path: str | Path, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(path), read_only=read_only)
    if not read_only:
        for ddl in (EVENTS_DDL, LABELS_DDL, INJECTIONS_DDL, ALERTS_DDL, INCIDENTS_DDL, TTD_DDL):
            con.execute(ddl)
    return con


def flatten(rec: dict) -> dict:
    ui = rec["userIdentity"]
    sc = ui.get("sessionContext") or {}
    mfa = (sc.get("attributes") or {}).get("mfaAuthenticated")
    if ui["type"] == "AssumedRole":
        ident = sc["sessionIssuer"]["userName"]
    else:
        ident = ui.get("userName") or ui["arn"]
    add = rec.get("additionalEventData") or {}
    return {
        "event_id": rec["eventID"], "event_time": rec["eventTime"].replace("T", " ").rstrip("Z"), "event_source": rec["eventSource"],
        "event_name": rec["eventName"], "aws_region": rec["awsRegion"], "source_ip": rec["sourceIPAddress"], "user_agent": rec["userAgent"],
        "identity_type": ui["type"], "identity": ident, "principal_id": ui["principalId"], "identity_arn": ui["arn"],
        "access_key_id": ui.get("accessKeyId") or None, "account_id": ui["accountId"],
        "mfa_authenticated": None if mfa is None else mfa == "true", "error_code": rec.get("errorCode"),
        "read_only": rec["readOnly"], "management_event": rec["managementEvent"], "event_type": rec["eventType"],
        "bytes_out": add.get("bytesTransferredOut"),
        "console_login": (rec.get("responseElements") or {}).get("ConsoleLogin") if rec["eventName"] == "ConsoleLogin" else None, "raw": json.dumps(rec, separators=(",", ":")),
    }


def insert_events(con: duckdb.DuckDBPyConnection, events: Iterable[tuple[dict, Optional[dict]]], labels_mode: str = "all") -> int:
    """labels_mode: 'all' = one labels row per event (batch datasets); 'none' = events only (live mode writes labels separately)."""
    rows, labels = [], []
    for rec, lab in events:
        rows.append(flatten(rec))
        l = lab or {"is_malicious": False, "scenario_id": None, "injection_id": None, "technique": None, "mitre_tactic": None}
        labels.append({"event_id": rec["eventID"], **l})
    if not rows:
        return 0
    ev = pd.DataFrame(rows, columns=EVENT_COLS)
    ev["event_time"] = pd.to_datetime(ev["event_time"])
    lb = pd.DataFrame(labels, columns=LABEL_COLS)
    con.register("_ev", ev)
    con.register("_lb", lb)
    con.execute("INSERT INTO events SELECT * FROM _ev")
    if labels_mode == "all":
        con.execute("INSERT INTO labels SELECT * FROM _lb")
    con.unregister("_ev")
    con.unregister("_lb")
    return len(rows)


def insert_flat(con: duckdb.DuckDBPyConnection, rows: list[dict]) -> int:
    """Insert already-flattened event rows (live worker). No label rows are written here."""
    if not rows:
        return 0
    ev = pd.DataFrame(rows, columns=EVENT_COLS)
    ev["event_time"] = pd.to_datetime(ev["event_time"])
    con.register("_evf", ev)
    con.execute("INSERT INTO events SELECT * FROM _evf")
    con.unregister("_evf")
    return len(rows)


def insert_injections(con: duckdb.DuckDBPyConnection, injections: list[dict]) -> None:
    if not injections:
        return
    df = pd.DataFrame(injections)
    con.register("_inj", df)
    con.execute("INSERT INTO injections SELECT injection_id, scenario_id, chain_id, start_time, end_time, victim, attacker_ip, n_events, stealth FROM _inj")
    con.unregister("_inj")


def insert_labels(con: duckdb.DuckDBPyConnection, rows: list[dict]) -> None:
    if not rows:
        return
    df = pd.DataFrame(rows, columns=LABEL_COLS)
    con.register("_lb2", df)
    con.execute("INSERT OR REPLACE INTO labels SELECT * FROM _lb2")
    con.unregister("_lb2")


def _ts(s: str) -> str:
    return s.replace("T", " ").rstrip("Z")


def upsert_alerts(con: duckdb.DuckDBPyConnection, alerts: list, incident_of: dict, wall_iso: str, status_of: Optional[dict] = None) -> None:
    if not alerts:
        return
    rows = []
    for a in alerts:
        rows.append({"alert_id": a.alert_id, "rule_id": a.rule_id, "title": a.title, "severity": a.severity, "risk": a.risk, "source": a.source,
                     "event_id": a.event_id, "event_time": _ts(a.event_time), "detected_at": _ts(a.detected_at), "ingested_wall": wall_iso,
                     "identity": a.identity, "source_ip": a.source_ip, "mitre_tactic": a.mitre_tactic, "mitre_technique": a.mitre_technique,
                     "description": a.description, "detail": a.detail, "event_name": a.event_name,
                     "matched_event_ids": json.dumps(a.matched_event_ids[:2000]), "reasons": json.dumps(a.reasons),
                     "incident_id": incident_of.get(a.alert_id), "status": (status_of or {}).get(a.alert_id, "Open")})
    df = pd.DataFrame(rows)
    for c in ("event_time", "detected_at", "ingested_wall"):
        df[c] = pd.to_datetime(df[c])
    con.register("_al", df)
    con.execute("INSERT OR REPLACE INTO alerts SELECT * FROM _al")
    con.unregister("_al")


def upsert_incidents(con: duckdb.DuckDBPyConnection, incidents: list) -> None:
    """Writes incidents, preserving analyst status/notes of any earlier incident that shares alerts (merges keep their status)."""
    if not incidents:
        return
    old = con.execute("SELECT incident_id, status, notes, alert_ids FROM incidents").fetchall()
    old_alerts = [(i, st, nt, set(json.loads(al))) for i, st, nt, al in old]
    rows = []
    for inc in incidents:
        mine = set(inc.alert_ids)
        status, notes = inc.status, ""
        for oid, st, nt, oal in old_alerts:
            if oal & mine:
                if st != "Open":
                    status = st
                if nt:
                    notes = nt
        rows.append({"incident_id": inc.incident_id, "title": inc.title, "severity": inc.severity, "risk_score": inc.risk_score,
                     "first_seen": _ts(inc.first_seen), "last_seen": _ts(inc.last_seen), "identities": json.dumps(inc.identities),
                     "ips": json.dumps(inc.ips), "tactics": json.dumps(inc.tactics), "techniques": json.dumps(inc.techniques),
                     "alert_ids": json.dumps(inc.alert_ids), "sources": json.dumps(inc.sources), "n_alerts": inc.n_alerts,
                     "status": status, "notes": notes})
    df = pd.DataFrame(rows)
    df["first_seen"], df["last_seen"] = pd.to_datetime(df["first_seen"]), pd.to_datetime(df["last_seen"])
    new_ids = set(df["incident_id"])
    all_new_alerts = {a for inc in incidents for a in inc.alert_ids}
    merged_away = [oid for oid, _, _, oal in old_alerts if oid not in new_ids and oal & all_new_alerts]     # superseded by a merge
    for oid in merged_away:
        con.execute("DELETE FROM incidents WHERE incident_id = ?", [oid])
    con.register("_inc", df)
    con.execute("INSERT OR REPLACE INTO incidents SELECT * FROM _inc")
    con.unregister("_inc")
