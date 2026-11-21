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
  management_event BOOLEAN, event_type VARCHAR, bytes_out BIGINT, raw JSON)
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
EVENT_COLS = ["event_id", "event_time", "event_source", "event_name", "aws_region", "source_ip", "user_agent", "identity_type", "identity",
              "principal_id", "identity_arn", "access_key_id", "account_id", "mfa_authenticated", "error_code", "read_only",
              "management_event", "event_type", "bytes_out", "raw"]
LABEL_COLS = ["event_id", "is_malicious", "scenario_id", "injection_id", "technique", "mitre_tactic"]


def connect(path: str | Path, read_only: bool = False) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(str(path), read_only=read_only)
    if not read_only:
        for ddl in (EVENTS_DDL, LABELS_DDL, INJECTIONS_DDL):
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
        "bytes_out": add.get("bytesTransferredOut"), "raw": json.dumps(rec, separators=(",", ":")),
    }


def insert_events(con: duckdb.DuckDBPyConnection, events: Iterable[tuple[dict, Optional[dict]]]) -> int:
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
    con.execute("INSERT INTO labels SELECT * FROM _lb")
    con.unregister("_ev")
    con.unregister("_lb")
    return len(rows)


def insert_injections(con: duckdb.DuckDBPyConnection, injections: list[dict]) -> None:
    if not injections:
        return
    df = pd.DataFrame(injections)
    con.register("_inj", df)
    con.execute("INSERT INTO injections SELECT injection_id, scenario_id, chain_id, start_time, end_time, victim, attacker_ip, n_events, stealth FROM _inj")
    con.unregister("_inj")
