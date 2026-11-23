"""Dashboard data access (pure functions over a DuckDB cursor, no Streamlit) so everything here is unit-testable.

None of these queries touch the ground-truth tables (labels / injections / ttd) except the clearly separated `simulator_*` helpers."""
from __future__ import annotations

import json
import re
from typing import Optional

import pandas as pd

from src.generator import geo

SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
STATUSES = ["Open", "Investigating", "Resolved", "False Positive"]


def df(cur, sql: str, params: Optional[list] = None) -> pd.DataFrame:
    return cur.execute(sql, params or []).fetchdf()


def sim_bounds(cur) -> tuple[Optional[pd.Timestamp], Optional[pd.Timestamp]]:
    lo, hi = cur.execute("SELECT min(event_time), max(event_time) FROM events").fetchone()
    return (pd.Timestamp(lo) if lo else None, pd.Timestamp(hi) if hi else None)


# ------------------------------------------------------------------------------------------------ overview
def kpis(cur) -> dict:
    _, now = sim_bounds(cur)
    if now is None:
        return {"events_total": 0, "events_per_min": 0.0, "identities": 0, "open_by_sev": {s: 0 for s in SEV_ORDER}, "open_incidents": 0, "alerts": 0}
    r = cur.execute("SELECT count(*) FROM events WHERE event_time > ?", [now - pd.Timedelta(minutes=15)]).fetchone()[0]
    sev = dict(cur.execute("SELECT severity, count(*) FROM incidents WHERE status IN ('Open','Investigating') GROUP BY 1").fetchall())
    return {"events_total": cur.execute("SELECT count(*) FROM events").fetchone()[0], "events_per_min": round(r / 15, 1),
            "identities": cur.execute("SELECT count(DISTINCT identity) FROM events").fetchone()[0],
            "open_by_sev": {s: int(sev.get(s, 0)) for s in SEV_ORDER}, "open_incidents": int(sum(sev.values())),
            "alerts": cur.execute("SELECT count(*) FROM alerts").fetchone()[0]}


def events_over_time(cur, hours: float = 6, bucket_min: int = 5) -> pd.DataFrame:
    _, now = sim_bounds(cur)
    if now is None:
        return pd.DataFrame(columns=["t", "events"])
    return df(cur, f"SELECT time_bucket(INTERVAL '{bucket_min} minutes', event_time) AS t, count(*) AS events FROM events "
                   f"WHERE event_time > ? GROUP BY 1 ORDER BY 1", [now - pd.Timedelta(hours=hours)])


def alerts_over_time(cur, hours: float = 6) -> pd.DataFrame:
    _, now = sim_bounds(cur)
    if now is None:
        return pd.DataFrame(columns=["detected_at", "severity", "title", "identity"])
    return df(cur, "SELECT detected_at, severity, title, identity, risk FROM alerts WHERE detected_at > ? ORDER BY detected_at",
              [now - pd.Timedelta(hours=hours)])


def top_risky_identities(cur, n: int = 8) -> pd.DataFrame:
    return df(cur, """
        SELECT identity, count(*) AS alerts, max(risk) AS max_risk,
               max(CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 ELSE 1 END) AS sev_rank
        FROM alerts WHERE status <> 'False Positive' GROUP BY identity ORDER BY max_risk DESC, alerts DESC LIMIT ?""", [n])


def top_source_ips(cur, n: int = 10, hours: float = 6) -> pd.DataFrame:
    _, now = sim_bounds(cur)
    if now is None:
        return pd.DataFrame(columns=["source_ip", "country", "network", "kind", "events", "identities", "alerts"])
    d = df(cur, """
        SELECT e.source_ip, count(*) AS events, count(DISTINCT e.identity) AS identities
        FROM events e WHERE e.event_time > ? AND regexp_matches(e.source_ip, '^[0-9]') GROUP BY 1""", [now - pd.Timedelta(hours=hours)])
    a = df(cur, "SELECT source_ip, count(*) AS alerts FROM alerts GROUP BY 1")
    d = d.merge(a, on="source_ip", how="left").fillna({"alerts": 0})
    d["alerts"] = d["alerts"].astype(int)
    g = d["source_ip"].map(geo.lookup)
    d["country"] = g.map(lambda x: x.country)
    d["network"] = g.map(lambda x: x.org)
    d["kind"] = g.map(lambda x: x.kind)
    return d.sort_values(["alerts", "events"], ascending=False).head(n).reset_index(drop=True)


def country_counts(cur, hours: float = 6) -> pd.DataFrame:
    d = top_source_ips(cur, n=10_000, hours=hours)
    if d.empty:
        return pd.DataFrame(columns=["country", "events", "alerts"])
    return d.groupby("country").agg(events=("events", "sum"), alerts=("alerts", "sum")).reset_index().sort_values("events", ascending=False)


def latest_alerts(cur, n: int = 12) -> pd.DataFrame:
    return df(cur, "SELECT alert_id, detected_at, severity, source, title, identity, source_ip, incident_id, status FROM alerts "
                   "ORDER BY ingested_wall DESC, detected_at DESC LIMIT ?", [n])


# ------------------------------------------------------------------------------------------------ incidents
def incident_list(cur) -> pd.DataFrame:
    d = df(cur, "SELECT * FROM incidents ORDER BY first_seen DESC")
    for c in ("identities", "ips", "tactics", "techniques", "alert_ids", "sources"):
        d[c] = d[c].map(lambda s: json.loads(s) if isinstance(s, str) else [])
    d["rank"] = d["severity"].map(SEV_ORDER)
    return d


def get_incident(cur, incident_id: str) -> Optional[dict]:
    r = df(cur, "SELECT * FROM incidents WHERE incident_id = ?", [incident_id])
    if r.empty:
        return None
    d = r.iloc[0].to_dict()
    for c in ("identities", "ips", "tactics", "techniques", "alert_ids", "sources"):
        d[c] = json.loads(d[c]) if isinstance(d[c], str) else []
    return d


def incident_alerts(cur, incident_id: str) -> pd.DataFrame:
    d = df(cur, "SELECT * FROM alerts WHERE incident_id = ? ORDER BY detected_at", [incident_id])
    d["reasons"] = d["reasons"].map(lambda s: json.loads(s) if isinstance(s, str) and s else [])
    d["matched_event_ids"] = d["matched_event_ids"].map(lambda s: json.loads(s) if isinstance(s, str) and s else [])
    return d


def incident_timeline(cur, inc: dict, alerts: pd.DataFrame, known_ips: set, pad_min: int = 30, max_points: int = 5000) -> pd.DataFrame:
    """Events of the incident's identities (and of its non-org-known IPs) around its window, tagged with how they were flagged."""
    lo = pd.Timestamp(inc["first_seen"]) - pd.Timedelta(minutes=pad_min)
    hi = pd.Timestamp(inc["last_seen"]) + pd.Timedelta(minutes=pad_min)
    ips = [i for i in inc["ips"] if i not in known_ips and i[:1].isdigit()]
    idents = inc["identities"]
    cond = "identity IN (SELECT unnest(?::VARCHAR[]))"
    params: list = [idents]
    if ips:
        cond = f"({cond} OR source_ip IN (SELECT unnest(?::VARCHAR[])))"
        params.append(ips)
    ev = df(cur, f"SELECT event_id, event_time, identity, source_ip, event_name, event_source, aws_region, error_code, user_agent, identity_type "
                 f"FROM events WHERE {cond} AND event_time BETWEEN ? AND ? ORDER BY event_time", params + [lo, hi])
    precise: dict[str, int] = {}
    window_only: set = set()
    for a in alerts.itertuples():
        ids = set(a.matched_event_ids) | {a.event_id}
        if a.source == "anomaly":
            window_only |= ids
        else:
            for e in ids:
                precise[e] = max(precise.get(e, 0), SEV_ORDER[a.severity])
    inv = {v: k for k, v in SEV_ORDER.items()}
    ev["flag"] = [inv[precise[e]] if e in precise else ("ANOMALOUS WINDOW" if e in window_only else "CONTEXT") for e in ev["event_id"]]
    if len(ev) > max_points:
        keep = ev[ev["flag"] != "CONTEXT"]
        ctx = ev[ev["flag"] == "CONTEXT"].sample(max(0, max_points - len(keep)), random_state=0)
        ev = pd.concat([keep, ctx]).sort_values("event_time")
    return ev.reset_index(drop=True)


def raw_event(cur, event_id: str) -> Optional[dict]:
    r = cur.execute("SELECT raw FROM events WHERE event_id = ?", [event_id]).fetchone()
    return json.loads(r[0]) if r else None


def raw_events(cur, event_ids: list[str], limit: int = 500) -> list[dict]:
    if not event_ids:
        return []
    rows = cur.execute("SELECT raw FROM events WHERE event_id IN (SELECT unnest(?::VARCHAR[])) LIMIT ?", [event_ids[:limit], limit]).fetchall()
    return [json.loads(r[0]) for r in rows]


# ------------------------------------------------------------------------------------------------ forensics
ANALYST_TABLES = {"events", "alerts", "incidents"}            # the only tables the analyst SQL box may read (ground truth is not among them)
_SAFE_TABLE_FUNCS = {"unnest", "generate_series", "range"}
# functions that read files, the environment, settings or system catalogs, or run nested SQL
_DENY_FUNC = re.compile(r"^(read_|write_|copy_|parquet_|sniff_|duckdb_|pragma_|which_|load_|install_|iceberg_|delta_|query$|query_table$|glob$|getenv$|"
                        r"current_setting$|current_query$|list_files|getvariable|.*_scan$)", re.I)
_MAX_SQL_CHARS = 4000


def _walk(node, tables, funcs, table_funcs, ctes):
    if isinstance(node, dict):
        t = node.get("type")
        if t == "BASE_TABLE":
            tables.append((node.get("catalog_name") or "", node.get("schema_name") or "", (node.get("table_name") or "")))
        elif t == "TABLE_FUNCTION":
            table_funcs.append(((node.get("function") or {}).get("function_name") or "").lower())
        elif t == "FUNCTION":
            funcs.append((node.get("function_name") or "").lower())
        if "cte_map" in node and isinstance(node["cte_map"], dict):
            for item in node["cte_map"].get("map", []):
                ctes.add(str(item.get("key", "")).lower())
        for v in node.values():
            _walk(v, tables, funcs, table_funcs, ctes)
    elif isinstance(node, list):
        for v in node:
            _walk(v, tables, funcs, table_funcs, ctes)


def is_safe_select(sql: str) -> tuple[bool, str]:
    """Allowlist check built on DuckDB's own parser (a keyword filter is not enough: read_text('/etc/passwd'), FROM 'file.csv',
    glob(), getenv() all look like harmless SELECTs). Only a single SELECT over events/alerts/incidents (and its own CTEs) is allowed,
    with no file, environment, settings or system-catalog access."""
    import duckdb
    s = sql.strip().rstrip(";").strip()
    if not s:
        return False, "Empty query."
    if len(s) > _MAX_SQL_CHARS:
        return False, f"Query is longer than {_MAX_SQL_CHARS} characters."
    try:
        if len(duckdb.extract_statements(s)) != 1:
            return False, "Only one statement is allowed."
        raw = duckdb.connect(":memory:").execute("SELECT json_serialize_sql(?::VARCHAR)", [s]).fetchone()[0]
    except Exception as ex:   # noqa: BLE001 - any parse failure means "not a plain SELECT"
        return False, f"Could not parse a single SELECT statement: {str(ex)[:120]}"
    tree = json.loads(raw)
    if tree.get("error"):
        return False, "Only SELECT queries are allowed (read-only)."
    tables, funcs, table_funcs, ctes = [], [], [], set()
    _walk(tree, tables, funcs, table_funcs, ctes)
    for cat, schema, name in tables:
        if cat or schema not in ("", "main"):
            return False, "Only the events, alerts and incidents tables are available."
        n = name.lower()
        if n not in ANALYST_TABLES and n not in ctes:
            if n in ("labels", "injections", "ttd"):
                return False, "Ground-truth tables (labels, injections, ttd) are not available to analysts."
            return False, f"Table or file '{name}' is not available. Use events, alerts or incidents."
    for f in table_funcs:
        if f not in _SAFE_TABLE_FUNCS:
            return False, f"Table function {f}() is not allowed."
    for f in funcs + table_funcs:
        if _DENY_FUNC.match(f):
            return False, f"Function {f}() is not allowed (it reads files, settings or system state)."
    return True, ""


def run_readonly(cur, sql: str, row_limit: int = 5000, timeout_s: float = 15.0) -> pd.DataFrame:
    """Run an already-validated analyst query on its own cursor with a row cap and a wall-clock timeout (a cross join must not freeze the app)."""
    import threading
    timer = threading.Timer(timeout_s, cur.interrupt)
    timer.start()
    try:
        return cur.execute(f"SELECT * FROM ({sql.strip().rstrip(';')}) AS q LIMIT {int(row_limit)}").fetchdf()
    except Exception as ex:   # noqa: BLE001
        if "INTERRUPT" in str(ex).upper():
            raise TimeoutError(f"Query stopped after {timeout_s:.0f} s. Add filters or a LIMIT.") from ex
        raise
    finally:
        timer.cancel()


def build_forensics_sql(f: dict, limit: int = 5000) -> tuple[str, list]:
    """f: identity, access_key, ip, event_name, region, errors_only, t_from, t_to (all optional). Substring match for text fields."""
    where, params = [], []
    for key, col in (("identity", "identity"), ("access_key", "access_key_id"), ("ip", "source_ip"), ("event_name", "event_name"), ("region", "aws_region")):
        v = (f.get(key) or "").strip()
        if v:
            where.append(f"{col} ILIKE ?")
            params.append(f"%{v}%")
    if f.get("errors_only"):
        where.append("error_code IS NOT NULL")
    if f.get("t_from") is not None:
        where.append("event_time >= ?"); params.append(f["t_from"])
    if f.get("t_to") is not None:
        where.append("event_time <= ?"); params.append(f["t_to"])
    sql = ("SELECT event_time, identity, source_ip, event_name, aws_region, error_code, access_key_id, user_agent, event_id FROM events"
           + (" WHERE " + " AND ".join(where) if where else "") + f" ORDER BY event_time DESC LIMIT {int(limit)}")
    return sql, params


def pivot_ip(cur, ip: str) -> dict:
    g = geo.lookup(ip)
    ids = df(cur, "SELECT identity, count(*) AS events, min(event_time) AS first_seen, max(event_time) AS last_seen FROM events WHERE source_ip = ? GROUP BY 1 ORDER BY 2 DESC", [ip])
    names = df(cur, "SELECT event_name, count(*) AS events FROM events WHERE source_ip = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 15", [ip])
    al = df(cur, "SELECT detected_at, severity, title, identity FROM alerts WHERE source_ip = ? ORDER BY detected_at DESC LIMIT 20", [ip])
    return {"geo": g, "identities": ids, "events": names, "alerts": al}


def pivot_identity(cur, identity: str) -> dict:
    ips = df(cur, "SELECT source_ip, count(*) AS events, min(event_time) AS first_seen, max(event_time) AS last_seen FROM events WHERE identity = ? GROUP BY 1 ORDER BY 2 DESC", [identity])
    if not ips.empty:
        g = ips["source_ip"].map(geo.lookup)
        ips["country"], ips["network"] = g.map(lambda x: x.country), g.map(lambda x: x.org)
    keys = df(cur, "SELECT access_key_id, count(*) AS events FROM events WHERE identity = ? AND access_key_id IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 10", [identity])
    names = df(cur, "SELECT event_name, count(*) AS events FROM events WHERE identity = ? GROUP BY 1 ORDER BY 2 DESC LIMIT 15", [identity])
    return {"ips": ips, "keys": keys, "events": names}


# ------------------------------------------------------------------------------------------------ simulator (ground truth view)
def simulator_injections(cur) -> pd.DataFrame:
    """Injections joined with how/when they were detected. The ONLY place the dashboard reads ground truth."""
    return df(cur, """
        SELECT i.injection_id, i.scenario_id, i.chain_id, i.victim, i.attacker_ip, i.n_events, i.start_time,
               t.detected_by, t.ttd_sim_s, t.ttd_wall_s, t.pipeline_latency_ms, t.first_alert_id
        FROM injections i LEFT JOIN ttd t USING (injection_id) ORDER BY i.start_time DESC""")
