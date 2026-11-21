"""Behavioural features: identity x 15-minute sliding windows (5-minute step), relative to each identity's own baseline.

Inputs are flat event rows (see storage.EVENT_COLS minus `raw`). Nothing here reads ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

import duckdb
import numpy as np
import pandas as pd

from src.generator import geo

WINDOW_MIN, STEP_MIN = 15, 5
N_SHIFTS = WINDOW_MIN // STEP_MIN

# API semantics only (nothing scenario-specific): IAM writes, logging/detection changes, sharing/permission changes, compute launch.
HIGH_RISK = [
    "CreateUser", "CreateAccessKey", "DeleteAccessKey", "AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
    "CreateLoginProfile", "UpdateAssumeRolePolicy", "CreateRole", "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
    "DeleteDetector", "UpdateDetector", "DeleteFlowLogs", "PutBucketPolicy", "PutBucketAcl", "ModifySnapshotAttribute",
    "AuthorizeSecurityGroupIngress", "CreateFunction20150331", "RunInstances", "RequestSpotInstances", "DeleteBucket", "TerminateInstances",
]
ERRORS = ["AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation", "AccessDeniedException"]

FEATURES = ["log_n", "n_distinct_names", "n_services", "read_ratio", "err_ratio", "high_risk_share", "recon_ratio",
            "new_ip", "new_asn", "new_country", "new_ua", "new_region", "hour_rarity", "is_weekend",
            "log_max_dist", "log_max_speed", "bytes_z", "volume_z", "log_n_ips", "login_fail", "type_user", "type_role", "type_root"]

_ATTRS = {"ip": "source_ip", "asn": "asn", "country": "country", "ua": "user_agent", "region": "aws_region"}
_PUBLIC_COLS = ["event_id", "event_time", "event_source", "event_name", "aws_region", "source_ip", "user_agent", "identity_type", "identity",
                "access_key_id", "error_code", "read_only", "management_event", "bytes_out", "console_login"]


def ip_geo(ips) -> pd.DataFrame:
    rows = []
    for ip in pd.unique(pd.Series(list(ips))):
        g = geo.lookup(ip)
        rows.append((ip, g.country, g.asn, g.lat, g.lon))
    return pd.DataFrame(rows, columns=["source_ip", "country", "asn", "lat", "lon"])


def load_events(con, where: str = "", cols: Optional[list[str]] = None) -> pd.DataFrame:
    cols = cols or _PUBLIC_COLS
    df = con.execute(f"SELECT {', '.join(cols)} FROM events {where} ORDER BY event_time, event_id").fetchdf()
    df["event_time"] = pd.to_datetime(df["event_time"])
    return df


@dataclass
class Baseline:
    sets: dict = field(default_factory=dict)         # attr -> DataFrame(identity, value)
    org_sets: dict = field(default_factory=dict)     # attr -> DataFrame(identity_type, value)
    hours: Optional[pd.DataFrame] = None             # identity, hour, rarity
    org_hours: Optional[pd.DataFrame] = None         # identity_type, hour, rarity
    vol: Optional[pd.DataFrame] = None               # identity, mu_n, sd_n, mu_b, sd_b
    org_vol: Optional[pd.DataFrame] = None           # identity_type, mu_n, sd_n, mu_b, sd_b
    identity_types: dict = field(default_factory=dict)

    @property
    def known_identities(self) -> set:
        return set(self.identity_types)


# ---------------------------------------------------------------------------------------------------- SQL pieces
def _enriched(con: duckdb.DuckDBPyConnection, base: Baseline) -> None:
    """Create view `enr` from registered tables ev (events+geo) and baseline tables."""
    for attr in _ATTRS:
        con.register(f"b_{attr}", base.sets[attr])
        con.register(f"o_{attr}", base.org_sets[attr])
    con.register("b_hours", base.hours)
    con.register("o_hours", base.org_hours)
    known = pd.DataFrame({"identity": list(base.identity_types)})
    con.register("known", known)
    con.execute(f"""
    CREATE OR REPLACE TEMP VIEW enr AS
    WITH x AS (
      SELECT e.*, k.identity IS NOT NULL AS is_known,
        LAG(e.source_ip) OVER w AS prev_ip, LAG(e.event_time) OVER w AS prev_t
      FROM ev e LEFT JOIN known k ON k.identity = e.identity
      WINDOW w AS (PARTITION BY e.identity ORDER BY e.event_time, e.event_id)
    )
    SELECT x.*,
      {" ".join(f"CASE WHEN x.is_known THEN (b_{a}.value IS NULL) ELSE (o_{a}.value IS NULL) END::INT AS new_{a}," for a in _ATTRS)}
      COALESCE(CASE WHEN x.is_known THEN bh.rarity ELSE oh.rarity END, 1.0) AS hour_rarity,
      COALESCE(pd.km, 0.0) AS dist_km,
      CASE WHEN pd.km IS NULL THEN 0.0
           ELSE LEAST(20000.0, pd.km / GREATEST(epoch(x.event_time - x.prev_t) / 3600.0, 1.0 / 360.0)) END AS speed_kmh
    FROM x
    {" ".join(f"LEFT JOIN b_{a} ON b_{a}.identity = x.identity AND b_{a}.value = x.{c} LEFT JOIN o_{a} ON o_{a}.identity_type = x.identity_type AND o_{a}.value = x.{c}" for a, c in _ATTRS.items())}
    LEFT JOIN b_hours bh ON bh.identity = x.identity AND bh.hour = hour(x.event_time)
    LEFT JOIN o_hours oh ON oh.identity_type = x.identity_type AND oh.hour = hour(x.event_time)
    LEFT JOIN pair_dist pd ON pd.source_ip = x.source_ip AND pd.prev_ip = x.prev_ip
    """)


def _raw_windows_sql(identity_filter: str = "") -> str:
    hr = ", ".join(f"'{n}'" for n in HIGH_RISK)
    er = ", ".join(f"'{n}'" for n in ERRORS)
    return f"""
    SELECT identity, any_value(identity_type) AS identity_type,
      time_bucket(INTERVAL '{STEP_MIN} minutes', event_time) - k.g * INTERVAL '{STEP_MIN} minutes' AS wstart,
      count(*) AS n, count(DISTINCT event_name) AS n_distinct_names, count(DISTINCT event_source) AS n_services,
      avg(read_only::INT) AS read_ratio,
      avg(COALESCE(error_code IN ({er}), FALSE)::INT) AS err_ratio,
      avg((event_name IN ({hr}))::INT) AS high_risk_share,
      avg((management_event AND regexp_matches(event_name, '^(List|Describe|Get)'))::INT) AS recon_ratio,
      avg(new_ip) AS new_ip, avg(new_asn) AS new_asn, avg(new_country) AS new_country, avg(new_ua) AS new_ua, avg(new_region) AS new_region,
      avg(hour_rarity) AS hour_rarity, max((dayofweek(event_time) IN (0, 6))::INT) AS is_weekend,
      max(dist_km) AS max_dist, max(speed_kmh) AS max_speed,
      COALESCE(sum(bytes_out), 0) AS bytes_out, count(DISTINCT source_ip) AS n_ips,
      sum(login_failed::INT) AS login_fail
    FROM enr CROSS JOIN (SELECT unnest(range({N_SHIFTS})) AS g) k {identity_filter}
    GROUP BY identity, wstart
    """


def _prepare(con: duckdb.DuckDBPyConnection, events: pd.DataFrame) -> None:
    g = ip_geo(events["source_ip"])
    ev = events.merge(g, on="source_ip", how="left")
    ev["login_failed"] = ev["console_login"] == "Failure"     # failed sign-ins carry no errorCode; the result is in responseElements
    con.register("ev", ev)
    # distance table for consecutive-IP pairs per identity
    pairs = con.execute("""SELECT DISTINCT source_ip, prev_ip FROM (
        SELECT source_ip, LAG(source_ip) OVER (PARTITION BY identity ORDER BY event_time, event_id) AS prev_ip FROM ev)
        WHERE prev_ip IS NOT NULL AND prev_ip <> source_ip""").fetchdf()
    gi = g.set_index("source_ip")
    km = [geo.haversine_km(gi.at[a, "lat"], gi.at[a, "lon"], gi.at[b, "lat"], gi.at[b, "lon"]) if a in gi.index and b in gi.index else 0.0
          for a, b in zip(pairs["source_ip"], pairs["prev_ip"])]
    pairs["km"] = km
    con.register("pair_dist", pairs)


def _derive(raw: pd.DataFrame, base: Baseline) -> pd.DataFrame:
    f = raw.copy()
    f["log_n"] = np.log1p(f["n"])
    f["log_max_dist"] = np.log1p(f["max_dist"])
    f["log_max_speed"] = np.log1p(f["max_speed"])
    f["log_n_ips"] = np.log1p(f["n_ips"])
    f["login_fail"] = np.log1p(f["login_fail"])
    f["type_user"] = (f["identity_type"] == "IAMUser").astype(int)
    f["type_role"] = (f["identity_type"] == "AssumedRole").astype(int)
    f["type_root"] = (f["identity_type"] == "Root").astype(int)
    v = base.vol.set_index("identity")
    ov = base.org_vol.set_index("identity_type")
    mu_n = f["identity"].map(v["mu_n"]).fillna(f["identity_type"].map(ov["mu_n"])).fillna(2.0)
    sd_n = f["identity"].map(v["sd_n"]).fillna(f["identity_type"].map(ov["sd_n"])).fillna(1.0)
    mu_b = f["identity"].map(v["mu_b"]).fillna(f["identity_type"].map(ov["mu_b"])).fillna(0.0)
    sd_b = f["identity"].map(v["sd_b"]).fillna(f["identity_type"].map(ov["sd_b"])).fillna(1.0)
    f["volume_z"] = ((f["log_n"] - mu_n) / sd_n).clip(-10, 10)
    lb = np.log1p(f["bytes_out"])
    f["bytes_z"] = np.where(f["bytes_out"] > 0, ((lb - mu_b) / sd_b).clip(-5, 10), 0.0)
    f[FEATURES] = f[FEATURES].astype(float)
    if f[FEATURES].isna().any().any():
        bad = f[FEATURES].columns[f[FEATURES].isna().any()].tolist()
        raise ValueError(f"NaN in feature columns {bad}")      # a silent NaN once hid a bug; never let one through
    return f


def compute_windows(events: pd.DataFrame, base: Baseline, min_start: Optional[pd.Timestamp] = None) -> pd.DataFrame:
    """Feature table: one row per (identity, wstart) with FEATURES columns. `events` must be time-sorted flat rows."""
    if events.empty:
        return pd.DataFrame(columns=["identity", "identity_type", "wstart", *FEATURES])
    con = duckdb.connect()
    _prepare(con, events)
    _enriched(con, base)
    raw = con.execute(_raw_windows_sql()).fetchdf()
    con.close()
    if min_start is not None:
        raw = raw[raw["wstart"] >= min_start]
    return _derive(raw, base).sort_values(["wstart", "identity"]).reset_index(drop=True)


def fit_baseline(events: pd.DataFrame) -> Baseline:
    """Learn per-identity (and org-level fallback) known IPs/ASNs/countries/UAs/regions, active hours and volume stats."""
    g = ip_geo(events["source_ip"])
    ev = events.merge(g, on="source_ip", how="left")
    b = Baseline()
    b.identity_types = ev.groupby("identity")["identity_type"].first().to_dict()
    for a, col in _ATTRS.items():
        b.sets[a] = ev[["identity", col]].dropna().drop_duplicates().rename(columns={col: "value"})
        b.org_sets[a] = ev[["identity_type", col]].dropna().drop_duplicates().rename(columns={col: "value"})
    for key, name in (("identity", "hours"), ("identity_type", "org_hours")):
        h = ev.assign(hour=ev["event_time"].dt.hour).groupby([key, "hour"]).size().rename("c").reset_index()
        h["rarity"] = 1.0 - h["c"] / h.groupby(key)["c"].transform("max")
        setattr(b, name, h[[key, "hour", "rarity"]])
    # volume stats from the training windows themselves (two-pass): temporarily use empty novelty tables
    tmp = Baseline(sets={a: pd.DataFrame(columns=["identity", "value"]) for a in _ATTRS},
                   org_sets={a: pd.DataFrame(columns=["identity_type", "value"]) for a in _ATTRS},
                   hours=b.hours, org_hours=b.org_hours, identity_types=b.identity_types)
    con = duckdb.connect()
    _prepare(con, events)
    _enriched(con, tmp)
    raw = con.execute(_raw_windows_sql()).fetchdf()
    con.close()
    raw["ln"] = np.log1p(raw["n"])
    raw["lb"] = np.log1p(raw["bytes_out"])
    def stats(df, key):
        s = df.groupby(key).agg(mu_n=("ln", "mean"), sd_n=("ln", "std"))
        bb = df[df["bytes_out"] > 0].groupby(key).agg(mu_b=("lb", "mean"), sd_b=("lb", "std"))
        s = s.join(bb).fillna({"mu_b": 0.0, "sd_b": 1.0}).reset_index()
        s["sd_n"] = s["sd_n"].fillna(1.0).clip(lower=0.25)
        s["sd_b"] = s["sd_b"].fillna(1.0).clip(lower=0.5)
        return s
    b.vol = stats(raw, "identity")
    b.org_vol = stats(raw, "identity_type")
    return b
