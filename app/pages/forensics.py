import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st

from app import common as C
from app import data as D

C.sidebar()
st.title("Forensics Search")
st.caption("Query the CloudTrail events captured so far. Pivot by clicking a row, then choosing an IP, identity or access key.")
cur = C.cur()

# ---- pivots arriving from other pages (set before the widgets are created)
for src, dst in (("pivot_ip", "f_ip"), ("pivot_identity", "f_identity")):
    if st.session_state.get(src):
        st.session_state[dst] = st.session_state.pop(src)
        for other in ("f_identity", "f_ip", "f_access_key", "f_event_name", "f_region"):
            if other != dst:
                st.session_state.setdefault(other, "")


def set_filter(**kv):
    """Button callback: replace all text filters with these values (a pivot)."""
    for k in ("f_identity", "f_ip", "f_access_key", "f_event_name", "f_region"):
        st.session_state[k] = ""
    for k, v in kv.items():
        st.session_state[k] = v


with st.form("forensics"):
    c1, c2, c3 = st.columns(3)
    c1.text_input("Identity (user / role)", key="f_identity", placeholder="e.g. alice")
    c2.text_input("Source IP", key="f_ip", placeholder="e.g. 185.")
    c3.text_input("Access key ID", key="f_access_key", placeholder="AKIA…")
    c4, c5, c6, c7 = st.columns([2, 2, 2, 1])
    c4.text_input("Event name", key="f_event_name", placeholder="e.g. AttachUserPolicy")
    c5.text_input("Region", key="f_region", placeholder="e.g. ap-southeast-1")
    rng = c6.selectbox("Time range (simulated)", ["All captured", "Last 1 hour", "Last 6 hours", "Last 24 hours"], key="f_range")
    c7.write("")
    errs = c7.checkbox("Errors only", key="f_errs")
    st.form_submit_button("Search", type="primary")

_, now = D.sim_bounds(cur)
hours = {"Last 1 hour": 1, "Last 6 hours": 6, "Last 24 hours": 24}.get(rng)
f = {"identity": st.session_state.get("f_identity"), "ip": st.session_state.get("f_ip"), "access_key": st.session_state.get("f_access_key"),
     "event_name": st.session_state.get("f_event_name"), "region": st.session_state.get("f_region"), "errors_only": errs,
     "t_from": (now - pd.Timedelta(hours=hours)) if (hours and now is not None) else None}
sql, params = D.build_forensics_sql(f, limit=5000)
res = D.df(cur, sql, params)
res["error_code"] = res["error_code"].fillna("")
st.caption(f"{len(res):,} events shown (max 5,000, newest first)")
ev = st.dataframe(res.drop(columns=["event_id"]), hide_index=True, width="stretch", height=320, on_select="rerun", selection_mode="single-row", key="f_table",
                  column_config={"event_time": st.column_config.DatetimeColumn("Time", format="MM-DD HH:mm:ss"), "identity": "Identity", "source_ip": "Source IP",
                                 "event_name": "Event", "aws_region": "Region", "error_code": "Error", "access_key_id": "Access key", "user_agent": "User agent"})
rows = ev.selection.rows
if rows:
    r = res.iloc[rows[0]]
    st.markdown("**Pivot from the selected event**")
    b1, b2, b3, b4 = st.columns(4)
    b1.button(f"🌐 IP {r['source_ip']}", on_click=set_filter, kwargs={"f_ip": r["source_ip"]}, width="stretch")
    b2.button(f"👤 {r['identity']}", on_click=set_filter, kwargs={"f_identity": r["identity"]}, width="stretch")
    if r["access_key_id"]:
        b3.button(f"🔑 {r['access_key_id']}", on_click=set_filter, kwargs={"f_access_key": r["access_key_id"]}, width="stretch")
    b4.button(f"⚙ {r['event_name']}", on_click=set_filter, kwargs={"f_event_name": r["event_name"]}, width="stretch")
    tabs = st.tabs(["Raw CloudTrail JSON", "IP pivot", "Identity pivot"])
    with tabs[0]:
        st.json(D.raw_event(cur, r["event_id"]) or {})
    with tabs[1]:
        p = D.pivot_ip(cur, r["source_ip"])
        g = p["geo"]
        st.markdown(f"**{r['source_ip']}** — {g.country_name} ({g.country}) · {g.org} {g.asn} · {g.kind}")
        a, b = st.columns(2)
        a.markdown("Identities seen on this IP")
        a.dataframe(p["identities"], hide_index=True, width="stretch")
        b.markdown("Top events")
        b.dataframe(p["events"], hide_index=True, width="stretch")
        if not p["alerts"].empty:
            st.markdown("Alerts on this IP")
            st.dataframe(p["alerts"], hide_index=True, width="stretch")
    with tabs[2]:
        p = D.pivot_identity(cur, r["identity"])
        a, b = st.columns(2)
        a.markdown("IPs used by this identity")
        a.dataframe(p["ips"], hide_index=True, width="stretch")
        b.markdown("Access keys / top events")
        b.dataframe(p["keys"], hide_index=True, width="stretch")
        b.dataframe(p["events"], hide_index=True, width="stretch")

st.divider()
st.subheader("SQL")
st.caption("Read-only DuckDB. Tables: `events`, `alerts`, `incidents`. Results are capped at 5,000 rows.")
default_sql = "SELECT event_name, count(*) AS n, count(DISTINCT identity) AS identities\nFROM events\nWHERE error_code IS NOT NULL\nGROUP BY 1 ORDER BY n DESC LIMIT 20"
sql_text = st.text_area("Query", value=st.session_state.get("sql_text", default_sql), height=140, key="sql_text")
if st.button("Run query"):
    ok, why = D.is_safe_select(sql_text)
    if not ok:
        st.error(why)
    else:
        try:
            out = D.df(cur, f"SELECT * FROM ({sql_text.strip().rstrip(';')}) LIMIT 5000")
            st.dataframe(out, hide_index=True, width="stretch")
            st.download_button("⬇ CSV", out.to_csv(index=False), file_name="query.csv", mime="text/csv")
        except Exception as ex:   # noqa: BLE001 - show SQL errors to the analyst
            st.error(f"Query failed: {ex}")
