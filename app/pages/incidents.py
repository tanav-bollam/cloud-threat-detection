import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st

from app import common as C
from app import data as D

C.sidebar()
st.title("Alerts & Incidents")
eng = C.engine()
auto = st.toggle("Auto-refresh every 5 s", value=False, help="Off by default so row selections are not disturbed while you work.")
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@st.fragment(run_every=5 if auto else None)
def incidents_tab() -> None:
    inc = D.incident_list(C.cur())
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    sev = f1.multiselect("Severity", SEVS, default=SEVS, key="inc_sev")
    status = f2.multiselect("Status", D.STATUSES, default=["Open", "Investigating"], key="inc_status")
    layers = f3.multiselect("Detected by", ["rule", "anomaly", "ip"], default=[], key="inc_layers", placeholder="any layer")
    text = f4.text_input("Search title / identity / IP", key="inc_text")
    if inc.empty:
        st.info("No incidents yet.")
        return
    m = inc["severity"].isin(sev) & inc["status"].isin(status)
    if layers:
        m &= inc["sources"].map(lambda s: bool(set(s) & set(layers)))
    if text:
        t = text.lower()
        m &= inc.apply(lambda r: t in (r["title"] + " ".join(r["identities"]) + " ".join(r["ips"])).lower(), axis=1)
    v = inc[m].sort_values(["rank", "risk_score"], ascending=False).reset_index(drop=True)
    show = pd.DataFrame({"Severity": v["severity"].map(C.sev_label), "Risk": v["risk_score"], "Title": v["title"], "Identities": v["identities"].map(", ".join),
                         "First seen": v["first_seen"], "Last seen": v["last_seen"], "Alerts": v["n_alerts"], "Detected by": v["sources"].map(", ".join),
                         "Status": v["status"], "ID": v["incident_id"]})
    st.caption(f"{len(v)} of {len(inc)} incidents · click column headers to sort · tick rows for actions")
    ev = st.dataframe(show, hide_index=True, width="stretch", on_select="rerun", selection_mode="multi-row", key="inc_table",
                      column_config={"Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
                                     "Title": st.column_config.TextColumn("Title", width="large"),
                                     "First seen": st.column_config.DatetimeColumn(format="MM-DD HH:mm:ss"),
                                     "Last seen": st.column_config.DatetimeColumn(format="MM-DD HH:mm:ss")})
    rows = ev.selection.rows
    sel = v.iloc[rows] if rows else v.iloc[0:0]
    a, b, c = st.columns([2, 1, 2])
    new_status = a.selectbox("Set status for selected", D.STATUSES, key="inc_new_status", disabled=sel.empty)
    if b.button("Apply", disabled=sel.empty, width="stretch"):
        for iid in sel["incident_id"]:
            eng.set_incident_status(iid, new_status)
        st.toast(f"{len(sel)} incident(s) → {new_status}")
        st.rerun(scope="fragment")
    if c.button("Open investigation →", disabled=len(sel) != 1, width="stretch", type="primary",
                help="Select exactly one incident"):
        C.go("pages/investigation.py", selected_incident=sel.iloc[0]["incident_id"])


@st.fragment(run_every=5 if auto else None)
def alerts_tab() -> None:
    al = D.df(C.cur(), "SELECT alert_id, detected_at, severity, source, rule_id, title, identity, source_ip, risk, mitre_tactic, incident_id, status FROM alerts ORDER BY detected_at DESC")
    f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
    sev = f1.multiselect("Severity", SEVS, default=SEVS, key="al_sev")
    layer = f2.multiselect("Layer", ["rule", "anomaly", "ip"], default=["rule", "anomaly", "ip"], key="al_layer")
    status = f3.multiselect("Status", D.STATUSES, default=["Open", "Investigating"], key="al_status")
    text = f4.text_input("Search title / identity / IP / rule", key="al_text")
    if al.empty:
        st.info("No alerts yet.")
        return
    m = al["severity"].isin(sev) & al["source"].isin(layer) & al["status"].isin(status)
    if text:
        t = text.lower()
        m &= (al["title"] + " " + al["identity"] + " " + al["source_ip"].fillna("") + " " + al["rule_id"]).str.lower().str.contains(t, regex=False)
    v = al[m].reset_index(drop=True)
    show = v.drop(columns=["alert_id"]).assign(severity=v["severity"].map(C.sev_label))
    st.caption(f"{len(v)} of {len(al)} alerts")
    ev = st.dataframe(show, hide_index=True, width="stretch", on_select="rerun", selection_mode="multi-row", key="al_table",
                      column_config={"detected_at": st.column_config.DatetimeColumn("Detected", format="MM-DD HH:mm:ss"), "severity": "Severity", "source": "Layer",
                                     "rule_id": "Rule", "title": "Alert", "identity": "Identity", "source_ip": "Source IP",
                                     "risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
                                     "mitre_tactic": "MITRE tactic", "incident_id": "Incident", "status": "Status"})
    rows = ev.selection.rows
    sel = v.iloc[rows] if rows else v.iloc[0:0]
    st.markdown("**Bulk actions** (apply to the ticked rows)")
    a, b, c = st.columns([2, 3, 2])
    st_new = a.selectbox("Status", ["Investigating", "Resolved", "Open"], key="al_new_status", disabled=sel.empty)
    if a.button("Set status", disabled=sel.empty, width="stretch"):
        for aid in sel["alert_id"]:
            eng.mark_alert(aid, st_new)
        st.rerun(scope="fragment")
    scope = b.radio("Suppression scope for False Positive", ["identity", "ip", "rule"], horizontal=True, key="al_scope",
                    format_func={"identity": "this rule + identity", "ip": "this rule + IP", "rule": "this rule, everyone"}.get,
                    help="Marking False Positive stores a suppression entry. It filters future alerts; nothing is retrained.")
    if b.button("Mark False Positive", disabled=sel.empty, width="stretch"):
        for aid in sel["alert_id"]:
            eng.mark_alert(aid, "False Positive", scope=scope, note="marked in dashboard")
        st.toast(f"{len(sel)} alert(s) marked False Positive; suppression added")
        st.rerun(scope="fragment")
    c.write("")
    sl = eng.suppressions
    with st.expander(f"Suppression list ({len(sl.entries) if sl else 0})"):
        if not sl or not sl.entries:
            st.caption("Empty. Mark an alert as False Positive to add an entry.")
        else:
            alerts_now = list(eng.detector.alerts.values())
            imp = sl.impact(alerts_now)
            st.caption(f"Impact on the {imp['alerts_total']} alerts currently in memory: {imp['would_suppress']} would be suppressed. "
                       "Thresholds are not retrained automatically.")
            for i, s in enumerate(list(sl.entries)):
                cc1, cc2 = st.columns([5, 1])
                cc1.markdown(f"`{s.rule_id}` · identity `{s.identity}` · ip `{s.source_ip}` · {s.note}")
                if cc2.button("Remove", key=f"rm_{i}"):
                    sl.remove(s)
                    st.rerun(scope="fragment")


t1, t2 = st.tabs(["Incidents", "Alerts"])
with t1:
    incidents_tab()
with t2:
    alerts_tab()
