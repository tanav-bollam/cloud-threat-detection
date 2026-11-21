import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app import common as C
from app import data as D
from src import reporting
from src.detection.rules_engine import load_rules

C.sidebar()
st.title("Incident Investigation")
eng = C.engine()
cur = C.cur()

inc_df = D.incident_list(cur)
if inc_df.empty:
    st.info("No incidents yet. Inject an attack from **Attack Simulator** or wait for activity.")
    st.stop()
inc_df = inc_df.sort_values(["rank", "risk_score"], ascending=False)
ids = list(inc_df["incident_id"])
want = st.session_state.get("selected_incident")
label = {r.incident_id: f"{C.sev_label(r.severity)} · {r.risk_score:.0f} · {r.title[:70]} ({r.incident_id})" for r in inc_df.itertuples()}
iid = st.selectbox("Incident", ids, index=ids.index(want) if want in ids else 0, format_func=label.get)
st.session_state["selected_incident"] = iid
inc = D.get_incident(cur, iid)
alerts = D.incident_alerts(cur, iid)
RULES = {r.id: r for r in load_rules()}

# ------------------------------------------------------------------ header
st.markdown(f"### {inc['title']}")
h1, h2, h3, h4 = st.columns([1.2, 1, 1.5, 1.5])
h1.markdown(C.sev_chip(inc["severity"]), unsafe_allow_html=True)
h2.metric("Risk score", f"{inc['risk_score']:.0f} / 100")
h3.metric("First seen", pd.Timestamp(inc["first_seen"]).strftime("%m-%d %H:%M:%S"))
h4.metric("Last seen", pd.Timestamp(inc["last_seen"]).strftime("%m-%d %H:%M:%S"))
st.markdown("**MITRE ATT&CK chain** &nbsp; " + C.tactic_chain(inc["tactics"]), unsafe_allow_html=True)
if inc["techniques"]:
    st.caption("Techniques: " + ", ".join(inc["techniques"]) + " · detected by: " + ", ".join(inc["sources"]))

# entities + pivots
st.markdown("**Entities** — click to pivot in Forensics")
cols = st.columns(max(1, min(6, len(inc["identities"]) + len(inc["ips"]))))
k = 0
for ident in inc["identities"][:6]:
    if cols[k % len(cols)].button(f"👤 {ident}", key=f"pi_{ident}", width="stretch"):
        C.go("pages/forensics.py", pivot_identity=ident, pivot_ip="")
    k += 1
for ip in inc["ips"][:6]:
    if ip[:1].isdigit() and cols[k % len(cols)].button(f"🌐 {ip}", key=f"pp_{ip}", width="stretch"):
        C.go("pages/forensics.py", pivot_ip=ip, pivot_identity="")
    k += 1

# ------------------------------------------------------------------ status + notes
with st.container(border=True):
    s1, s2 = st.columns([1, 3])
    status = s1.selectbox("Status", D.STATUSES, index=D.STATUSES.index(inc["status"]) if inc["status"] in D.STATUSES else 0, key=f"st_{iid}")
    notes = s2.text_area("Analyst notes", value=inc.get("notes") or "", key=f"nt_{iid}", height=90, placeholder="What did you check? What did you find?")
    if st.button("Save status & notes", type="primary"):
        eng.set_incident_status(iid, status, notes)
        st.toast("Saved")
        st.rerun()

# ------------------------------------------------------------------ timeline
tl = D.incident_timeline(cur, inc, alerts, eng.org_known_ips)
st.subheader("Timeline")
st.caption("Every event by the involved identities (and non-organisation IPs) around the incident. Filled markers were flagged by a rule or the IP layer; "
           "blue rings fall inside an anomalous window; grey is context.")
if tl.empty:
    st.info("No events in range.")
else:
    fig = go.Figure()
    SYM = {"CONTEXT": "circle", "ANOMALOUS WINDOW": "circle-open", "LOW": "circle-open", "MEDIUM": "circle", "HIGH": "triangle-up", "CRITICAL": "diamond"}
    SIZE = {"CONTEXT": 5, "ANOMALOUS WINDOW": 8, "LOW": 10, "MEDIUM": 10, "HIGH": 12, "CRITICAL": 13}
    for flag in ("CONTEXT", "ANOMALOUS WINDOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
        t = tl[tl["flag"] == flag]
        if t.empty:
            continue
        name = "Context" if flag == "CONTEXT" else "In anomalous window" if flag == "ANOMALOUS WINDOW" else f"{C.SEV_SYMBOL[flag]} {flag}"
        fig.add_trace(go.Scatter(
            x=t["event_time"], y=t["identity"], mode="markers", name=name, opacity=0.55 if flag == "CONTEXT" else 1,
            marker=dict(symbol=SYM[flag], size=SIZE[flag], color=C.FLAG_COLOR[flag], line=dict(width=1.5 if "open" in SYM[flag] else 1, color=C.FLAG_COLOR[flag] if "open" in SYM[flag] else C.SURFACE)),
            customdata=t[["event_name", "source_ip", "aws_region", "error_code"]].fillna("").to_numpy(),
            hovertemplate="%{x|%H:%M:%S}<br><b>%{customdata[0]}</b><br>IP %{customdata[1]} · %{customdata[2]}<br>%{customdata[3]}<extra></extra>"))
    C.style_fig(fig, height=max(240, 70 * tl["identity"].nunique() + 120))
    st.plotly_chart(fig, width="stretch", key="inv_tl")
    flagged = tl[tl["flag"] != "CONTEXT"]
    with st.expander(f"Event table ({len(tl)} events, {len(flagged)} flagged)"):
        st.dataframe(tl.drop(columns=["event_id", "event_source", "identity_type"]), hide_index=True, width="stretch", height=300)

# ------------------------------------------------------------------ alerts + why flagged
st.subheader("Alerts and why they fired")
for a in alerts.itertuples():
    with st.expander(f"{C.sev_label(a.severity)} · {a.title} · {pd.Timestamp(a.detected_at):%H:%M:%S} · {a.identity}", expanded=(a.source == "anomaly" and len(alerts) <= 4)):
        st.markdown(f"**{a.rule_id}** ({a.source}) · risk {a.risk:.0f} · tactic {a.mitre_tactic or 'n/a'} {a.mitre_technique or ''}")
        st.write(a.description)
        if a.detail:
            st.caption(a.detail)
        r = RULES.get(a.rule_id)
        if r and r.false_positive_notes:
            st.markdown(f"*Possible false positives:* {r.false_positive_notes}")
        if a.reasons:
            fr = pd.DataFrame(a.reasons)
            f = go.Figure(go.Bar(y=fr["feature"], x=fr["contribution"], orientation="h", marker_color=C.BLUE, name="SHAP contribution",
                                 text=[f"{v} ({c:+.2f})" for v, c in zip(fr["value"], fr["contribution"])], textposition="outside",
                                 textfont=dict(color=C.INK2), hovertemplate="%{y}: pushes score +%{x:.2f}<extra></extra>"))
            C.style_fig(f, height=60 + 34 * len(fr), legend=False)
            f.update_yaxes(autorange="reversed")
            f.update_xaxes(title_text="SHAP contribution toward 'anomalous' (feature value in labels)", range=[0, max(fr["contribution"]) * 1.5])
            st.plotly_chart(f, width="stretch", key=f"shap_{a.alert_id}")
        ids_a = [e for e in a.matched_event_ids][:15]
        if ids_a:
            pick = st.selectbox("Inspect a matched event", ids_a, key=f"pick_{a.alert_id}", format_func=lambda e: e[:8])
            if st.button("Show raw CloudTrail JSON", key=f"raw_{a.alert_id}"):
                st.json(D.raw_event(cur, pick) or {})

# ------------------------------------------------------------------ export
st.subheader("Export report")
flag_ev = tl[tl["flag"] != "CONTEXT"] if not tl.empty else tl
rep_tl = [{"time": str(r.event_time), "identity": r.identity, "ip": r.source_ip, "event": r.event_name, "region": r.aws_region,
           "error": r.error_code, "risk": r.flag} for r in flag_ev.itertuples()]
raw = D.raw_events(cur, list(flag_ev["event_id"])) if not flag_ev.empty else []
rep = reporting.build_report(inc, json.loads(alerts.drop(columns=["matched_event_ids"]).to_json(orient="records", date_format="iso")), rep_tl, raw,
                             notes=st.session_state.get(f"nt_{iid}", inc.get("notes") or ""))
c1, c2 = st.columns(2)
c1.download_button("⬇ Markdown report", reporting.to_markdown(rep), file_name=f"{iid}.md", mime="text/markdown", width="stretch")
c2.download_button("⬇ JSON report", json.dumps(rep, indent=1, default=str), file_name=f"{iid}.json", mime="application/json", width="stretch")
with st.expander("Preview report"):
    st.markdown(reporting.to_markdown(rep))
