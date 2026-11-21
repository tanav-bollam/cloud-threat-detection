import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app import common as C
from app import data as D

C.sidebar()
st.title("Overview")
st.caption("Live view of the simulated AWS account. All times are simulated UTC.")

SYMBOL = {"LOW": "circle-open", "MEDIUM": "circle", "HIGH": "triangle-up", "CRITICAL": "diamond"}


def toast_new_alerts(c) -> None:
    seen = st.session_state.setdefault("seen_alerts", None)
    cur_ids = D.df(c, "SELECT alert_id, severity, title, identity FROM alerts")
    if seen is None:                                   # first load: don't toast history
        st.session_state["seen_alerts"] = set(cur_ids["alert_id"])
        return
    new = cur_ids[~cur_ids["alert_id"].isin(seen)]
    for r in new.itertuples():
        if r.severity in ("HIGH", "CRITICAL"):
            st.toast(f"{C.sev_label(r.severity)}: {r.title} ({r.identity})", icon=":material/warning:")
    st.session_state["seen_alerts"] = seen | set(cur_ids["alert_id"])


@st.fragment(run_every=3)
def live() -> None:
    c = C.cur()
    toast_new_alerts(c)
    k = D.kpis(c)
    cols = st.columns(5)
    cols[0].metric("Events / min", f"{k['events_per_min']:,}", help="Average over the last 15 simulated minutes")
    cols[1].metric("Events processed", f"{k['events_total']:,}")
    seen = {r[0] for r in c.execute("SELECT DISTINCT identity FROM events").fetchall()}
    cols[2].metric("Identities monitored", len(seen | set(C.engine().baseline.identity_types)), help="Everything with a learned baseline plus anything new seen in the stream")
    cols[3].metric("Alerts raised", k["alerts"])
    cols[4].metric("Open incidents", k["open_incidents"])
    st.markdown("**Open incidents by severity** &nbsp; " + " &nbsp; ".join(
        f"{C.sev_chip(s)} <b>{k['open_by_sev'][s]}</b>" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")), unsafe_allow_html=True)

    # --- events over time with alert markers
    ev = D.events_over_time(c, hours=6, bucket_min=5)
    al = D.alerts_over_time(c, hours=6)
    fig = go.Figure()
    if not ev.empty:
        fig.add_trace(go.Scatter(x=ev["t"], y=ev["events"], mode="lines", name="Events per 5 min", line=dict(color=C.BLUE, width=2),
                                 hovertemplate="%{x|%H:%M}  %{y:,} events<extra></extra>"))
        if not al.empty:
            al = al.copy()
            al["bucket"] = pd.to_datetime(al["detected_at"]).dt.floor("5min")
            y = ev.set_index("t")["events"]
            al["y"] = al["bucket"].map(y).fillna(float(y.median()))
            for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                a = al[al["severity"] == sev]
                if a.empty:
                    continue
                fig.add_trace(go.Scatter(x=a["detected_at"], y=a["y"], mode="markers", name=f"{C.SEV_SYMBOL[sev]} {sev} alert",
                                         marker=dict(symbol=SYMBOL[sev], size=11, color=C.SEV_COLOR[sev], line=dict(color=C.SURFACE, width=2)),
                                         text=a["title"] + " — " + a["identity"], hovertemplate="%{x|%H:%M:%S}<br>%{text}<extra></extra>"))
    C.style_fig(fig, height=300)
    fig.update_yaxes(title_text="events / 5 min", rangemode="tozero")
    st.plotly_chart(fig, width="stretch", key="ov_events")

    left, right = st.columns([1, 1])
    with left:
        st.subheader("Top risky identities")
        ti = D.top_risky_identities(c)
        if ti.empty:
            st.info("No alerts yet.")
        else:
            inv = {v: k_ for k_, v in D.SEV_ORDER.items()}
            ti["severity"] = ti["sev_rank"].map(inv)
            fig2 = go.Figure()
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                t = ti[ti["severity"] == sev]
                if not t.empty:
                    fig2.add_trace(go.Bar(y=t["identity"], x=t["max_risk"], orientation="h", name=f"{C.SEV_SYMBOL[sev]} {sev}", marker_color=C.SEV_COLOR[sev],
                                          text=t["max_risk"].round(0).astype(int), textposition="outside", textfont=dict(color=C.INK2),
                                          customdata=t["alerts"], hovertemplate="%{y}: max risk %{x} (%{customdata} alerts)<extra></extra>"))
            C.style_fig(fig2, height=max(220, 34 * len(ti) + 80))
            fig2.update_layout(barmode="stack", bargap=0.35)
            fig2.update_yaxes(autorange="reversed")
            fig2.update_xaxes(range=[0, 115], title_text="max alert risk (0–100)")
            st.plotly_chart(fig2, width="stretch", key="ov_ident")
    with right:
        st.subheader("Top source IPs")
        ips = D.top_source_ips(c, n=8).drop(columns=["identities"])
        st.dataframe(ips, hide_index=True, width="stretch", height=min(35 * len(ips) + 38, 340),
                     column_config={"source_ip": "IP", "country": "Country", "network": "Network", "kind": "Type",
                                    "events": st.column_config.NumberColumn("Events"),
                                    "alerts": st.column_config.NumberColumn("Alerts")})
        cc = D.country_counts(c)
        if not cc.empty:
            f3 = go.Figure(go.Bar(x=cc["country"], y=cc["events"], marker_color=C.BLUE, name="Events",
                                  hovertemplate="%{x}: %{y:,} events<extra></extra>"))
            C.style_fig(f3, height=170, legend=False)
            f3.update_yaxes(title_text="events", rangemode="tozero")
            st.plotly_chart(f3, width="stretch", key="ov_country")
            st.caption("Events by source country (last 6 simulated hours).")

    st.subheader("Latest alerts")
    la = D.latest_alerts(c, 12)
    if la.empty:
        st.info("No alerts yet. Open **Attack Simulator** and inject a scenario, or wait for the stream to produce activity.")
    else:
        la["severity"] = la["severity"].map(C.sev_label)
        st.dataframe(la.drop(columns=["alert_id"]), hide_index=True, width="stretch",
                     column_config={"detected_at": st.column_config.DatetimeColumn("Detected (sim)", format="HH:mm:ss"), "severity": "Severity",
                                    "source": "Layer", "title": "Alert", "identity": "Identity", "source_ip": "Source IP", "incident_id": "Incident", "status": "Status"})


live()
