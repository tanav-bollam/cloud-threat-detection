import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app import common as C
from src.generator.attacks import SCEN

C.sidebar()
st.title("Detection Quality")
st.caption("Measured against the generator's ground-truth labels on a held-out week. Numbers are read from `reports/*.json`; "
           "regenerate with `scripts/evaluate.py`, `scripts/robustness.py` and `scripts/make_results.py`.")

REPORTS = C.ROOT / "reports"
NAMES = {k: v["name"] for k, v in SCEN["scenarios"].items()}
LAYERS = {"rules_only": "Rules", "anomaly_only": "IsolationForest", "ip_only": "IP layer", "combined": "Combined"}
LAYER_ALL = {"rules_only": "Rules only", "anomaly_only": "IsolationForest only", "ip_only": "IP layer only", "rules+ip": "Rules + IP",
             "rules+anomaly": "Rules + IsolationForest", "combined": "Combined"}
SERIES = {"rules_only": C.BLUE, "anomaly_only": C.ORANGE, "ip_only": C.AQUA, "combined": "#c98500"}     # dataviz slots 1-4 (dark steps)
DASH = {"rules_only": "solid", "anomaly_only": "solid", "ip_only": "solid", "combined": "solid"}


@st.cache_data(show_spinner=False)
def load(name: str, mtime: float):
    p = REPORTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def get(name: str):
    p = REPORTS / name
    return load(name, p.stat().st_mtime if p.exists() else 0.0)


g, pg, rob, live = get("metrics.json"), get("metrics_per_group.json"), get("robustness.json"), get("live_ttd.json")
if not g:
    st.warning("No metrics yet. Run `python scripts/train.py` then `python scripts/evaluate.py` (see the README).")
    st.stop()

L = g["layers"]
Cm = L["combined"]
k = st.columns(5)
k[0].metric("Attacks detected", f"{Cm['test_week']['injection_recall']*100:.0f}%", help=f"Incident-level recall over {g['injections']} injected attack stages")
k[1].metric("False-positive incidents / day", Cm["benign_week"]["fp_incidents_per_day"], help="Measured on a separate benign-only week")
k[2].metric("False-positive HIGH+ / day", Cm["benign_week"]["fp_high_or_critical_per_day"])
k[3].metric("Time to detect p50 / p95", f"{Cm['ttd_p50_s']:.0f} / {Cm['ttd_p95_s']:.0f} s", help="Simulated seconds from the first malicious event")
k[4].metric("Kill chains in one incident", f"{Cm['test_week']['chains_in_single_incident']}/{Cm['test_week']['chains']}")

t1, t2, t3, t4, t5 = st.tabs(["Ablation", "Per scenario", "Time to detect", "Stealth robustness", "Live pipeline"])

with t1:
    st.markdown("**Which layer catches what.** Incident-level recall per scenario; the table below adds precision and false positives.")
    sc = sorted(Cm["per_scenario"])
    fig = go.Figure()
    for key, name in LAYERS.items():
        rec = [L[key]["test_week"]["recall_by_scenario"].get(s, 0) * 100 for s in sc]
        fig.add_trace(go.Bar(x=sc, y=rec, name=name, marker_color=SERIES[key], hovertemplate="%{x}: %{y:.0f}% (" + name + ")<extra></extra>"))
    C.style_fig(fig, height=330)
    fig.update_layout(barmode="group", bargap=0.25, bargroupgap=0.06)
    fig.update_yaxes(range=[0, 108], title_text="incident recall (%)")
    fig.update_xaxes(tickvals=sc, ticktext=[f"{s}" for s in sc])
    st.plotly_chart(fig, width="stretch", key="q_abl")
    st.caption("Scenarios: " + " · ".join(f"**{s}** {NAMES[s]}" for s in sc))
    rows = [{"Layers": LAYER_ALL[n], "Incident recall": v["test_week"]["injection_recall"] * 100, "Incident precision": v["test_week"]["incident_precision"] * 100,
             "FP incidents/day": v["benign_week"]["fp_incidents_per_day"], "FP HIGH+/day": v["benign_week"]["fp_high_or_critical_per_day"],
             "Event precision": v["event_level"]["precision"] * 100, "Event recall": v["event_level"]["recall"] * 100,
             "TTD p50 (s)": v["ttd_p50_s"], "TTD p95 (s)": v["ttd_p95_s"]} for n, v in L.items()]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch",
                 column_config={c: st.column_config.NumberColumn(c, format="%.1f") for c in ("Incident recall", "Incident precision", "Event precision", "Event recall", "TTD p50 (s)", "TTD p95 (s)")})
    if pg:
        P = pg["layers"]
        st.markdown("**Global vs per-group model**")
        st.dataframe(pd.DataFrame([
            {"Variant": "Global (identity type as features)", "Anomaly-only recall %": L["anomaly_only"]["test_week"]["injection_recall"] * 100, "Combined recall %": Cm["test_week"]["injection_recall"] * 100,
             "Combined FP incidents/day": Cm["benign_week"]["fp_incidents_per_day"]},
            {"Variant": "Per group (human vs service role)", "Anomaly-only recall %": P["anomaly_only"]["test_week"]["injection_recall"] * 100, "Combined recall %": P["combined"]["test_week"]["injection_recall"] * 100,
             "Combined FP incidents/day": P["combined"]["benign_week"]["fp_incidents_per_day"]}]), hide_index=True, width="stretch")

with t2:
    ps = Cm["per_scenario"]
    df = pd.DataFrame([{"Scenario": f"{s}: {NAMES[s]}", "Injections": v["injections"], "Detected": v["detected"], "Incident P %": v["incident"]["precision"] * 100,
                        "Incident R %": v["incident"]["recall"] * 100, "Incident F1 %": v["incident"]["f1"] * 100, "Event P %": v["event"]["precision"] * 100,
                        "Event R %": v["event"]["recall"] * 100, "Event F1 %": v["event"]["f1"] * 100} for s, v in ps.items()])
    st.dataframe(df, hide_index=True, width="stretch", column_config={c: st.column_config.NumberColumn(c, format="%.1f") for c in df.columns if c.endswith("%")})
    st.info("Precision here is one-vs-rest against the benign background: every scenario is charged all of the test week's false positives, so it depends on how many "
            "attacks were injected (synthetic prevalence). Use *false positives per day* (benign week) as the prevalence-independent number. Event-level precision is low "
            "for scenarios with few events because an anomaly window also pulls in neighbouring benign events.")

with t3:
    ttd = pd.Series(Cm["ttd_sim_s"], dtype=float)
    bins = [(-1, 0, "0 s (on the event)"), (0, 10, "≤ 10 s"), (10, 60, "10–60 s"), (60, 300, "1–5 min"), (300, 900, "5–15 min"), (900, 1e9, "> 15 min")]
    counts = [int(((ttd > lo) & (ttd <= hi)).sum()) for lo, hi, _ in bins]
    f = go.Figure(go.Bar(x=[b[2] for b in bins], y=counts, marker_color=C.BLUE, name="Injections", text=counts, textposition="outside", textfont=dict(color=C.INK2),
                         hovertemplate="%{x}: %{y} injections<extra></extra>"))
    C.style_fig(f, height=300, legend=False)
    f.update_yaxes(title_text="injections", rangemode="tozero")
    st.plotly_chart(f, width="stretch", key="q_ttd")
    st.caption("Combined detector, simulated time from the first malicious event to the first alert covering it. Rules and the IP layer fire on the event; the longer tail is "
               "attacks first caught by the anomaly layer, which alerts when its 15-minute window completes.")
    st.dataframe(pd.DataFrame([{"Layers": LAYER_ALL[n], "p50 (s)": v["ttd_p50_s"], "p95 (s)": v["ttd_p95_s"], "detected": len(v["ttd_sim_s"])} for n, v in L.items()]),
                 hide_index=True, width="stretch", column_config={"p50 (s)": st.column_config.NumberColumn(format="%.1f"), "p95 (s)": st.column_config.NumberColumn(format="%.1f")})

with t4:
    if not rob:
        st.info("Run `python scripts/robustness.py` to measure how recall falls as the attacker blends in.")
    else:
        lv = rob["levels"]
        st.markdown("**How recall falls as the attacker blends in.** Same benign traffic; each level adds to the previous one (and slows the attacker).")
        fig = go.Figure()
        for key, name in LAYERS.items():
            y = [rob["results"][str(x)][key]["incident_recall"] * 100 for x in lv]
            fig.add_trace(go.Scatter(x=lv, y=y, mode="lines+markers", name=name, line=dict(color=SERIES[key], width=2),
                                     marker=dict(size=9, color=SERIES[key], line=dict(color=C.SURFACE, width=2)), hovertemplate="stealth %{x}: %{y:.0f}% (" + name + ")<extra></extra>"))
        C.style_fig(fig, height=340)
        fig.update_yaxes(range=[0, 105], title_text="incident recall (%)")
        fig.update_xaxes(tickvals=lv, ticktext=[f"{x}<br><span style='font-size:10px'>{rob['notes'].get(str(x), '')}</span>" for x in lv], title_text="attacker stealth")
        st.plotly_chart(fig, width="stretch", key="q_rob")
        sc = sorted(Cm["per_scenario"])
        z = [[rob["results"][str(x)]["combined"]["recall_by_scenario"].get(s, 0) * 100 for s in sc] for x in lv]
        hm = go.Figure(go.Heatmap(z=z, x=sc, y=[f"stealth {x}" for x in lv], zmin=0, zmax=100, colorscale=[[0, "#242423"], [0.5, "#1c5cab"], [1, "#86b6ef"]],
                                  text=[[f"{v:.0f}%" for v in r] for r in z], texttemplate="%{text}", textfont=dict(color=C.INK, size=12),
                                  colorbar=dict(title="recall %", tickfont=dict(color=C.INK2)), xgap=2, ygap=2, hovertemplate="%{y} · %{x}: %{z:.0f}%<extra></extra>"))
        C.style_fig(hm, height=60 + 52 * len(lv), legend=False)
        hm.update_yaxes(autorange="reversed")
        st.markdown("**Combined detector, per scenario**")
        st.plotly_chart(hm, width="stretch", key="q_heat")
        st.caption("Stealth levels: " + " · ".join(f"**{x}** {rob['notes'].get(str(x), '')}" for x in lv) + ". All levels slow the attacker by 1 + 20×stealth. S9 (impossible travel) is not affected by the stealth setting because its geography is the attack, "
                   "so its flat column is not evidence of robustness. Only S1 (a few read-only calls with valid credentials) becomes hard to see.")

with t5:
    if not live:
        st.info("Run `python scripts/run_live.py --speed 150 --sim-hours 3 --inject S1+S2+S3+S4+S5@1500` for real-time numbers.")
    else:
        a, b, c, d = st.columns(4)
        a.metric("Injections detected", f"{live['detected']}/{live['injections']}")
        b.metric("Time to detect p50 / p95", f"{live['ttd_sim_p50_s']:.0f} / {live['ttd_sim_p95_s']:.0f} s")
        c.metric("Pipeline latency p50", f"{live['pipeline_latency_p50_ms']:.0f} ms")
        d.metric("Pipeline latency p95", f"{live['pipeline_latency_p95_ms']:.0f} ms")
        st.dataframe(pd.DataFrame(live["per_injection"]), hide_index=True, width="stretch")
        st.caption("Measured headless at real-time replay speed; latency rises when the dashboard renders in the same process.")
