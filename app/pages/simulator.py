import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import json

import pandas as pd
import streamlit as st

from app import common as C
from app import data as D
from src.generator.attacks import SCEN

C.sidebar()
st.title("Attack Simulator")
st.caption("Inject a labeled attack into the live stream, then compare what was injected (ground truth) with what the detectors found. "
           "The detectors never see the labels.")
eng = C.engine()

PRESETS = {
    "Compromised access key → privilege escalation → disable CloudTrail": "S1+S3+S4",
    "Full kill chain: key theft → recon → privesc → evasion → exfiltration": "S1+S2+S3+S4+S5",
    **{f"{k}: {v['name']}": k for k, v in SCEN["scenarios"].items()},
}
c1, c2 = st.columns([3, 2])
with c1:
    choice = st.selectbox("Scenario", list(PRESETS), key="sim_scenario")
    spec = PRESETS[choice]
    st.caption("Steps: " + " → ".join(f"{s} ({SCEN['scenarios'][s]['name']})" for s in spec.split("+")))
with c2:
    victims = ["(random)"] + sorted(p.name for p in eng.runner.eligible_victims())
    victim = st.selectbox("Target identity", victims, key="sim_victim")
d1, d2 = st.columns(2)
speed = d1.select_slider("Attacker pace", [1, 2, 5, 10, 30], value=1, key="sim_speed", help="Divides the gaps between attacker actions (1 = realistic).")
stealth = d2.slider("Stealth", 0.0, 1.0, 0.0, 0.1, key="sim_stealth",
                    help="At 0.5 and above the attacker blends in (victim's usual region/user agent, same-country IP) and moves slowly. Expect lower detection.")
if st.button("💥 Inject attack", type="primary"):
    ids = eng.inject(spec, victim=None if victim == "(random)" else victim, stealth=stealth, speed=float(speed))
    st.success(f"Injected {spec} → {', '.join(ids)}. Events appear in the stream at the current simulated time.")


@st.fragment(run_every=3)
def results() -> None:
    cur = C.cur()
    inj = D.simulator_injections(cur)
    st.subheader("Ground truth vs detection")
    if inj.empty:
        st.info("Nothing injected yet.")
        return
    show = pd.DataFrame({
        "Injection": inj["injection_id"], "Scenario": inj["scenario_id"], "Victim": inj["victim"], "Attacker IP": inj["attacker_ip"],
        "Malicious events": inj["n_events"], "Starts (sim)": inj["start_time"],
        "Detected": inj["detected_by"].map(lambda x: "✓ " + x if isinstance(x, str) else "… waiting"),
        "Time to detect (sim s)": inj["ttd_sim_s"].round(0), "Pipeline latency (ms)": inj["pipeline_latency_ms"].round(0)})
    sel = st.dataframe(show, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row", key="sim_table",
                       column_config={"Starts (sim)": st.column_config.DatetimeColumn(format="HH:mm:ss")})
    det = inj["detected_by"].notna().sum()
    st.caption(f"{det}/{len(inj)} injections detected so far. Anomaly-layer detections fire when a 15-minute window completes, so they can lag rule hits.")
    if sel.selection.rows:
        row = inj.iloc[sel.selection.rows[0]]
        lab = D.df(cur, """SELECT e.event_time, e.event_name, e.source_ip, e.error_code, l.technique, l.mitre_tactic, e.event_id
                           FROM labels l JOIN events e USING (event_id) WHERE l.injection_id = ? AND l.is_malicious ORDER BY e.event_time""", [row["injection_id"]])
        al = D.df(cur, "SELECT alert_id, rule_id, source, matched_event_ids, event_id, incident_id FROM alerts")
        cover: dict[str, str] = {}
        for a in al.itertuples():
            for e in set(json.loads(a.matched_event_ids or "[]")) | {a.event_id}:
                cover.setdefault(e, a.rule_id)
        lab["Detected by"] = lab["event_id"].map(lambda e: "✓ " + cover[e] if e in cover else "✗ not flagged")
        n_cov = lab["Detected by"].str.startswith("✓").sum()
        st.markdown(f"**{row['injection_id']}** — {n_cov}/{len(lab)} malicious events covered by at least one alert")
        st.dataframe(lab.drop(columns=["event_id"]), hide_index=True, width="stretch", height=300,
                     column_config={"event_time": st.column_config.DatetimeColumn("Time", format="HH:mm:ss"), "event_name": "Event", "source_ip": "IP",
                                    "error_code": "Error", "technique": "MITRE technique", "mitre_tactic": "Tactic"})
        if isinstance(row["first_alert_id"], str):
            inc = cur.execute("SELECT incident_id FROM alerts WHERE alert_id = ?", [row["first_alert_id"]]).fetchone()
            if inc and inc[0] and st.button(f"Open incident {inc[0]} →"):
                C.go("pages/investigation.py", selected_incident=inc[0])


results()
