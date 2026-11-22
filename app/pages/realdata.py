import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from app import common as C

C.sidebar()
st.title("Real Data")
st.caption("The detectors run against real public CloudTrail logs the project did not generate. Read from `reports/real_data.json`; "
           "regenerate with `scripts/load_flaws.py` then `scripts/validate_real.py`. Full write-up: `docs/REAL_DATA_FINDINGS.md`.")


@st.cache_data(show_spinner=False)
def load(mtime: float):
    p = C.ROOT / "reports" / "real_data.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


p = C.ROOT / "reports" / "real_data.json"
d = load(p.stat().st_mtime if p.exists() else 0.0)
if not d:
    st.warning("No real-data results yet. Run `python scripts/load_flaws.py` and `python scripts/validate_real.py` (see the README).")
    st.stop()

st.info("Geolocation is switched off for all real data (the synthetic registry is made up and the published IPs are anonymized), so country/travel signals are silent here by design.")
t1, t2, t3, t4 = st.tabs(["Stratus technique coverage", "flaws.cloud", "Invictus-IR & SANS", "How to read this"])

with t1:
    s = d["stratus"]
    b, a = s["before"], s["after"]
    c = st.columns(4)
    if b:
        c[0].metric("Technique-specific coverage, before", f"{b['covered_specific']}/{b['techniques']} ({b['covered_specific']/b['techniques']*100:.0f}%)",
                    help=f"{b['rules_evaluated']} original rules, written without seeing real data (measured at the Phase 8 commit)")
    c[1].metric("After (post-hoc)", f"{a['covered_specific']}/{a['techniques']} ({a['covered_specific']/a['techniques']*100:.0f}%)",
                help=f"{a['rules_evaluated']} rules: 17 were added after reading these samples, so this is a regression check, not an independent measurement")
    c[2].metric("Real techniques tested", a["techniques"])
    st.markdown("Each row is a real captured detonation of one Stratus Red Team technique. **Before** is the honest, held-out number; **after** is post-hoc.")
    rows = [{"Tactic": r["tactic"].replace("_", " "), "Technique": r["technique"].replace("aws.", ""), "Events": r["events"],
             "Before": "—" if r["before"] is None else (", ".join(sorted(r["before"])) or "✗ miss"), "After": ", ".join(sorted(r["after"])) or "✗ miss"} for r in s["rows"]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=520)
    st.caption("Generic rules R022 (user agent) and R023 (AccessDenied burst) do not count as technique-specific coverage.")

with t2:
    f = d.get("flaws")
    if not f:
        st.info("flaws.cloud was not part of this run (`--skip-flaws`, or the dataset was not loaded).")
    else:
        o, ig = f["overview"], f.get("ingest") or {}
        c = st.columns(4)
        c[0].metric("Unique events", f"{o['events']:,}", help=(f"{ig['records_seen']:,} records read; {ig['duplicates']:,} exact duplicates dropped" if ig else None))
        c[1].metric("Identities", o["identities"])
        c[2].metric("Source IPs", f"{o['source_ips']:,}")
        c[3].metric("Rule alerts (whole timeline)", f"{f['rules']['alerts']:,}")
        rr = pd.DataFrame(f["rules"]["by_rule"]).head(12)
        if not rr.empty:
            fig = go.Figure(go.Bar(y=rr["rule_id"] + " " + rr["title"].str.slice(0, 44), x=rr["alerts"], orientation="h", marker_color=C.BLUE, name="Alerts",
                                   text=rr["alerts"].map("{:,}".format), textposition="outside", textfont=dict(color=C.INK2), hovertemplate="%{y}: %{x:,} alerts<extra></extra>"))
            C.style_fig(fig, height=60 + 32 * len(rr), legend=False)
            fig.update_yaxes(autorange="reversed")
            fig.update_xaxes(title_text="alerts (after deduplication)", rangemode="tozero")
            st.markdown("**Which rules fire on real attacker traffic**")
            st.plotly_chart(fig, width="stretch", key="rd_rules")
        sg = f.get("surge")
        if sg:
            st.markdown(f"**Independent check: the {sg['month']} surge.** {sg['events_in_month']:,} events in one month, {sg['x_median']}× the median, "
                        f"dominated by `{sg['dominant_identity']}` calling `{sg['dominant_event']}` ({sg['dominant_events']:,} calls across {sg['regions_touched']} regions). "
                        "Found from raw counts, not labels; the model was trained only on history before it.")
            ml = f.get("ml")
            if ml:
                lay = pd.DataFrame([{"Layer": k, "Incidents/day": v["incidents_per_day"], "Surge events covered %": v["surge_events_covered_pct"],
                                     "Detected": "yes" if v["surge_detected"] else "no", "Onset → first alert (min)": v["minutes_from_onset_to_first_alert"]} for k, v in ml["by_layer"].items()])
                st.dataframe(lay, hide_index=True, width="stretch")
                if ml["top_incidents"]:
                    st.markdown("**Highest-risk incidents (combined layers)**")
                    st.dataframe(pd.DataFrame([{"Severity": C.sev_label(i["severity"]), "Risk": i["risk"], "Identities": ", ".join(i["identities"]), "First seen": i["first_seen"][:16],
                                                "Tactics": " → ".join(i["tactics"]), "Layers": ", ".join(i["sources"]), "Alerts": i["alerts"]} for i in ml["top_incidents"]]),
                                 hide_index=True, width="stretch")
                if ml["top_anomalies_outside_surge"]:
                    st.markdown("**Strongest anomaly windows outside the surge month** (with SHAP reasons)")
                    st.dataframe(pd.DataFrame(ml["top_anomalies_outside_surge"]), hide_index=True, width="stretch")

with t3:
    for key, title in (("invictus", "Invictus-IR: 32 Stratus attacks in one account"), ("sans", "SANS-504 S3 ransomware lab")):
        x = d.get(key)
        if not x:
            continue
        o = x["overview"]
        st.subheader(title)
        c = st.columns(4)
        c[0].metric("Unique events", f"{o['events']:,}")
        c[1].metric("Identities", o["identities"])
        c[2].metric("Rule alerts", x["alerts"])
        c[3].metric("Events covered by an alert", f"{x['alerted_events']:,}")
        st.dataframe(pd.DataFrame(x["rules"]).drop(columns=["tactic", "first", "last", "sample_event"], errors="ignore"), hide_index=True, width="stretch", height=260)
        if x["high_risk_gap"]:
            st.markdown("High-risk APIs seen but **not** alerted (candidate gaps, or benign activity):")
            st.dataframe(pd.DataFrame(x["high_risk_gap"]), hide_index=True, width="stretch")

with t4:
    st.markdown("""
- **Synthetic recall does not transfer.** The rules caught everything the generator produced and a minority of real Stratus techniques. The *before* number is the honest one.
- **The 'after' coverage is post-hoc.** The 17 added rules were written after reading these samples, so they are a regression check, not an independent measurement.
- **flaws.cloud is unlabeled.** The surge check is one event visible in raw monthly counts; it says the detectors notice a large known abuse burst, not how often they catch the next one.
- **Real exports are messy.** Duplicates (37% of flaws.cloud records), missing fields, odd identity types, IPv6, anonymized fake regions. The ingestor and detectors are fuzz-tested against these.
- **Two shipped rules were wrong on real record shapes** (R017, R009); synthetic data could not reveal that.
""")
