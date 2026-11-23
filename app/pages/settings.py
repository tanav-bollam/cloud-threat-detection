import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import streamlit as st

from app import common as C
from src import settings as S
from src.detection.rules_engine import load_rules
from src.integrations.webhook import WebhookNotifier, valid_url

C.sidebar()
st.title("Settings")
st.caption("Changes apply immediately to the running pipeline and are saved to `data/settings.json`. They affect alerts raised from now on; existing alerts are not rewritten.")
eng = C.engine()
cur = S.load()

# ---------------------------------------------------------------------------------- rules
st.subheader("Detection rules")
rules = sorted(load_rules(), key=lambda r: r.id)
tbl = pd.DataFrame([{"Enabled": r.id not in cur.disabled_rules, "ID": r.id, "Severity": r.severity, "Tactic": r.mitre_tactic, "Title": r.title} for r in rules])
edited = st.data_editor(tbl, hide_index=True, width="stretch", height=330, key="rules_editor", disabled=["ID", "Severity", "Tactic", "Title"],
                        column_config={"Enabled": st.column_config.CheckboxColumn("Enabled", help="Untick to stop this rule from raising alerts")})
st.caption(f"{int(edited['Enabled'].sum())} of {len(rules)} rules enabled.")

# ---------------------------------------------------------------------------------- grouping + anomaly
c1, c2 = st.columns(2)
with c1:
    st.subheader("Alert deduplication")
    dedupe = st.number_input("Fold repeats within (seconds)", min_value=0.0, max_value=86400.0, value=float(cur.dedupe_s), step=60.0, key="set_dedupe",
                             help="Single-event rules: repeats of the same rule by the same identity and IP inside this window become one alert that still lists every matched event. 0 turns it off.")
with c2:
    st.subheader("Anomaly sensitivity")
    sens = st.slider("Threshold offset", -0.15, 0.15, float(cur.anomaly_sensitivity), 0.01, key="set_sens",
                     help="Added to the calibrated IsolationForest threshold. Negative = more sensitive (more alerts, more false positives); positive = quieter.")
    if eng.model is not None:
        thr = {k: round(getattr(u, "_base_threshold", u.threshold), 4) for k, u in eng.model.units.items()}
        st.caption("Calibrated thresholds: " + ", ".join(f"{k}: {v}" for k, v in thr.items()) + f" · effective offset {sens:+.2f}")
    else:
        st.caption("The anomaly layer is off in this session.")

# ---------------------------------------------------------------------------------- webhook
st.subheader("Alert webhook (optional)")
import os

env_locked = bool(os.environ.get("CTD_WEBHOOK_URL"))
w1, w2 = st.columns([3, 1])
url = w1.text_input("Discord / Slack / generic webhook URL", value=cur.webhook_url, type="password", key="set_url", disabled=env_locked,
                    help="A free incoming-webhook URL. Leave empty to disable. Set the CTD_WEBHOOK_URL environment variable to keep it out of the settings file.")
sev = w2.selectbox("Send at or above", ["LOW", "MEDIUM", "HIGH", "CRITICAL"], index=["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(cur.webhook_min_severity), key="set_sev")
st.warning("With a real webhook, alert details (title, identity, IP, MITRE tactic) leave this machine. The simulated data here is synthetic, but point this only at a channel you control.")
if env_locked:
    st.info("The webhook URL is provided by the `CTD_WEBHOOK_URL` environment variable.")
n = getattr(eng, "_webhook", None)
if n is not None:
    st.caption(f"Active ({n.kind}) · sent {n.stats['sent']} · failed {n.stats['failed']} · below threshold {n.stats['skipped_below_threshold']} · rate-limited {n.stats['dropped_rate_limit']}"
               + (f" · last error: {n.stats['last_error']}" if n.stats["last_error"] else ""))
if st.button("Send a test message", disabled=not (url or env_locked)):
    if not valid_url(url or os.environ.get("CTD_WEBHOOK_URL", "")):
        st.error("Webhook URL must start with http:// or https://")
    else:
        tester = WebhookNotifier(url or os.environ["CTD_WEBHOOK_URL"], sev)
        ok, detail = tester.send_test()
        tester.close()
        (st.success if ok else st.error)("Test message sent." if ok else f"Test failed: {detail}")

# ---------------------------------------------------------------------------------- save
b1, b2, _ = st.columns([1, 1, 3])
if b1.button("Save & apply", type="primary"):
    new = S.Settings(disabled_rules=sorted(edited.loc[~edited["Enabled"], "ID"]), dedupe_s=float(dedupe), anomaly_sensitivity=float(sens),
                     webhook_url=url if not env_locked else "", webhook_min_severity=sev)
    errs = new.validate()
    if errs:
        for e in errs:
            st.error(e)
    else:
        S.save(new)
        warns = S.apply(eng, S.load())
        for w in warns:
            st.warning(w)
        st.success("Saved and applied.")
if b2.button("Reset to defaults"):
    S.save(S.Settings())
    S.apply(eng, S.load())
    st.rerun()
