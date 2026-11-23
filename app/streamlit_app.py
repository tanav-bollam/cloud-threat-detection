"""Entrypoint:  streamlit run app/streamlit_app.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import streamlit as st

st.set_page_config(page_title="Cloud Threat Detection", page_icon=":material/shield:", layout="wide")

pages = [
    st.Page("pages/overview.py", title="Overview", icon=":material/dashboard:", default=True),
    st.Page("pages/incidents.py", title="Alerts & Incidents", icon=":material/notifications_active:"),
    st.Page("pages/investigation.py", title="Incident Investigation", icon=":material/search_insights:"),
    st.Page("pages/forensics.py", title="Forensics Search", icon=":material/manage_search:"),
    st.Page("pages/simulator.py", title="Attack Simulator", icon=":material/bug_report:"),
    st.Page("pages/quality.py", title="Detection Quality", icon=":material/monitoring:"),
    st.Page("pages/realdata.py", title="Real Data", icon=":material/public:"),
    st.Page("pages/settings.py", title="Settings", icon=":material/settings:"),
]
st.navigation(pages).run()
