"""Shared dashboard plumbing: engine singleton, theme (validated palette), severity chips, sidebar."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import pandas as pd
import streamlit as st

from app import data
from src.detection.iforest import AnomalyModel
from src.detection.triage import SuppressionList
from src.pipeline.live import LiveEngine

# ---- palette (dataviz reference instance, dark surface #1a1a19). Categorical slots 1-3 validate all-pairs; severity uses the fixed status steps.
BLUE, ORANGE, AQUA = "#3987e5", "#d95926", "#199e70"
INK, INK2, MUTED, GRID, SURFACE = "#f0efec", "#c3c2b7", "#8c8b84", "#2f2f2d", "#1a1a19"
SEV_COLOR = {"LOW": "#9a99a6", "MEDIUM": "#fab219", "HIGH": "#ec835a", "CRITICAL": "#d03b3b"}
SEV_SYMBOL = {"LOW": "○", "MEDIUM": "●", "HIGH": "▲", "CRITICAL": "◆"}
FLAG_COLOR = {**SEV_COLOR, "ANOMALOUS WINDOW": BLUE, "CONTEXT": "#5c5b57"}


def sev_label(sev: str) -> str:
    return f"{SEV_SYMBOL.get(sev, '·')} {sev}"


def sev_chip(sev: str) -> str:
    c = SEV_COLOR.get(sev, MUTED)
    return (f'<span style="display:inline-block;border:1px solid {c};border-radius:12px;padding:1px 10px;font-size:0.85rem;'
            f'color:{INK};white-space:nowrap"><span style="color:{c}">{SEV_SYMBOL.get(sev, "·")}</span> {sev}</span>')


def tactic_chain(tactics: list[str]) -> str:
    if not tactics:
        return "<span style='color:%s'>no MITRE tactic mapped</span>" % MUTED
    chips = [f'<span style="border:1px solid {MUTED};border-radius:6px;padding:2px 8px;color:{INK};white-space:nowrap">{t}</span>' for t in tactics]
    return f' <span style="color:{MUTED}">→</span> '.join(chips)


def style_fig(fig, height: int = 320, legend: bool = True):
    fig.update_layout(height=height, paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color=INK2, size=12),
                      margin=dict(l=10, r=10, t=30, b=10), showlegend=legend,
                      legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, font=dict(color=INK2)),
                      hoverlabel=dict(bgcolor="#242423", font_color=INK, bordercolor=MUTED))
    fig.update_xaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=MUTED))
    fig.update_yaxes(gridcolor=GRID, zeroline=False, linecolor=GRID, tickfont=dict(color=MUTED))
    return fig


# ------------------------------------------------------------------------------------------------ engine
def _env(name: str, default):
    v = os.environ.get(name)
    return type(default)(v) if v not in (None, "") and default is not None else (v if v not in (None, "") else default)


@st.cache_resource(show_spinner="Starting the detection engine…")
def get_engine(token: int = 0) -> LiveEngine:
    """One engine per server process (DuckDB allows a single writer, so the dashboard hosts the pipeline). `token` forces a restart."""
    models = Path(_env("CTD_MODELS", "models"))
    if not (models / "baseline.joblib").exists():
        raise FileNotFoundError(f"{models}/baseline.joblib not found. Run `python scripts/train.py` first (see README).")
    base = joblib.load(models / "baseline.joblib")
    mp = models / "anomaly_global.joblib"
    model = AnomalyModel.load(mp) if mp.exists() and _env("CTD_NO_ANOMALY", "") == "" else None
    sim_hours = _env("CTD_SIM_HOURS", 0.0)
    from datetime import datetime, timedelta
    start, hour = _env("CTD_START", "2025-01-13"), _env("CTD_START_HOUR", 9.0)
    until = datetime.strptime(start, "%Y-%m-%d") + timedelta(hours=hour + sim_hours) if sim_hours else None
    eng = LiveEngine(_env("CTD_DB", "data/live.duckdb"), base, model, speed=_env("CTD_SPEED", 120.0), scale=_env("CTD_SCALE", 0.3),
                     world_seed=_env("CTD_WORLD_SEED", 42), start=start, start_hour=hour, days=_env("CTD_DAYS", 2), until=until,
                     suppressions=SuppressionList(path=_env("CTD_SUPPRESSIONS", "data/suppressions.json")))
    return eng.start()


def engine() -> LiveEngine:
    return get_engine(st.session_state.get("engine_token", 0))


def cur():
    return engine().cursor()


def restart_engine() -> None:
    old = engine()
    old.stop()
    get_engine.clear()
    st.session_state["engine_token"] = st.session_state.get("engine_token", 0) + 1


SPEEDS = [1, 10, 60, 120, 300, 600, 1800, 3600]


def sidebar() -> None:
    """Engine status + controls, shown on every page."""
    eng = engine()
    s = eng.stats()
    with st.sidebar:
        st.markdown("### Pipeline")
        state = "ended" if s["finished"] and s["backlog"] == 0 else ("paused" if eng.streamer.paused.is_set() else "live")
        st.markdown(f"**Simulated time (UTC)**  \n`{pd.Timestamp(s['sim_now']):%Y-%m-%d %H:%M:%S}` · {state}")
        st.caption(f"{s['events']:,} events processed · backlog {s['backlog']} · {s['alerts']} alerts")
        cur_speed = int(s["speed"]) if s["speed"] in SPEEDS else 120
        sp = st.select_slider("Replay speed (sim s per real s)", SPEEDS, value=cur_speed, key="speed_sel")
        if sp != s["speed"]:
            eng.set_speed(float(sp))
        c1, c2 = st.columns(2)
        if c1.button("⏸ Pause" if not eng.streamer.paused.is_set() else "▶ Resume", width="stretch"):
            (eng.streamer.paused.clear if eng.streamer.paused.is_set() else eng.streamer.paused.set)()
            st.rerun()
        if c2.button("↻ Restart", width="stretch", help="Discard the current session and start a fresh simulated stream"):
            restart_engine()
            st.rerun()
        if eng.detector.error:
            st.error(f"Detector stopped: {eng.detector.error}")


def go(page: str, **state) -> None:
    for k, v in state.items():
        st.session_state[k] = v
    st.switch_page(page)
