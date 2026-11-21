import inspect
import json
import time
from datetime import datetime, timedelta

import numpy as np
import pandas as pd
import pytest

from src.detection.features import FEATURES, compute_windows, fit_baseline
from src.detection.iforest import AnomalyModel
from src.detection.incidents import Incident
from src.detection.triage import Suppression, SuppressionList
from src.generator.dataset import generate_dataset
from src.pipeline import storage
from src.pipeline.live import Detector, LiveEngine

from tests.conftest import WORLD
START = datetime(2025, 1, 13, 9, 0)


def run(tmp_path, trained, name, *, speed=0.0, injections=(("S1+S3+S4", 1800),), suppressions=None, hours=3.0, anomaly=True, live_inject=None):
    base, model = trained
    eng = LiveEngine(tmp_path / f"{name}.duckdb", base, model if anomaly else None, speed=speed, scale=0.05, world_seed=WORLD, days=1,
                     until=START + timedelta(hours=hours), suppressions=suppressions, queue_size=5000)
    if speed <= 0 or live_inject is None:
        for spec, off in injections:
            eng.inject(spec, at=START + timedelta(seconds=off))
    eng.start()
    if live_inject:
        while eng.streamer.sim_now() < START + timedelta(seconds=live_inject[1]):
            time.sleep(0.01)
        eng.inject(live_inject[0])
    assert eng.wait(120), "pipeline did not finish"
    assert eng.detector.error is None
    return eng


def alert_ids(eng):
    return sorted(r[0] for r in eng.cursor().execute("SELECT alert_id FROM alerts").fetchall())


def test_replay_detects_kill_chain_and_records_everything(tmp_path, trained):
    eng = run(tmp_path, trained, "a")
    cur = eng.cursor()
    s = eng.stats()
    assert cur.execute("SELECT count(*) FROM events").fetchone()[0] == s["events"] > 0
    assert s["injections"] == 3 and s["detected_injections"] == 3
    names = {r[0] for r in cur.execute("SELECT DISTINCT rule_id FROM alerts").fetchall()}
    assert "R001" in names or "R002" in names                      # tamper rule fired
    victim = [r for r in eng.truth.inj.values()][0]["victim"]
    inc = cur.execute("SELECT severity, tactics FROM incidents WHERE identities LIKE ? ORDER BY risk_score DESC", [f'%"{victim}"%']).fetchall()
    assert inc and inc[0][0] in ("HIGH", "CRITICAL")
    tactics = json.loads(inc[0][1])
    assert "Defense Evasion" in tactics and len(tactics) >= 2
    # every alert row is attached to an incident
    assert cur.execute("SELECT count(*) FROM alerts WHERE incident_id IS NULL").fetchone()[0] == 0


def test_ground_truth_written_separately_and_ttd_recorded(tmp_path, trained):
    eng = run(tmp_path, trained, "b")
    cur = eng.cursor()
    mal = cur.execute("SELECT count(*) FROM labels WHERE is_malicious").fetchone()[0]
    assert mal == sum(r["n_events"] for r in eng.truth.inj.values())
    assert cur.execute("SELECT count(*) FROM ttd").fetchone()[0] == 3
    for sim, wall, lat in cur.execute("SELECT ttd_sim_s, ttd_wall_s, pipeline_latency_ms FROM ttd").fetchall():
        assert 0 <= sim < 3600 and wall >= 0 and lat >= 0


def test_detector_class_never_references_ground_truth():
    src = inspect.getsource(Detector)
    for word in ("truth", "labels", "injection", "is_malicious", "scenario_id"):
        assert word not in src, f"Detector references {word}"


def test_results_independent_of_replay_speed_and_deterministic(tmp_path, trained):
    a = alert_ids(run(tmp_path, trained, "d0", speed=0.0))
    b = alert_ids(run(tmp_path, trained, "d1", speed=0.0))
    c = alert_ids(run(tmp_path, trained, "d2", speed=20000.0))
    assert a and a == b == c


def test_live_injection_while_streaming(tmp_path, trained):
    eng = run(tmp_path, trained, "live", speed=900.0, injections=(), live_inject=("S4", 1200), hours=2.0)
    cur = eng.cursor()
    assert eng.stats()["injections"] == 1 and eng.stats()["detected_injections"] == 1
    sim, wall, lat = cur.execute("SELECT ttd_sim_s, ttd_wall_s, pipeline_latency_ms FROM ttd").fetchone()
    assert sim < 120 and lat < 5000
    assert cur.execute("SELECT count(*) FROM alerts WHERE rule_id IN ('R001','R002','R003','R004')").fetchone()[0] >= 1


def test_suppression_filters_alerts_and_counts_them(tmp_path, trained):
    base = run(tmp_path, trained, "s0", anomaly=False)
    n_all = base.cursor().execute("SELECT count(*) FROM alerts WHERE rule_id='R022'").fetchone()[0]
    assert n_all > 0
    sl = SuppressionList([Suppression("R022")])
    eng = run(tmp_path, trained, "s1", anomaly=False, suppressions=sl)
    assert eng.cursor().execute("SELECT count(*) FROM alerts WHERE rule_id='R022'").fetchone()[0] == 0
    assert eng.stats()["suppressed"] >= n_all


def test_mark_false_positive_updates_alert_and_adds_suppression(tmp_path, trained):
    sl = SuppressionList(path=tmp_path / "supp.json")
    eng = run(tmp_path, trained, "fp", anomaly=False, suppressions=sl)
    aid, ident = eng.cursor().execute("SELECT alert_id, identity FROM alerts WHERE source='rule' LIMIT 1").fetchone()
    eng.mark_alert(aid, "False Positive", scope="identity", note="test")
    assert eng.cursor().execute("SELECT status FROM alerts WHERE alert_id=?", [aid]).fetchone()[0] == "False Positive"
    assert any(e.identity == ident for e in sl.entries)


def test_incident_upsert_preserves_status_when_merged(tmp_path):
    con = storage.connect(tmp_path / "i.duckdb")

    def inc(iid, alerts, n):
        return Incident(iid, "t", "HIGH", 50.0, "2025-01-13T10:00:00Z", "2025-01-13T10:05:00Z", ["alice"], ["1.1.1.1"], ["Discovery"], [], alerts, ["rule"], n)

    storage.upsert_incidents(con, [inc("INC-A", ["a1"], 1)])
    con.execute("UPDATE incidents SET status='Investigating', notes='looking' WHERE incident_id='INC-A'")
    storage.upsert_incidents(con, [inc("INC-B", ["a1", "a2"], 2)])           # merged/renamed incident
    rows = con.execute("SELECT incident_id, status, notes, n_alerts FROM incidents").fetchall()
    assert rows == [("INC-B", "Investigating", "looking", 2)]


def test_streamer_emits_in_time_order(tmp_path, trained):
    eng = run(tmp_path, trained, "o", anomaly=False)
    times = [r[0] for r in eng.cursor().execute("SELECT event_time FROM events ORDER BY rowid").fetchall()]
    assert times == sorted(times)
