import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from src.evaluation import _prf, scenario_prf
from src.pipeline import storage

ROOT = Path(__file__).resolve().parents[1]


def test_prf_math():
    assert _prf(5, 5, 0) == {"precision": 0.5, "recall": 1.0, "f1": 0.667, "tp": 5, "fp": 5, "fn": 0}
    assert _prf(0, 0, 0)["f1"] == 0.0 and _prf(0, 3, 2)["precision"] == 0.0


def inc(ids):
    return SimpleNamespace(matched_event_ids=ids)


def test_scenario_prf_hand_computed(tmp_path):
    con = storage.connect(tmp_path / "t.duckdb")
    lab = lambda e, s, i: {"event_id": e, "is_malicious": True, "scenario_id": s, "injection_id": i, "technique": "T", "mitre_tactic": "X"}
    storage.insert_labels(con, [lab("m1", "S3", "A"), lab("m2", "S3", "A"), lab("m3", "S4", "B"),
                                {"event_id": "b1", "is_malicious": False, "scenario_id": None, "injection_id": None, "technique": None, "mitre_tactic": None}])
    alerts = pd.DataFrame([{"event_id": "m1", "matched_event_ids": ["m1", "b1"]}, {"event_id": "b2", "matched_event_ids": ["b2"]}])
    out = scenario_prf(alerts, [inc(["m1", "b1"]), inc(["b2"])], con)
    # predicted events = {m1, b1, b2}; malicious = {m1, m2, m3}; FP events = {b1, b2}
    s3, s4 = out["S3"], out["S4"]
    assert (s3["event"]["tp"], s3["event"]["fp"], s3["event"]["fn"]) == (1, 2, 1)
    assert (s3["incident"]["tp"], s3["incident"]["fp"], s3["incident"]["fn"]) == (1, 1, 0) and s3["detected"] == 1
    assert (s4["event"]["tp"], s4["event"]["fn"]) == (0, 1) and s4["incident"]["recall"] == 0.0 and s4["detected"] == 0


# ---------------------------------------------------------------------------------------------- generated docs
def fake_layer(recall, fp):
    ps = {s: {"event": {"precision": 0.5, "recall": 1.0, "f1": 0.667}, "incident": {"precision": 0.5, "recall": recall, "f1": 0.6}, "injections": 4, "detected": 3} for s in ("S1", "S2")}
    return {"alerts": 10, "alert_injection_recall": recall, "event_level": {"precision": 0.91, "recall": 0.92, "f1": 0.9}, "ttd_p50_s": 12.0, "ttd_p95_s": 345.0, "ttd_sim_s": [0.0, 5.0, 300.0],
            "test_week": {"injection_recall": recall, "incident_precision": 0.77, "tp_incidents": 7, "fp_incidents": 2, "chains": 3, "chains_in_single_incident": 2,
                          "recall_by_scenario": {"S1": recall, "S2": recall}},
            "per_scenario": ps, "benign_week": {"incidents": 5, "fp_incidents_per_day": fp, "fp_high_or_critical_per_day": 0.0, "alerts_per_day": 9.0}}


def fake_metrics(recall=0.8123, fp=7.77):
    names = ["rules_only", "anomaly_only", "ip_only", "rules+ip", "rules+anomaly", "combined"]
    return {"mode": "global", "test_days": 7.0, "val_days": 7.0, "injections": 42, "detector_config": {"target_fp_windows_per_day": 6},
            "layers": {n: fake_layer(recall, fp) for n in names}}


def test_results_md_numbers_come_from_the_json(tmp_path, monkeypatch):
    import scripts.make_results as MR
    (tmp_path / "metrics.json").write_text(json.dumps(fake_metrics()))
    (tmp_path / "robustness.json").write_text(json.dumps({"levels": [0.0, 0.9], "notes": {"0.0": "noisy", "0.9": "careful"}, "results": {
        "0.0": {k: {"incident_recall": 0.99, "recall_by_scenario": {"S1": 1.0, "S2": 0.98}, "ttd_p50_s": 1.0} for k in ("rules_only", "anomaly_only", "ip_only", "combined")},
        "0.9": {k: {"incident_recall": 0.1234, "recall_by_scenario": {"S1": 0.1, "S2": 0.2}, "ttd_p50_s": 99.0} for k in ("rules_only", "anomaly_only", "ip_only", "combined")}}}))
    monkeypatch.setattr(MR, "REPORTS", tmp_path)
    md = MR.results_md()
    for needle in ("7.77", "81.2%", "12.3%", "2/3", "42 injected attack stages", "345", "Do not edit by hand", "Caveats"):
        assert needle in md, needle
    assert "Live pipeline" not in md                     # no live_ttd.json -> section omitted, not invented


def test_results_md_without_metrics_is_a_pointer_not_numbers(tmp_path, monkeypatch):
    import scripts.make_results as MR
    monkeypatch.setattr(MR, "REPORTS", tmp_path)
    assert "No metrics yet" in MR.results_md()


def test_detections_md_covers_every_rule_and_layer():
    import scripts.make_results as MR
    from src.detection.features import FEATURES
    from src.detection.rules_engine import load_rules
    md = MR.detections_md()
    for r in load_rules():
        assert r.id in md and r.title in md
    for rid in ("IP001", "IP002", "IP003", "IP004"):
        assert rid in md
    for f in FEATURES:
        assert f"`{f}`" in md


# ---------------------------------------------------------------------------------------------- page
def test_quality_page_renders_with_metrics(dash_engine, tmp_path, monkeypatch):
    from app import common as C
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "metrics.json").write_text(json.dumps(fake_metrics()))
    monkeypatch.setattr(C, "ROOT", tmp_path)
    at = AppTest.from_file(str(ROOT / "app" / "pages" / "quality.py"), default_timeout=60).run()
    assert not at.exception, at.exception
    labels = {m.label for m in at.metric}
    assert {"Attacks detected", "False-positive incidents / day", "Kill chains in one incident"} <= labels
    assert any("7.77" in str(m.value) for m in at.metric)


def test_quality_page_handles_missing_reports(dash_engine, tmp_path, monkeypatch):
    from app import common as C
    monkeypatch.setattr(C, "ROOT", tmp_path)
    at = AppTest.from_file(str(ROOT / "app" / "pages" / "quality.py"), default_timeout=60).run()
    assert not at.exception and any("No metrics yet" in w.value for w in at.warning)
