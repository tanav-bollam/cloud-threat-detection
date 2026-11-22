import json
from pathlib import Path

from streamlit.testing.v1 import AppTest

ROOT = Path(__file__).resolve().parents[1]


def fake_real():
    row = lambda t, tech, before, after, spec: {"tactic": t, "technique": tech, "events": 3, "event_names": ["X"], "before": before, "after": after, "after_specific": spec, "rule_titles": {}}
    small = lambda name: {"name": name, "ingest": {"records_seen": 120, "inserted": 100, "skipped_invalid": 0, "duplicates": 20},
                          "overview": {"events": 100, "identities": 4, "source_ips": 3, "user_agents": 2, "first": "2023-07-10 11:00:00", "last": "2023-07-10 12:00:00",
                                       "identity_types": {"IAMUser": 100}, "top_events": [["GetUser", 50]], "top_identities": [["bob", 60]], "error_events": 1},
                          "home_region_assumed": "us-east-1", "alerts": 7, "alerted_events": 9,
                          "rules": [{"rule_id": "R001", "title": "CloudTrail logging stopped", "severity": "CRITICAL", "tactic": "Defense Evasion", "alerts": 7, "identities": 1,
                                     "top_identity": "bob", "first": "2023-07-10T11:00:00Z", "last": "2023-07-10T11:30:00Z", "sample_event": "StopLogging"}],
                          "high_risk_gap": [{"event_name": "DeleteBucket", "events": 8, "alerted": 0}]}
    layer = lambda inc: {"alerts": 10, "incidents": inc, "incidents_per_day": 0.42, "surge_events_covered": 900, "surge_events_covered_pct": 77.7, "surge_detected": True, "minutes_from_onset_to_first_alert": 12.5}
    return {"sources": {"samples_repo": "https://example.org/samples", "flaws_tar": "https://example.org/flaws.tar", "flaws_blog": "https://example.org/blog"},
            "samples_commit": "abc1234", "flaws_integrity": {"tar_bytes": 1000, "members": 20, "identical_to_repo_copy": 20},
            "stratus": {"before": {"techniques": 35, "covered_specific": 12, "covered_any": 14, "rules_evaluated": 24, "measured_at_commit": "18f7504 (before)"},
                        "after": {"techniques": 35, "covered_specific": 33, "covered_any": 33, "rules_evaluated": 41},
                        "rows": [row("defense_evasion", "aws.defense-evasion.cloudtrail-stop", {"R001": 1}, {"R001": 1}, ["R001"]),
                                 row("persistence", "aws.persistence.lambda-overwrite-code", {}, {}, [])]},
            "invictus": small("invictus"), "sans": small("sans"),
            "flaws": {"overview": {"events": 1225784, "identities": 88, "source_ips": 9402, "user_agents": 8812, "first": "2017-02-12 19:57:06", "last": "2020-10-07 21:03:30",
                                   "identity_types": {}, "top_events": [["RunInstances", 708270]], "top_identities": [["backup", 580860]], "error_events": 5},
                      "ingest": {"records_seen": 1939207, "inserted": 1225784, "skipped_invalid": 0, "duplicates": 713423}, "monthly_median_events": 8000.0,
                      "rules": {"alerts": 4321, "seconds": 50, "by_rule": [{"rule_id": "R015", "title": "Large or GPU instance launched", "severity": "MEDIUM", "tactic": "Impact", "alerts": 4000,
                                                                         "identities": 2, "top_identity": "Level6", "first": "2018-07-03T00:00:00Z", "last": "2020-09-22T00:00:00Z", "sample_event": "RunInstances"}]},
                      "surge": {"month": "2019-08", "events_in_month": 710859, "x_median": 88.9, "dominant_identity": "backup", "dominant_event": "RunInstances", "dominant_events": 700000,
                                "onset": "2019-08-03 01:02:03", "regions_touched": 16, "errors_share": 0.95},
                      "ml": {"training_windows": 5000, "calibration_windows": 900, "calibration_fp_per_day_target": 0.5, "train_period": "2017-02-12 -> 2019-05-01", "scored_period": "2019-08-01 -> 2020-10-07",
                             "scored_days": 433, "scored_windows": 20000, "flagged_windows": 321, "by_layer": {"rules": layer(5), "anomaly": layer(6), "ip": layer(1), "combined": layer(9)},
                             "top_incidents": [{"severity": "HIGH", "risk": 77.0, "title": "t", "identities": ["backup"], "first_seen": "2019-08-03T01:00:00Z", "tactics": ["Impact"], "sources": ["rule", "anomaly"], "alerts": 4}],
                             "top_anomalies_outside_surge": [{"identity": "Level6", "when": "2020-01-01T00:00:00Z", "score": 0.7, "margin": 0.1, "reasons": "volume_z=9 (+1.2)", "events_in_window": 40, "identity_most_common_event": "GetPolicyVersion"}],
                             "flagged_windows_in_surge_month": 200}}}


def test_real_findings_md_numbers_come_from_json(tmp_path, monkeypatch):
    import scripts.make_results as MR
    import scripts.real_findings as RF
    (tmp_path / "real_data.json").write_text(json.dumps(fake_real()))
    monkeypatch.setattr(MR, "REPORTS", tmp_path)
    md = RF.real_md()
    for needle in ("12/35 (34%)", "33/35 (94%)", "713,423", "37%", "1,225,784", "88.9", "2019-08", "77.7", "abc1234", "20/20", "post-hoc", "R017", "lambda-overwrite-code", "DeleteBucket"):
        assert needle in md, needle


def test_real_findings_md_without_data_is_a_pointer(tmp_path, monkeypatch):
    import scripts.make_results as MR
    import scripts.real_findings as RF
    monkeypatch.setattr(MR, "REPORTS", tmp_path)
    assert "No real-data run yet" in RF.real_md()


def test_real_data_page_renders_and_handles_missing(dash_engine, tmp_path, monkeypatch):
    from app import common as C
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "real_data.json").write_text(json.dumps(fake_real()))
    monkeypatch.setattr(C, "ROOT", tmp_path)
    at = AppTest.from_file(str(ROOT / "app" / "pages" / "realdata.py"), default_timeout=60).run()
    assert not at.exception, at.exception
    vals = {m.label: m.value for m in at.metric}
    assert vals["Technique-specific coverage, before"] == "12/35 (34%)" and vals["After (post-hoc)"] == "33/35 (94%)"
    assert any("1,225,784" in m.value for m in at.metric)
    monkeypatch.setattr(C, "ROOT", tmp_path / "nowhere")
    at2 = AppTest.from_file(str(ROOT / "app" / "pages" / "realdata.py"), default_timeout=60).run()
    assert not at2.exception and any("No real-data results yet" in w.value for w in at2.warning)
