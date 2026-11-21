import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src.detection.explain import explain
from src.detection.features import FEATURES, compute_windows, fit_baseline
from src.detection.iforest import AnomalyModel, windows_to_alerts
from src.generator import geo

ROOT = Path(__file__).resolve().parents[1]
HOME_IP, OTHER_US_IP, LONDON_IP = "11.5.5.5", "11.6.6.6", "81.1.1.1"
UA, REGION = "aws-cli/2.15.30", "us-east-1"


def ev(i, t, ident="alice", ip=HOME_IP, name="DescribeInstances", ua=UA, region=REGION, err=None, ro=True, mgmt=True, itype="IAMUser", bytes_out=None, login=None):
    return {"event_id": f"e{i}", "event_time": pd.Timestamp(t), "event_source": "ec2.amazonaws.com", "event_name": name, "aws_region": region,
            "source_ip": ip, "user_agent": ua, "identity_type": itype, "identity": ident, "access_key_id": "AKIAX", "error_code": err,
            "read_only": ro, "management_event": mgmt, "bytes_out": bytes_out, "console_login": login}


def history():
    rows = [ev(i, f"2025-01-0{1 + i % 3} {9 + i % 8}:{(i * 7) % 60:02d}:00") for i in range(120)]
    return pd.DataFrame(rows).sort_values("event_time").reset_index(drop=True)


@pytest.fixture(scope="module")
def base():
    return fit_baseline(history())


def test_event_lands_in_three_overlapping_windows(base):
    w = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00")]), base)
    assert sorted(w["wstart"]) == [pd.Timestamp("2025-01-08 09:50"), pd.Timestamp("2025-01-08 09:55"), pd.Timestamp("2025-01-08 10:00")]
    assert (w["n"] == 1).all()


def test_known_vs_new_attributes(base):
    known = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00")]), base)
    assert known[["new_ip", "new_asn", "new_country", "new_ua", "new_region"]].to_numpy().sum() == 0
    new = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00", ip=LONDON_IP, ua="python-requests/2.31", region="eu-west-1")]), base)
    r = new.iloc[0]
    assert (r["new_ip"], r["new_asn"], r["new_country"], r["new_ua"], r["new_region"]) == (1, 1, 1, 1, 1)


def test_new_ip_same_country_is_not_new_country(base):
    r = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00", ip=OTHER_US_IP)]), base).iloc[0]
    assert r["new_ip"] == 1 and r["new_country"] == 0


def test_unknown_identity_falls_back_to_org_baseline(base):
    # bob never appeared; HOME_IP is known org-wide for IAMUser so it must not look new
    r = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00", ident="bob")]), base).iloc[0]
    assert r["new_ip"] == 0
    r2 = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00", ident="bob", ip=LONDON_IP)]), base).iloc[0]
    assert r2["new_ip"] == 1


def test_impossible_travel_speed_math(base):
    events = pd.DataFrame([ev(1, "2025-01-08 10:00:00"), ev(2, "2025-01-08 11:00:00", ip=LONDON_IP)])
    w = compute_windows(events, base)
    km = geo.distance_km(HOME_IP, LONDON_IP)
    assert 5400 < km < 5700
    got = w["log_max_speed"].max()
    assert np.expm1(got) == pytest.approx(km / 1.0, rel=1e-3)          # 1 hour apart => km/h == km
    assert np.expm1(w["log_max_dist"].max()) == pytest.approx(km, rel=1e-3)


def test_same_country_ip_switch_is_not_travel(base):
    events = pd.DataFrame([ev(1, "2025-01-08 10:00:00"), ev(2, "2025-01-08 10:02:00", ip=OTHER_US_IP)])
    assert compute_windows(events, base)["log_max_speed"].max() == 0.0


def test_ratios_and_counts(base):
    rows = [ev(1, "2025-01-08 10:00:10", name="ListUsers", err="AccessDenied"),
            ev(2, "2025-01-08 10:00:20", name="CreateUser", ro=False),
            ev(3, "2025-01-08 10:00:30", name="DescribeInstances"),
            ev(4, "2025-01-08 10:00:40", name="GetObject", mgmt=False)]
    w = compute_windows(pd.DataFrame(rows), base)
    r = w[w["wstart"] == pd.Timestamp("2025-01-08 10:00:00")].iloc[0]
    assert r["n"] == 4 and r["n_distinct_names"] == 4
    assert r["err_ratio"] == pytest.approx(0.25)
    assert r["read_ratio"] == pytest.approx(0.75)
    assert r["high_risk_share"] == pytest.approx(0.25)          # CreateUser
    assert r["recon_ratio"] == pytest.approx(0.5)               # ListUsers + DescribeInstances (GetObject is a data event)


def test_no_nan_features_and_err_ratio_zero_when_no_errors(base):
    w = compute_windows(pd.DataFrame([ev(i, f"2025-01-08 10:00:{i:02d}") for i in range(5)]), base)
    assert not w[FEATURES].isna().any().any()
    assert (w["err_ratio"] == 0.0).all()


def test_failed_logins_counted(base):
    rows = [ev(i, f"2025-01-08 10:00:{i:02d}", name="ConsoleLogin", login="Failure", ro=False) for i in range(6)]
    assert compute_windows(pd.DataFrame(rows), base).iloc[0]["login_fail"] == pytest.approx(np.log1p(6))


def test_rare_hour_has_higher_rarity(base):
    common = compute_windows(pd.DataFrame([ev(1, "2025-01-08 10:03:00")]), base).iloc[0]["hour_rarity"]
    rare = compute_windows(pd.DataFrame([ev(1, "2025-01-08 03:03:00")]), base).iloc[0]["hour_rarity"]
    assert rare == 1.0 and common < rare


# ------------------------------------------------------------------------------------------------ model
def synthetic_feats(n=3000, seed=0):
    rng = np.random.default_rng(seed)
    X = pd.DataFrame(rng.normal(0, 1, (n, len(FEATURES))), columns=FEATURES)
    X["identity"], X["identity_type"] = "x", "IAMUser"
    X["wstart"] = pd.date_range("2025-01-01", periods=n, freq="5min")
    return X


@pytest.mark.parametrize("mode", ["global", "per_group"])
def test_outlier_scores_higher_and_threshold_flags(mode):
    train = synthetic_feats()
    m = AnomalyModel(mode=mode, n_estimators=100, max_samples=256, random_state=1).fit(train)
    val = synthetic_feats(2000, seed=1)
    info = m.calibrate(val, target_windows_per_day=5, days=2.0)
    assert sum(v["budget"] for v in info.values()) >= 1
    assert abs(int(m.flag(val).sum()) - 10) <= 3
    out = synthetic_feats(1, seed=2)
    out.loc[0, FEATURES] = 10.0                       # extreme on every feature => isolated in very few splits
    assert m.score(out)[0] > np.median(m.score(val))
    assert m.flag(out)[0]


def test_explain_surfaces_the_anomalous_feature():
    train = synthetic_feats()
    m = AnomalyModel(mode="global", n_estimators=100, max_samples=256, random_state=1).fit(train)
    out = synthetic_feats(1, seed=2)
    out.loc[0, "new_country"] = 15.0
    reasons = explain(m, out, top_k=5)[0]
    assert reasons and reasons[0]["feature"] == "new_country" and reasons[0]["contribution"] > 0
    assert len(reasons) <= 5


def test_windows_to_alerts_merges_consecutive_windows():
    feats = synthetic_feats(6)
    feats["wstart"] = pd.to_datetime(["2025-01-01 10:00", "2025-01-01 10:05", "2025-01-01 10:10", "2025-01-01 12:00", "2025-01-01 12:05", "2025-01-01 15:00"])
    feats["identity"] = "alice"
    events = pd.DataFrame([ev(i, t) for i, t in enumerate(["2025-01-01 10:01", "2025-01-01 10:12", "2025-01-01 12:03", "2025-01-01 15:02"])])
    flagged = np.array([True, True, True, True, True, False])
    alerts = windows_to_alerts(feats, np.arange(6, dtype=float), flagged, events)
    assert len(alerts) == 2                       # run 10:00-10:10 and run 12:00-12:05
    assert alerts[0].detected_at == "2025-01-01T10:15:00Z"          # first window end, not event time
    assert len(alerts[0].matched_event_ids) == 2


# ------------------------------------------------------------------------------------------------ leakage
def test_detection_code_never_touches_label_tables():
    banned = re.compile(r"\blabels\b|\binjections\b|is_malicious|scenario_id|injection_id")
    files = list((ROOT / "src" / "detection").glob("*.py")) + [ROOT / "src" / "pipeline" / "batch.py"]
    assert files
    for f in files:
        text = f.read_text(encoding="utf-8")
        hits = banned.findall(text)
        assert not hits, f"{f.name} references label data: {hits}"
