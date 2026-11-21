import pandas as pd
import pytest

from src.detection.features import fit_baseline
from src.detection.incidents import group_alerts
from src.detection.ip_analysis import IpAnalyzer
from src.detection.rules_engine import Alert, RulesEngine
from src.detection.scoring import alert_id, load_config, score_alert, score_alerts
from src.detection.triage import SuppressionList
from tests.test_features_model import HOME_IP, LONDON_IP, ev, history

CFG = load_config()
NYC2 = "11.7.7.7"


@pytest.fixture(scope="module")
def base():
    return fit_baseline(history())


def row(i, t, ident="alice", ip=HOME_IP, itype="IAMUser"):
    return {"event_id": f"x{i}", "event_time": pd.Timestamp(t), "identity": ident, "source_ip": ip, "identity_type": itype, "event_name": "ListUsers"}


def fire(rows, base, rid=None):
    an = IpAnalyzer(CFG["ip"], base)
    out = [a for r in rows for a in an.evaluate(r)]
    return [a for a in out if rid is None or a.rule_id == rid]


# ------------------------------------------------------------------------------------------- IP layer
def test_impossible_travel_fires_and_names_the_distance(base):
    a = fire([row(1, "2025-01-08 10:00:00"), row(2, "2025-01-08 10:10:00", ip=LONDON_IP)], base, "IP001")
    assert len(a) == 1 and "km" in a[0].detail and a[0].severity == "HIGH" and a[0].matched_event_ids == ["x1", "x2"]


def test_travel_negatives(base):
    assert not fire([row(1, "2025-01-08 10:00:00"), row(2, "2025-01-08 10:10:00", ip=NYC2)], base, "IP001")             # same country
    assert not fire([row(1, "2025-01-08 10:00:00"), row(2, "2025-01-08 22:00:00", ip=LONDON_IP)], base, "IP001")        # 12h is plausible
    assert not fire([row(1, "2025-01-08 10:00:00", ident="a"), row(2, "2025-01-08 10:01:00", ident="b", ip=LONDON_IP)], base, "IP001")  # different identities


def test_travel_cooldown_limits_alert_storm(base):
    rows = []
    for i in range(10):
        rows.append(row(2 * i, f"2025-01-08 10:{i:02d}:00"))
        rows.append(row(2 * i + 1, f"2025-01-08 10:{i:02d}:30", ip=LONDON_IP))
    assert len(fire(rows, base, "IP001")) == 1


def test_shared_ip_new_to_many_identities(base):
    rows = [row(i, f"2025-01-08 10:0{i}:00", ident=n, ip="45.9.9.9") for i, n in enumerate(["bob", "carol", "dave"])]
    assert len(fire(rows, base, "IP002")) == 1
    known = [row(i, f"2025-01-08 10:0{i}:00", ident=n, ip=HOME_IP) for i, n in enumerate(["bob", "carol", "dave"])]
    assert not fire(known, base, "IP002")                 # an IP the org already knows (e.g. the office) is not suspicious
    two = rows[:2]
    assert not fire(two, base, "IP002")


def test_identity_on_many_ips(base):
    ips = ["45.1.1.1", "45.2.2.2", "45.3.3.3", "45.4.4.4"]
    assert len(fire([row(i, f"2025-01-08 10:0{i}:00", ip=ip) for i, ip in enumerate(ips)], base, "IP003")) == 1
    assert not fire([row(i, f"2025-01-08 10:0{i}:00", ip=ip) for i, ip in enumerate(ips[:3])], base, "IP003")


def test_blocklisted_asn_once_per_hour(base):
    rows = [row(i, f"2025-01-08 10:0{i}:00", ip="185.5.5.5") for i in range(4)]
    a = fire(rows, base, "IP004")
    assert len(a) == 1 and "AS9009" in a[0].detail


# ------------------------------------------------------------------------------------------- scoring
def mkalert(rid="R001", sev="HIGH", ident="alice", ip="45.1.1.1", t="2025-01-08T10:00:00Z", tactic="Defense Evasion", src="rule", eid="e1", **kw):
    return Alert(rid, "t", sev, tactic, "T1", eid, t, ident, ip, "d", source=src, **kw)


def test_rule_alert_risk_follows_severity_points():
    sc = CFG["scoring"]
    for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert score_alert(mkalert(sev=sev), sc).risk == sc["severity_points"][sev]


def test_anomaly_severity_and_tactic_from_margin_and_reasons():
    sc = CFG["scoring"]
    lo = score_alert(mkalert(rid="ML001", src="anomaly", margin=0.01, reasons=[{"feature": "new_country", "value": 1, "contribution": 1}], tactic=""), sc)
    hi = score_alert(mkalert(rid="ML001", src="anomaly", margin=0.2, reasons=[{"feature": "bytes_z", "value": 5, "contribution": 1}], tactic=""), sc)
    assert lo.severity == "LOW" and hi.severity == "HIGH"
    assert lo.mitre_tactic == "Initial Access" and hi.mitre_tactic == "Exfiltration"
    assert hi.risk > lo.risk and hi.risk <= sc["anomaly"]["max_points"]


def test_alert_id_is_stable_and_distinct():
    a, b = mkalert(eid="e1"), mkalert(eid="e2")
    assert alert_id(a) == alert_id(mkalert(eid="e1")) and alert_id(a) != alert_id(b)


# ------------------------------------------------------------------------------------------- incidents
def inc(alerts, known=None):
    return group_alerts(score_alerts(alerts, CFG), CFG, known)


def test_same_identity_within_gap_groups_and_chain_is_ordered():
    al = [mkalert("R1", "MEDIUM", t="2025-01-08T10:00:00Z", tactic="Initial Access", eid="a"),
          mkalert("R2", "HIGH", t="2025-01-08T10:20:00Z", tactic="Privilege Escalation", eid="b"),
          mkalert("R3", "CRITICAL", t="2025-01-08T10:40:00Z", tactic="Defense Evasion", eid="c")]
    out = inc(al)
    assert len(out) == 1
    i = out[0]
    assert i.tactics == ["Initial Access", "Privilege Escalation", "Defense Evasion"] and i.severity == "CRITICAL" and i.n_alerts == 3
    assert i.title.startswith("Multi-stage activity on alice")


def test_different_identity_and_ip_do_not_group():
    al = [mkalert(ident="alice", ip="45.1.1.1", eid="a"), mkalert(ident="bob", ip="45.2.2.2", eid="b")]
    assert len(inc(al)) == 2


def test_shared_attacker_ip_links_identities_but_org_known_ip_does_not():
    al = [mkalert(ident="alice", ip="45.1.1.1", eid="a", t="2025-01-08T10:00:00Z"), mkalert(ident="bob", ip="45.1.1.1", eid="b", t="2025-01-08T10:05:00Z")]
    assert len(inc(al)) == 1
    assert len(inc(al, known={"45.1.1.1"})) == 2


def test_gap_splits_incidents_unless_high_severity():
    low = [mkalert(sev="LOW", eid="a", t="2025-01-08T10:00:00Z"), mkalert(sev="LOW", eid="b", t="2025-01-08T12:00:00Z")]
    assert len(inc(low)) == 2
    high = [mkalert(sev="HIGH", eid="a", t="2025-01-08T10:00:00Z"), mkalert(sev="LOW", eid="b", t="2025-01-08T14:00:00Z")]
    assert len(inc(high)) == 1                                   # within the 6h high-severity gap
    far = [mkalert(sev="HIGH", eid="a", t="2025-01-08T10:00:00Z"), mkalert(sev="LOW", eid="b", t="2025-01-08T18:00:00Z")]
    assert len(inc(far)) == 2


def test_many_tactics_escalate_severity_and_risk_is_bounded():
    al = [mkalert("R1", "LOW", tactic="Discovery", eid="a", t="2025-01-08T10:00:00Z"), mkalert("R2", "LOW", tactic="Persistence", eid="b", t="2025-01-08T10:01:00Z"),
          mkalert("R3", "LOW", tactic="Impact", eid="c", t="2025-01-08T10:02:00Z")]
    i = inc(al)[0]
    assert i.severity in ("HIGH", "CRITICAL") and 0 < i.risk_score <= 100


def test_multiple_sources_corroborate_risk():
    single = inc([mkalert("R1", "MEDIUM", eid="a")])[0]
    multi = inc([mkalert("R1", "MEDIUM", eid="a"), mkalert("IP001", "MEDIUM", src="ip", eid="b", t="2025-01-08T10:01:00Z")])[0]
    assert multi.risk_score > single.risk_score and set(multi.sources) == {"rule", "ip"}


# ------------------------------------------------------------------------------------------- triage
def test_suppression_scopes_and_impact(tmp_path):
    path = tmp_path / "supp.json"
    sl = SuppressionList(path=path)
    a1, a2, a3 = mkalert("R007", ident="alice", eid="a"), mkalert("R007", ident="bob", eid="b"), mkalert("R001", ident="alice", eid="c")
    sl.add_from_alert(a1, "identity", "admin key rotation")
    kept, dropped = sl.apply([a1, a2, a3])
    assert [x.event_id for x in dropped] == ["a"] and len(kept) == 2          # only rule+identity matches
    assert sl.impact([a1, a2, a3])["would_suppress"] == 1
    assert len(SuppressionList(path=path).entries) == 1                       # persisted
    sl.add_from_alert(a2, "rule")
    assert len(sl.apply([a1, a2, a3])[1]) == 2


# ------------------------------------------------------------------------------------------- end to end
def test_end_to_end_kill_chain_becomes_one_high_incident():
    from src.generator.dataset import generate_dataset
    from src.pipeline.storage import flatten
    ds = generate_dataset(seed=31, world_seed=9, days=3, scale=0.04, attacks=["S1+S2+S3+S4"], count=1)
    flat = pd.DataFrame([flatten(r) for r, _ in ds.events]).drop(columns=["raw"])
    flat["event_time"] = pd.to_datetime(flat["event_time"])
    base = fit_baseline(flat[flat["event_time"] < flat["event_time"].min().normalize() + pd.Timedelta(days=1)])
    eng = RulesEngine()
    alerts = [a for r, _ in ds.events for a in eng.evaluate(r)]
    alerts += IpAnalyzer(CFG["ip"], base).evaluate_frame(flat)
    incidents = group_alerts(score_alerts(alerts, CFG), CFG, set(base.org_sets["ip"]["value"]))
    victim = ds.injections[0]["victim"]
    mine = [i for i in incidents if victim in i.identities and i.severity in ("HIGH", "CRITICAL")]
    assert len(mine) == 1
    chain = mine[0].tactics
    for earlier, later in (("Initial Access", "Defense Evasion"), ("Privilege Escalation", "Defense Evasion")):
        assert earlier in chain and later in chain and chain.index(earlier) < chain.index(later)
    assert mine[0].severity == "CRITICAL"                           # StopLogging / DeleteTrail
    inj_start = pd.Timestamp(ds.injections[0]["start_time"])
    assert pd.Timestamp(mine[0].first_seen.rstrip("Z")) - inj_start < pd.Timedelta(minutes=2)    # detected at the first malicious event
