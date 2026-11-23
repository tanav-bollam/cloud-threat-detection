from src.detection.rules_engine import RulesEngine
from src.generator.world import Principal
from tests.test_rules import ACCT, ALICE, mk  # noqa: F401

BOB = Principal("bob", "IAMUser", "developers", ACCT, access_key="AKIAZZZZZZZZZZZZZZZZ", principal_id="AIDAYYYYYYYYYYYYYYYYY")


def flood(n, step=2, who=ALICE, ip="11.5.5.5", t0=0):
    return [mk("RunInstances", t=t0 + i * step, who=who, ip=ip, region="ap-southeast-1", ctx={"instance_type": "p3.16xlarge"}) for i in range(n)]


def alerts(engine, recs, rule):
    return [a for r in recs for a in engine.evaluate(r) if a.rule_id == rule]


def test_repeats_fold_into_one_alert_that_keeps_every_event():
    recs = flood(50)
    out = alerts(RulesEngine(), recs, "R016")
    assert len(out) == 1
    assert out[0].matched_event_ids == [r["eventID"] for r in recs]          # event coverage unchanged
    assert "50 matching events" in out[0].detail


def test_new_alert_after_the_window_and_for_other_identities_or_ips():
    eng = RulesEngine(dedupe_s=300)
    assert len(alerts(eng, flood(5) + flood(5, t0=400), "R016")) == 2          # 400 s later -> a second alert
    assert len(alerts(RulesEngine(dedupe_s=300), flood(5) + flood(5, who=BOB), "R016")) == 2
    assert len(alerts(RulesEngine(dedupe_s=300), flood(5) + flood(5, ip="11.9.9.9"), "R016")) == 2


def test_dedupe_can_be_disabled_and_is_per_rule():
    recs = flood(10)
    assert len(alerts(RulesEngine(dedupe_s=0), recs, "R016")) == 10
    eng = RulesEngine()
    out = [a for r in recs for a in eng.evaluate(r)]
    assert {a.rule_id for a in out} >= {"R015", "R016"} and sum(a.rule_id == "R015" for a in out) == 1 and sum(a.rule_id == "R016" for a in out) == 1


def test_threshold_rules_keep_their_own_cooldown():
    recs = [mk("ListUsers", t=i, error="AccessDenied") for i in range(60)]
    assert len(alerts(RulesEngine(), recs, "R023")) == 1


def test_reset_clears_dedupe_state():
    eng = RulesEngine()
    alerts(eng, flood(3), "R016")
    eng.reset()
    assert len(alerts(eng, flood(3), "R016")) == 1


def test_pop_updated_returns_alerts_that_absorbed_repeats_once():
    eng = RulesEngine()
    out = [a for r in flood(5) for a in eng.evaluate(r) if a.rule_id == "R016"]
    assert len(out) == 1
    upd = eng.pop_updated()
    assert out[0] in upd and len({id(a) for a in upd}) == len(upd)           # the same object, no duplicates
    assert eng.pop_updated() == []                                           # cleared after reading
    assert len(out[0].matched_event_ids) == 5


def test_live_pipeline_persists_folded_repeats(tmp_path, trained):
    """In live mode the stored alert must list every folded event, not just the first."""
    import json
    from datetime import datetime, timedelta
    from src.pipeline.live import LiveEngine
    base, model = trained
    start = datetime(2025, 1, 13, 9, 0)
    eng = LiveEngine(tmp_path / "l.duckdb", base, model, speed=0, scale=0.05, world_seed=9, days=1, until=start + timedelta(hours=2), fresh=True)
    eng.inject("S7", at=start + timedelta(minutes=30))
    eng.start()
    assert eng.wait(120) and eng.detector.error is None
    rows = eng.cursor().execute("SELECT rule_id, matched_event_ids, detail FROM alerts WHERE rule_id IN ('R015','R016')").fetchall()
    assert rows, "S7 should raise the instance rules"
    folded = [(r, json.loads(m)) for r, m, d in rows if "repeats folded" in (d or "")]
    assert folded and all(len(ids) > 1 for _, ids in folded), "a folded alert was stored with only its first event"
    eng.close()
