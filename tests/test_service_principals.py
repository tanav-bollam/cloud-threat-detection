from src.detection.rules_engine import RulesEngine
from tests.test_rules import mk


def test_aws_service_principals_do_not_trigger_the_accessdenied_burst_rule():
    """Real data (SANS lab): delivery.logs.amazonaws.com produced 164 'enumeration' alerts. AWS service principals are excluded."""
    eng = RulesEngine()
    recs = []
    for i in range(40):
        r = mk("ListUsers", t=i, error="AccessDenied")
        r["userIdentity"] = {"type": "AWSService", "invokedBy": "delivery.logs.amazonaws.com"}
        recs.append(r)
    assert not [a for r in recs for a in eng.evaluate(r) if a.rule_id == "R023"]
    human = [mk("ListUsers", t=i, error="AccessDenied") for i in range(40)]
    eng2 = RulesEngine()                                   # one engine, so the burst threshold can accumulate
    assert [a for r in human for a in eng2.evaluate(r) if a.rule_id == "R023"]
