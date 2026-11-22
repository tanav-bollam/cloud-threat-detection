"""Every rule has a positive and a negative fixture. Fixtures are built with the same record builder the generator
uses, then mutated, so they stay schema-valid."""
import copy
import json
import random
from datetime import datetime, timedelta

import pytest

from src.detection.rules_engine import RulesEngine, load_rules
from src.generator.schema import validate_record
from src.generator.world import Principal, build_record, console_login

ACCT = "123456789012"
rng = random.Random(1)
T0 = datetime(2025, 1, 8, 10, 0, 0)
ALICE = Principal("alice", "IAMUser", "developers", ACCT, access_key="AKIAABCDEFGHIJKLMNOP", principal_id="AIDAXXXXXXXXXXXXXXXXX")
ROOT = Principal("root", "Root", "root", ACCT, principal_id=ACCT)
ROLE = Principal("ci-deployer", "AssumedRole", "ci", ACCT, principal_id="AROAXXXXXXXXXXXXXXXXX")


def mk(name, t=0, who=ALICE, ip="11.5.5.5", ua="aws-cli/2.15.30 Python/3.11.8", region="us-east-1", error=None, ctx=None, mut=None):
    session = who.new_session(random.Random(t), console=False)
    rec = build_record(random.Random(f"{name}{t}"), T0 + timedelta(seconds=t), who, session, ip, ua, region, name, error=error, ctx=ctx)
    if mut:
        mut(rec)
    validate_record(rec)
    return rec


def login(t, ok, mfa=True, ip="11.5.5.5", who=ALICE):
    rec = console_login(random.Random(t), T0 + timedelta(seconds=t), who, ip, "Mozilla/5.0", "us-east-1", success=ok, mfa=mfa)
    validate_record(rec)
    return rec


POL_PUBLIC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
POL_PRIVATE = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:role/app"}, "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
POL_ADMIN = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
POL_S3 = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]})
TRUST_EXT = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999988887777:root"}, "Action": "sts:AssumeRole"}]})
TRUST_SVC = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]})
TRUST_SELF = json.dumps({"Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "sts:AssumeRole"}]})


def set_req(**kw):
    def f(rec):
        rec["requestParameters"].update(kw)
    return f


# rule_id -> (positive sequences, negative sequences); each sequence is a list of records evaluated in order on a fresh engine
FIXTURES = {
    "R001": ([[mk("StopLogging")], [mk("DeleteTrail")]], [[mk("DescribeTrails")], [mk("GetTrailStatus")]]),
    "R002": ([[mk("UpdateTrail")], [mk("PutEventSelectors")]], [[mk("LookupEvents")]]),
    "R003": ([[mk("DeleteDetector")], [mk("UpdateDetector")]], [[mk("ListDetectors")], [mk("UpdateDetector", mut=set_req(enable=True))]]),
    "R004": ([[mk("DeleteFlowLogs")]], [[mk("DescribeVpcs")]]),
    "R005": ([[mk("AttachUserPolicy", ctx={"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})],
              [mk("AttachRolePolicy", ctx={"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"})]],
             [[mk("AttachUserPolicy", ctx={"policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})],
              [mk("AttachUserPolicy", ctx={"policy_arn": "arn:aws:iam::aws:policy/AdministratorAccessSomethingElse"})]]),
    "R006": ([[mk("PutUserPolicy", ctx={"policy_doc": POL_ADMIN})]], [[mk("PutUserPolicy", ctx={"policy_doc": POL_S3})]]),
    "R007": ([[mk("CreateAccessKey", ctx={"target_user": "bob"})]], [[mk("CreateAccessKey", ctx={"target_user": "alice"})]]),
    "R008": ([[mk("CreateLoginProfile")]], [[mk("ListUsers")]]),
    "R009": ([[mk("UpdateAssumeRolePolicy", ctx={"trust_doc": TRUST_EXT})]],
             [[mk("UpdateAssumeRolePolicy", ctx={"trust_doc": TRUST_SVC})], [mk("UpdateAssumeRolePolicy", ctx={"trust_doc": TRUST_SELF})]]),
    "R010": ([[mk("CreateUser")]], [[mk("GetUser")]]),
    "R011": ([[mk("CreateFunction20150331")]], [[mk("GetFunction20150331v2")]]),
    "R012": ([[mk("PutBucketPolicy", ctx={"policy": POL_PUBLIC})]], [[mk("PutBucketPolicy", ctx={"policy": POL_PRIVATE})]]),
    "R013": ([[mk("PutBucketAcl", ctx={"acl": ["public-read"]})]], [[mk("PutBucketAcl", ctx={"acl": ["private"]})]]),
    "R014": ([[mk("ModifySnapshotAttribute", ctx={"external_account": "999988887777"})]],
             [[mk("ModifySnapshotAttribute", ctx={"external_account": ACCT})]]),
    "R015": ([[mk("RunInstances", ctx={"instance_type": "p3.16xlarge"})], [mk("RequestSpotInstances", ctx={"instance_type": "g5.48xlarge"})]],
             [[mk("RunInstances", ctx={"instance_type": "t3.micro"})], [mk("RunInstances", ctx={"instance_type": "m5.large"})]]),
    "R016": ([[mk("RunInstances", region="ap-southeast-1")]], [[mk("RunInstances", region="us-west-2")]]),
    "R017": ([[mk("AuthorizeSecurityGroupIngress", ctx={"cidr": "0.0.0.0/0"})]], [[mk("AuthorizeSecurityGroupIngress", ctx={"cidr": "10.0.0.0/8"})]]),
    "R018": ([[mk("ListUsers", who=ROOT)], [login(0, True, who=ROOT)]], [[mk("ListUsers")], [login(0, False, who=ROOT)]]),
    "R019": ([[login(0, True, mfa=False)]], [[login(0, True, mfa=True)], [login(0, False, mfa=False)]]),
    "R020": ([[login(i * 10, False) for i in range(5)]], [[login(i * 10, False) for i in range(4)],
                                                            [login(i * 400, False) for i in range(5)]]),          # spread over >10 min
    "R021": ([[login(i * 5, False) for i in range(5)] + [login(60, True)]], [[login(i * 5, False) for i in range(4)] + [login(60, True)],
                                                                             [login(0, True)]]),
    "R022": ([[mk("ListUsers", ua="python-requests/2.31.0")], [mk("ListUsers", ua="aws-cli/1.22.34 Python/3.10.12 Linux/6.5.0-kali3-amd64")]],
             [[mk("ListUsers", ua="aws-cli/2.15.30 Python/3.11.8 Linux/5.15.0")], [mk("ListUsers", ua="Boto3/1.34.69 Botocore/1.34.69")]]),
    "R023": ([[mk("ListUsers", t=i, error="AccessDenied") for i in range(15)]], [[mk("ListUsers", t=i, error="AccessDenied") for i in range(14)],
                                                                                [mk("ListUsers", t=i, error="ThrottlingException") for i in range(30)]]),
    "R024": ([[mk("GetObject", t=i) for i in range(250)]], [[mk("GetObject", t=i) for i in range(249)],
                                                              [mk("GetObject", t=i, who=ROLE) for i in range(400)]]),   # service roles excluded
}


# merge fixtures for rules added after real-data validation BEFORE the parametrized tests below read FIXTURES
from tests import rule_fixtures_real  # noqa: E402,F401


def fired(seq, rule_id):
    eng = RulesEngine()
    return [a for r in seq for a in eng.evaluate(r) if a.rule_id == rule_id]


def test_every_rule_has_fixtures_and_complete_metadata():
    rules = load_rules()
    assert len(rules) >= 20
    for r in rules:
        assert r.id in FIXTURES, f"{r.id} has no fixtures"
        assert r.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert r.mitre_tactic and r.mitre_technique and r.description and r.false_positive_notes, r.id
    assert set(FIXTURES) == {r.id for r in rules}


@pytest.mark.parametrize("rule_id", sorted(FIXTURES))
def test_positive_fixtures_fire(rule_id):
    for seq in FIXTURES[rule_id][0]:
        assert fired(seq, rule_id), f"{rule_id} did not fire on a positive fixture"


@pytest.mark.parametrize("rule_id", sorted(FIXTURES))
def test_negative_fixtures_do_not_fire(rule_id):
    for seq in FIXTURES[rule_id][1]:
        assert not fired(seq, rule_id), f"{rule_id} fired on a negative fixture"


def test_threshold_cooldown_prevents_alert_storm():
    seq = [mk("ListUsers", t=i, error="AccessDenied") for i in range(60)]
    assert len(fired(seq, "R023")) == 1


def test_threshold_groups_are_independent():
    other = Principal("bob", "IAMUser", "developers", ACCT, access_key="AKIAZZZZZZZZZZZZZZZZ", principal_id="AIDAYYYYYYYYYYYYYYYYY")
    seq = []
    for i in range(10):
        seq.append(mk("ListUsers", t=i * 2, error="AccessDenied"))
        seq.append(mk("ListUsers", t=i * 2 + 1, who=other, error="AccessDenied"))
    assert not fired(seq, "R023")      # 10 each, never 15 for one identity


def test_sequence_failures_from_other_ip_do_not_count():
    seq = [login(i * 5, False, ip="45.1.1.1") for i in range(5)] + [login(60, True, ip="11.5.5.5")]
    assert not fired(seq, "R021")


def test_disabled_rule_does_not_fire():
    eng = RulesEngine(disabled={"R001"})
    assert not [a for a in eng.evaluate(mk("StopLogging")) if a.rule_id == "R001"]


def test_alert_carries_metadata():
    a = fired([mk("StopLogging")], "R001")[0]
    assert a.severity == "CRITICAL" and a.mitre_technique == "T1562.008" and a.identity == "alice" and a.event_name == "StopLogging"


def test_engine_never_sees_labels():
    rec = copy.deepcopy(mk("StopLogging"))
    assert "scenario_id" not in json.dumps(rec)

