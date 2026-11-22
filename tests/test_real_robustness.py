"""Detectors and the ingestor must survive the shapes real CloudTrail exports contain."""
import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest

from src.detection.ip_analysis import IpAnalyzer
from src.detection.rules_engine import RulesEngine
from src.detection.scoring import load_config
from src.generator import geo
from src.pipeline import ingest, storage
from tests.test_rules import mk

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "data" / "raw" / "suzaku-sample-data" / "aws"


def test_rules_survive_malformed_real_world_records():
    base = mk("StopLogging")
    weird = []
    for rp in ("a string", ["list"], 5, {"policyDocument": 7}, {"policyDocument": "not json"}, {"launchPermission": "x"}, {"names": "x"}):
        for name in ("PutBucketPolicy", "AttachUserPolicy", "ModifyImageAttribute", "AuthorizeSecurityGroupIngress", "CreateRole", "RunInstances", "GetParameters", "PutUserPolicy"):
            r = json.loads(json.dumps(base))
            r["eventName"], r["requestParameters"] = name, rp
            weird.append(r)
    r = json.loads(json.dumps(base))
    del r["userIdentity"]["arn"]
    weird.append(r)
    r2 = json.loads(json.dumps(base))
    r2["userIdentity"] = {}
    r2["responseElements"] = ["x"]
    del r2["sourceIPAddress"]
    weird.append(r2)
    eng = RulesEngine()
    for rec in weird:
        eng.evaluate(rec)                         # must not raise


def test_ip_layer_handles_ipv6_service_names_and_leading_zeros():
    an = IpAnalyzer(load_config()["ip"])
    for i, ip in enumerate(["2600:1f18::1", "cloudtrail.amazonaws.com", "AWS Internal", "08.1.250.216", "", "256.1.1.1"]):
        an.evaluate({"event_id": f"e{i}", "event_time": f"2025-01-01 10:0{i}:00", "identity": "x", "identity_type": "IAMUser", "source_ip": ip, "event_name": "X"})


def test_geo_can_be_disabled_for_real_data():
    assert geo.lookup("13.5.1.1").kind == "office"
    geo.set_enabled(False)
    try:
        g = geo.lookup("13.5.1.1")
        assert g.country == "ZZ" and g.kind == "unknown"
    finally:
        geo.set_enabled(True)
    assert geo.lookup("13.5.1.1").kind == "office"


def rec(i, **kw):
    r = {"eventVersion": "1.05", "eventID": f"id-{i}", "eventTime": "2020-01-02T03:04:05Z", "eventName": "ListBuckets", "eventSource": "s3.amazonaws.com",
         "awsRegion": "us-east-1", "sourceIPAddress": "1.2.3.4", "userAgent": "x", "recipientAccountId": "111122223333",
         "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/ann", "userName": "ann", "accountId": "111122223333"}}
    r.update(kw)
    return r


def test_flatten_lenient_identity_types_and_defaults():
    cases = [
        ({"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/MyRole/sess", "sessionContext": {"sessionIssuer": {"userName": "MyRole"}}}, "MyRole"),
        ({"type": "AssumedRole", "arn": "arn:aws:sts::1:assumed-role/OnlyArn/sess"}, "OnlyArn"),
        ({"type": "Root", "arn": "arn:aws:iam::1:root"}, "root"),
        ({"type": "AWSService", "invokedBy": "ec2.amazonaws.com"}, "ec2.amazonaws.com"),
        ({"type": "AWSAccount", "principalId": "ABC", "accountId": "9"}, "ABC"),
        ({"type": "FederatedUser", "arn": "arn:aws:sts::1:federated-user/bob"}, "arn:aws:sts::1:federated-user/bob"),
        ({}, "unknown"),
    ]
    for i, (ui, want) in enumerate(cases):
        row = ingest.flatten_lenient(rec(i, userIdentity=ui))
        assert row["identity"] == want, (ui, row["identity"])
        assert isinstance(row["read_only"], bool) and isinstance(row["management_event"], bool)
    r = rec(99)
    r.pop("readOnly", None)
    assert ingest.flatten_lenient(r)["read_only"] is True                       # inferred from the List* name
    r = rec(98, eventName="CreateUser")
    assert ingest.flatten_lenient(r)["read_only"] is False
    assert ingest.flatten_lenient({"eventName": "X"}) is None                  # no id/time -> skipped


@pytest.fixture
def exports(tmp_path):
    recs = [rec(i) for i in range(5)]
    (tmp_path / "wrapped.json").write_text(json.dumps({"Records": recs[:2]}))
    (tmp_path / "list.json").write_text(json.dumps(recs[2:3]))
    (tmp_path / "single.json").write_text(json.dumps(recs[3]))
    (tmp_path / "lines.jsonl").write_text("\n".join(json.dumps(r) for r in recs[4:]) + "\n")
    with gzip.open(tmp_path / "gz.json.gz", "wt") as f:
        json.dump({"Records": [rec(10), rec(11)]}, f)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, body in (("a/x.json", json.dumps({"Records": [rec(20)]})), ("a/y.json.gz", gzip.compress(json.dumps([rec(21)]).encode()))):
            data = body.encode() if isinstance(body, str) else body
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    (tmp_path / "bundle.tar").write_bytes(buf.getvalue())
    (tmp_path / "README.md").write_text("ignored")
    (tmp_path / "dup.json").write_text(json.dumps({"Records": [rec(0)]}))              # exact duplicate of id-0
    return tmp_path


def test_ingest_all_formats_and_dedup(exports, tmp_path):
    con = storage.connect(tmp_path / "x.duckdb")
    stats = ingest.ingest(con, [exports], chunk=3)
    ids = sorted(r[0] for r in con.execute("SELECT event_id FROM events").fetchall())
    assert ids == sorted([f"id-{i}" for i in range(5)] + ["id-10", "id-11", "id-20", "id-21"])
    assert stats["records_seen"] == 10 and stats["inserted"] == 9 and stats["duplicates"] == 1 and stats["skipped_invalid"] == 0
    assert con.execute("SELECT count(*) FROM labels").fetchone()[0] == 0              # real data has no labels


def test_generated_events_round_trip_through_files(tmp_path):
    from src.generator.dataset import generate_dataset
    ds = generate_dataset(seed=3, world_seed=9, days=1, scale=0.03, attacks=["S4"], count=1)
    recs = [r for r, _ in ds.events]
    (tmp_path / "x.json").write_text(json.dumps({"Records": recs}))
    con = storage.connect(tmp_path / "rt.duckdb")
    assert ingest.ingest(con, [tmp_path / "x.json"])["inserted"] == len(recs)
    orig = storage.flatten(recs[100])
    got = con.execute("SELECT * FROM events WHERE event_id = ?", [recs[100]["eventID"]]).fetchdf().iloc[0]
    for col in ("event_name", "identity", "source_ip", "identity_type", "aws_region"):
        assert got[col] == orig[col], col


@pytest.mark.skipif(not SAMPLES.exists(), reason="real sample data not downloaded (see scripts/load_flaws.py / docs)")
def test_detectors_never_crash_on_real_sample_files():
    """Run the rules and IP layer over every real sample file (Stratus, Invictus-IR, SANS, TrailDiscover) and a flaws.cloud shard."""
    eng, an = RulesEngine(), IpAnalyzer(load_config()["ip"])
    n = 0
    files = [f for d in ("stratus-red-team.cloud", "invictus-ir", "traildiscover.cloud") for f in (SAMPLES / d).rglob("*.json")]
    files += sorted((SAMPLES / "flaws.cloud").glob("*19.json.gz"))[:1]
    for r in sorted(ingest.iter_records(files), key=lambda r: r["eventTime"]):
        eng.evaluate(r)
        row = ingest.flatten_lenient(r)
        if row:
            an.evaluate({**row, "event_time": row["event_time"]})
        n += 1
    assert n > 1000
