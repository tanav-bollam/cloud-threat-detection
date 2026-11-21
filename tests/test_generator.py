import json
from collections import Counter

import pytest

from src.generator import geo
from src.generator.dataset import generate_dataset
from src.generator.schema import validate_record
from src.pipeline import storage

SCEN = ["S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9"]


@pytest.fixture(scope="module")
def ds():
    return generate_dataset(seed=11, days=2, scale=0.05, attacks=SCEN + ["S1+S2+S3+S4+S5"], count=2)


def test_every_event_conforms_to_schema(ds):
    for rec, _ in ds.events:
        validate_record(rec)


def test_deterministic_same_seed():
    a = generate_dataset(seed=5, days=1, scale=0.05, attacks=["S3", "S4"], count=1)
    b = generate_dataset(seed=5, days=1, scale=0.05, attacks=["S3", "S4"], count=1)
    assert [json.dumps(e[0], sort_keys=True) for e in a.events] == [json.dumps(e[0], sort_keys=True) for e in b.events]
    c = generate_dataset(seed=6, days=1, scale=0.05, attacks=["S3", "S4"], count=1)
    assert [e[0]["eventID"] for e in a.events] != [e[0]["eventID"] for e in c.events]


def test_event_ids_unique_and_sorted(ds):
    ids = [e[0]["eventID"] for e in ds.events]
    assert len(ids) == len(set(ids))
    times = [e[0]["eventTime"] for e in ds.events]
    assert times == sorted(times)


def test_labels_never_inside_records(ds):
    banned = {"is_malicious", "scenario_id", "mitre_tactic", "technique", "injection_id"}
    for rec, _ in ds.events:
        assert not banned & set(rec)
        blob = json.dumps(rec)
        assert "scenario_id" not in blob and "is_malicious" not in blob


def test_all_scenarios_injected_with_malicious_events(ds):
    c = Counter(l["scenario_id"] for _, l in ds.events if l and l["is_malicious"])
    for s in SCEN:
        assert c[s] > 0, f"{s} produced no malicious events"
    assert {r["scenario_id"] for r in ds.injections} >= set(SCEN)


def test_chain_shares_attacker_and_victim(ds):
    chains = {}
    for r in ds.injections:
        if r["chain_id"]:
            chains.setdefault(r["chain_id"], []).append(r)
    assert chains
    for rows in chains.values():
        assert [r["scenario_id"] for r in rows] == ["S1", "S2", "S3", "S4", "S5"]
        assert len({r["victim"] for r in rows}) == 1
        starts = [r["start_time"] for r in rows]
        assert starts == sorted(starts)


def test_key_signals_present(ds):
    mal = [(r, l) for r, l in ds.events if l and l["is_malicious"]]
    names = {s: {r["eventName"] for r, l in mal if l["scenario_id"] == s} for s in SCEN}
    assert names["S4"] & {"StopLogging", "DeleteTrail"}
    assert "AttachUserPolicy" in names["S3"] and "CreateAccessKey" in names["S3"]
    assert "ModifySnapshotAttribute" in names["S5"] and "PutBucketPolicy" in names["S5"]
    assert "RunInstances" in names["S7"]
    assert "ConsoleLogin" in names["S8"]


def test_attacker_ips_are_foreign_for_s1(ds):
    s1 = [(r, l) for r, l in ds.events if l and l["scenario_id"] == "S1" and l["is_malicious"]]
    assert any(geo.lookup(r["sourceIPAddress"]).country != "US" for r, _ in s1)


def test_impossible_travel_distance(ds):
    by_inj = {}
    for r, l in ds.events:
        if l and l["scenario_id"] == "S9":
            by_inj.setdefault(l["injection_id"], []).append((r, l))
    assert by_inj
    for evs in by_inj.values():
        anchor = [r for r, l in evs if not l["is_malicious"]][0]
        far = [r for r, l in evs if l["is_malicious"]]
        assert geo.distance_km(anchor["sourceIPAddress"], far[0]["sourceIPAddress"]) >= 5000


def test_benign_has_no_root_and_noise_is_labeled(ds):
    benign_root = [r for r, l in ds.events if r["userIdentity"]["type"] == "Root" and not (l and l["is_malicious"])]
    assert benign_root == []
    assert any(l and l["scenario_id"] == "N_oncall" for _, l in ds.events)
    assert any(l and l["scenario_id"] == "N_onboarding" for _, l in ds.events)


def test_global_services_log_us_east_1(ds):
    for r, _ in ds.events:
        if r["eventSource"] == "iam.amazonaws.com":
            assert r["awsRegion"] == "us-east-1"


def test_geo_lookup_and_haversine():
    assert geo.lookup("13.5.1.1").kind == "office"
    assert geo.lookup("lambda.amazonaws.com").country == "ZZ"
    d = geo.haversine_km(40.7, -74.0, 51.5, -0.1)  # NYC-London ~5570 km
    assert 5400 < d < 5700


def test_storage_roundtrip(tmp_path, ds):
    con = storage.connect(tmp_path / "t.duckdb")
    n = storage.insert_events(con, ds.events[:500])
    storage.insert_injections(con, ds.injections)
    assert n == 500
    assert con.execute("select count(*) from events").fetchone()[0] == 500
    assert con.execute("select count(*) from labels").fetchone()[0] == 500
    assert con.execute("select count(*) from injections").fetchone()[0] == len(ds.injections)
    raw = con.execute("select raw from events limit 1").fetchone()[0]
    validate_record(json.loads(raw))
