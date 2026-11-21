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


def _s1_attackers(stealth, n=6):
    ds = generate_dataset(seed=21, world_seed=9, days=3, scale=0.03, attacks=["S1"], count=n, stealth=stealth)
    victims = {r["victim"]: r for r in ds.injections}
    out = []
    for rec, lab in ds.events:
        if lab and lab["is_malicious"] and lab["scenario_id"] == "S1":
            out.append(rec)
    return ds, out


def test_graded_stealth_levels():
    base_ds, base = _s1_attackers(0.0)
    ua_ds, ua = _s1_attackers(0.3)
    bl_ds, bl = _s1_attackers(0.6)
    biz_ds, biz = _s1_attackers(0.9)
    # 0.0: foreign IPs, offensive-tool agents
    assert any(geo.lookup(r["sourceIPAddress"]).country != "US" for r in base)
    # 0.3: victim's own user agent (no offensive tooling) but still a foreign IP
    assert not any("kali" in r["userAgent"] or r["userAgent"].startswith(("python-requests", "curl")) for r in ua)
    assert any(geo.lookup(r["sourceIPAddress"]).country != "US" for r in ua)
    # 0.6: same-country residential IP and the victim's usual region
    assert all(geo.lookup(r["sourceIPAddress"]).country == "US" for r in bl)
    assert all(r["awsRegion"] in ("us-east-1", "us-west-2") for r in bl if r["eventSource"] != "iam.amazonaws.com")
    # 0.9: business hours in UTC
    hours = [int(r["eventTime"][11:13]) for r in biz]
    assert all(14 <= h <= 22 for h in hours)


def test_stealth_slows_the_attacker():
    def span(stealth):
        ds = generate_dataset(seed=22, world_seed=9, days=3, scale=0.03, attacks=["S2"], count=1, stealth=stealth)
        return (ds.injections[0]["end_time"] - ds.injections[0]["start_time"]).total_seconds()
    assert span(0.9) > 5 * span(0.0)
