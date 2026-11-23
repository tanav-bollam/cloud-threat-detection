import copy

import pandas as pd
import pytest

from src.detection.features import fit_baseline
from src.detection.ip_analysis import IpAnalyzer
from src.detection.scoring import load_config
from tests.test_features_model import history

CFG = load_config()["ip"]


@pytest.fixture(scope="module")
def base():
    return fit_baseline(history())


def row(i, t, ident, ip, itype="IAMUser"):
    return {"event_id": f"x{i}", "event_time": pd.Timestamp(t), "identity": ident, "source_ip": ip, "identity_type": itype, "event_name": "ListUsers"}


def fire(rows, baseline, rid):
    an = IpAnalyzer(CFG, baseline)
    return [a for r in rows for a in an.evaluate(r) if a.rule_id == rid]


def test_baseline_records_how_many_ips_are_normal_per_identity(base):
    assert base.ip_p99["alice"] >= 1 and base.org_ip_p99["IAMUser"] >= 1 and base.ip_spread["alice"] == 1


def test_a_widely_shared_credential_does_not_make_an_ip_look_shared(base):
    b = copy.deepcopy(base)
    for name in ("pub1", "pub2", "pub3"):
        b.ip_spread[name] = 500                                   # seen from hundreds of IPs: a public/shared key
    rows = [row(i, f"2025-01-08 10:0{i}:00", n, "45.9.9.9") for i, n in enumerate(["pub1", "pub2", "pub3"])]
    assert not fire(rows, b, "IP002")
    normal = [row(i, f"2025-01-08 10:0{i}:00", n, "45.9.9.9") for i, n in enumerate(["bob", "carol", "dave"])]
    assert len(fire(normal, b, "IP002")) == 1                     # ordinary identities still trigger it
    mixed = [row(0, "2025-01-08 10:00:00", "pub1", "45.9.9.9"), row(1, "2025-01-08 10:01:00", "bob", "45.9.9.9"), row(2, "2025-01-08 10:02:00", "carol", "45.9.9.9")]
    assert not fire(mixed, b, "IP002")                            # the shared one does not count toward the 3


def test_many_ips_needs_more_than_normal_for_that_identity(base):
    ips = [f"45.{i}.{i}.{i}" for i in range(1, 9)]
    rows = lambda ident: [row(i, f"2025-01-08 10:{i:02d}:00", ident, ip) for i, ip in enumerate(ips)]
    assert len(fire(rows("alice"), base, "IP003")) == 1           # normal 1-2 IPs: 4 distinct is already unusual
    b = copy.deepcopy(base)
    b.ip_p99["busy"] = 10.0                                       # this identity routinely shows ~10 IPs per window
    assert not fire(rows("busy"), b, "IP003")                     # 8 distinct < 1.5 * 10 + 1
    more = [row(i, f"2025-01-08 10:{i:02d}:00", "busy", f"46.{i}.{i}.{i}") for i in range(20)]
    assert len(fire(more, b, "IP003")) == 1                       # 20 distinct is far above its normal


def test_unknown_identity_uses_the_org_level_normal(base):
    b = copy.deepcopy(base)
    b.org_ip_p99["IAMUser"] = 8.0
    ips = [row(i, f"2025-01-08 10:{i:02d}:00", "newcomer", f"47.{i}.{i}.{i}") for i in range(8)]
    assert not fire(ips, b, "IP003")


def test_an_older_pickled_baseline_without_the_new_fields_still_works(base):
    old = copy.deepcopy(base)
    for attr in ("ip_p99", "org_ip_p99", "ip_spread"):
        delattr(old, attr)                                        # what unpickling a pre-change baseline looks like
    ips = [row(i, f"2025-01-08 10:0{i}:00", "alice", f"45.{i}.{i}.{i}") for i in range(5)]
    assert len(fire(ips, old, "IP003")) == 1                      # falls back to the fixed threshold instead of crashing
