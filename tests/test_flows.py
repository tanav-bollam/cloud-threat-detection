import pytest

from src.detection import flow_correlation as FC
from src.generator.dataset import generate_dataset
from src.generator.flows import generate_flows
from src.generator.world import load_yaml
from src.pipeline import storage


@pytest.fixture(scope="module")
def con(tmp_path_factory):
    ds = generate_dataset(seed=21, days=2, scale=0.05, attacks=["S4", "S7"], count=8)
    c = storage.connect(str(tmp_path_factory.mktemp("f") / "f.duckdb"))
    storage.insert_events(c, ds.events)
    storage.insert_injections(c, ds.injections)
    storage.insert_flows(c, generate_flows(c, load_yaml("org.yaml"), 0))
    return c


def test_flows_generated_with_expected_shape(con):
    n, cols = con.execute("SELECT count(*), count(DISTINCT flow_log_id) FROM flows").fetchone()
    assert n > 1000 and cols >= 2
    assert con.execute("SELECT count(*) FROM flows WHERE action NOT IN ('ACCEPT','REJECT')").fetchone()[0] == 0


def test_flow_generation_is_deterministic(con):
    a = generate_flows(con, load_yaml("org.yaml"), 0)
    b = generate_flows(con, load_yaml("org.yaml"), 0)
    assert a.equals(b)


def test_each_correlation_fires_and_points_at_a_cloudtrail_event(con):
    alerts = FC.flow_alerts(con)
    by = {}
    for a in alerts:
        by.setdefault(a.rule_id, []).append(a)
    assert "FL001" in by and "FL002" in by
    ids = {r[0] for r in con.execute("SELECT event_id FROM events").fetchall()}
    assert all(a.event_id in ids for a in alerts if a.rule_id in ("FL002", "FL003"))
    assert all(a.source == "flow" for a in alerts)
    mining_launch = {r[0] for r in con.execute("SELECT event_id FROM events WHERE event_name='RunInstances'").fetchall()}
    assert all(a.event_id in mining_launch for a in by["FL001"] if not a.event_id.startswith("flow:"))


def test_no_flow_alerts_without_flows(tmp_path):
    c = storage.connect(str(tmp_path / "e.duckdb"))
    assert FC.flow_alerts(c) == []
