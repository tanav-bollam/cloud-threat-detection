import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
from streamlit.testing.v1 import AppTest

from src import settings as S
from src.detection.rules_engine import Alert, RulesEngine
from src.integrations.webhook import WebhookNotifier, build_payload, detect_kind, valid_url
from tests.test_rules import mk

ROOT = Path(__file__).resolve().parents[1]


def alert(sev="HIGH", title="CloudTrail logging stopped", **kw):
    return Alert("R001", title, sev, "Defense Impairment", "T1685.002", "e1", "2025-01-13T10:00:00Z", "alice", "45.1.1.1", "desc", risk=60.0, source="rule", **kw)


class Capture:
    """A real local HTTP endpoint that records JSON POST bodies."""

    def __init__(self, status=200):
        self.bodies, self.status = [], status
        cap = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                cap.bodies.append(json.loads(self.rfile.read(n)))
                self.send_response(cap.status)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def endpoint():
    c = Capture()
    yield c
    c.close()


# ------------------------------------------------------------------------------------------------ webhook
def test_url_validation_and_kind_detection():
    assert valid_url("https://discord.com/api/webhooks/1/x") and valid_url("http://127.0.0.1:9/h")
    for bad in ("file:///etc/passwd", "javascript:alert(1)", "ftp://x/y", "not a url", "", "http://"):
        assert not valid_url(bad), bad
    assert detect_kind("https://discord.com/api/webhooks/1/x") == "discord"
    assert detect_kind("https://hooks.slack.com/services/T/B/x") == "slack"
    assert detect_kind("https://example.org/hook") == "generic"
    with pytest.raises(ValueError):
        WebhookNotifier("file:///tmp/x")


def test_payload_shapes():
    a = alert("CRITICAL")
    d = build_payload(a, "discord")
    assert d["embeds"][0]["title"].startswith("◆ CRITICAL") and d["embeds"][0]["color"] == 0xD03B3B
    assert {"Identity", "Source IP", "MITRE"} <= {f["name"] for f in d["embeds"][0]["fields"]}
    s = build_payload(a, "slack")
    assert set(s) == {"text"} and "alice" in s["text"] and "45.1.1.1" in s["text"]
    g = build_payload(a, "generic")
    assert g["severity"] == "CRITICAL" and g["identity"] == "alice"


def test_delivers_only_alerts_at_or_above_threshold(endpoint):
    n = WebhookNotifier(endpoint.url, "HIGH", kind="slack")
    for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        n(alert(sev))
    n.drain()
    assert len(endpoint.bodies) == 2 and n.stats["sent"] == 2 and n.stats["skipped_below_threshold"] == 2
    assert "HIGH" in endpoint.bodies[0]["text"] and "CRITICAL" in endpoint.bodies[1]["text"]
    n.close()


def test_rate_limit_caps_messages_per_minute(endpoint):
    n = WebhookNotifier(endpoint.url, "LOW", max_per_minute=3)
    for i in range(10):
        n(alert("HIGH", title=f"a{i}"))
    n.drain()
    assert n.stats["sent"] == 3 and n.stats["dropped_rate_limit"] == 7
    n.close()


def test_a_dead_or_failing_endpoint_never_raises_into_the_pipeline():
    n = WebhookNotifier("http://127.0.0.1:9/nothing-listens-here", "LOW", timeout=0.5)
    n(alert())                                        # must return immediately and never raise
    n.drain(3)
    assert n.stats["failed"] == 1 and n.stats["last_error"]
    ok, detail = n.send_test()
    assert not ok and detail
    n.close()
    bad = Capture(status=500)
    try:
        m = WebhookNotifier(bad.url, "LOW")
        m(alert())
        m.drain()
        assert m.stats["failed"] == 1 and "500" in m.stats["last_error"]          # an HTTP error status is a failure, not a crash
        m.close()
    finally:
        bad.close()


def test_queue_is_bounded():
    blocker = threading.Event()
    n = WebhookNotifier("http://127.0.0.1:9/x", "LOW", queue_size=2, post=lambda u, p, t: blocker.wait(5) or 200)
    for _ in range(6):
        n(alert())
    assert n.stats["dropped_queue_full"] >= 3
    blocker.set()
    n.close()


def test_send_test_posts_a_marked_test_message(endpoint):
    n = WebhookNotifier(endpoint.url, "HIGH", kind="generic")
    ok, _ = n.send_test()
    assert ok and endpoint.bodies[0]["title"].startswith("Test notification")
    n.close()


# ------------------------------------------------------------------------------------------------ settings
def test_settings_round_trip_validation_and_env_secret(tmp_path, monkeypatch):
    p = tmp_path / "s.json"
    s = S.Settings(disabled_rules=["R022"], dedupe_s=120, anomaly_sensitivity=-0.05, webhook_url="https://example.org/h", webhook_min_severity="MEDIUM")
    S.save(s, p)
    assert S.load(p) == s
    monkeypatch.setenv("CTD_WEBHOOK_URL", "https://secret.example/hook")
    assert S.load(p).webhook_url == "https://secret.example/hook"          # environment wins
    S.save(S.load(p), p)
    assert "secret.example" not in p.read_text()                           # an env-provided secret is never written to disk
    monkeypatch.delenv("CTD_WEBHOOK_URL")
    p.write_text("{ not json")
    assert S.load(p) == S.Settings()                                       # corrupt file -> defaults
    assert S.Settings(dedupe_s=-1).validate() and S.Settings(anomaly_sensitivity=0.9).validate() and S.Settings(webhook_url="file:///x").validate()
    assert not S.Settings().validate()


class FakeEngine:
    def __init__(self):
        units = {"all": SimpleNamespace(threshold=0.60), "x": SimpleNamespace(threshold=0.70)}
        self.detector = SimpleNamespace(rules=RulesEngine())
        self.model = SimpleNamespace(units=units)
        self.callbacks = []


def test_apply_disables_rules_sets_dedupe_and_shifts_thresholds_reversibly():
    e = FakeEngine()
    S.apply(e, S.Settings(disabled_rules=["R001"], dedupe_s=42, anomaly_sensitivity=-0.1))
    assert e.detector.rules.disabled == {"R001"} and e.detector.rules.dedupe_s == 42
    assert e.model.units["all"].threshold == pytest.approx(0.50) and e.model.units["x"].threshold == pytest.approx(0.60)
    assert not [a for a in e.detector.rules.evaluate(mk("StopLogging")) if a.rule_id == "R001"]
    S.apply(e, S.Settings(anomaly_sensitivity=0.05))                        # offset is from the CALIBRATED value, not cumulative
    assert e.model.units["all"].threshold == pytest.approx(0.65)
    S.apply(e, S.Settings())
    assert e.model.units["all"].threshold == pytest.approx(0.60)
    assert [a for a in e.detector.rules.evaluate(mk("StopLogging", t=500)) if a.rule_id == "R001"]


def test_apply_adds_and_replaces_the_webhook(endpoint):
    e = FakeEngine()
    S.apply(e, S.Settings(webhook_url=endpoint.url))
    assert len(e.callbacks) == 1
    first = e.callbacks[0]
    S.apply(e, S.Settings(webhook_url=endpoint.url, webhook_min_severity="CRITICAL"))
    assert len(e.callbacks) == 1 and e.callbacks[0] is not first and e.callbacks[0].min_severity == "CRITICAL"
    S.apply(e, S.Settings())
    assert e.callbacks == []
    assert S.apply(e, S.Settings(webhook_url="file:///x"))                  # invalid URL -> a warning, no crash, no callback
    assert e.callbacks == []


# ------------------------------------------------------------------------------------------------ demo snapshot
def test_snapshot_seeds_a_fresh_engine(tmp_path, trained):
    from src.pipeline import storage
    from src.pipeline.live import LiveEngine
    snap = tmp_path / "snap.duckdb"
    con = storage.connect(snap)
    storage.insert_events(con, [(mk("StopLogging"), None)])
    con.execute("INSERT INTO incidents VALUES ('INC-SNAP','t','HIGH',50,'2025-01-12 10:00:00','2025-01-12 10:05:00','[]','[]','[]','[]','[]','[]',1,'Open','')").fetchall()
    con.close()
    base, model = trained
    eng = LiveEngine(tmp_path / "live.duckdb", base, model, speed=0, scale=0.03, world_seed=9, days=1, seed_db=snap)
    cur = eng.cursor()
    assert cur.execute("SELECT count(*) FROM events").fetchone()[0] == 1
    assert cur.execute("SELECT incident_id FROM incidents").fetchone()[0] == "INC-SNAP"
    eng.close()


def test_committed_demo_fits_the_20mb_budget_and_loads():
    demo = ROOT / "demo"
    if not demo.exists():
        pytest.skip("demo/ not built (run scripts/build_demo.py)")
    total = sum(f.stat().st_size for f in demo.rglob("*") if f.is_file())
    assert total < 25e6, f"demo is {total/1e6:.1f} MB"
    import joblib
    from src.detection.iforest import AnomalyModel
    assert joblib.load(demo / "models" / "baseline.joblib").identity_types
    assert AnomalyModel.load(demo / "models" / "anomaly_global.joblib").units
    import duckdb
    con = duckdb.connect(str(demo / "demo_snapshot.duckdb"), read_only=True)
    assert con.execute("SELECT count(*) FROM events").fetchone()[0] > 5000
    assert con.execute("SELECT count(*) FROM incidents").fetchone()[0] >= 3
    assert con.execute("SELECT count(*) FROM ttd").fetchone()[0] >= 3


# ------------------------------------------------------------------------------------------------ page
def test_settings_page_renders_saves_and_applies(dash_engine, tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setenv("CTD_SETTINGS", str(path))
    at = AppTest.from_file(str(ROOT / "app" / "pages" / "settings.py"), default_timeout=60).run()
    assert not at.exception, at.exception
    at.number_input(key="set_dedupe").set_value(120.0)
    at.slider(key="set_sens").set_value(-0.05)
    next(b for b in at.button if "Save" in b.label).click()
    at.run()
    assert not at.exception and any("Saved" in s.value for s in at.success)
    saved = S.load(path)
    assert saved.dedupe_s == 120.0 and saved.anomaly_sensitivity == pytest.approx(-0.05)
    assert dash_engine.detector.rules.dedupe_s == 120.0
    S.apply(dash_engine, S.Settings())                                     # leave the shared engine as we found it


def test_settings_page_rejects_an_invalid_webhook(dash_engine, tmp_path, monkeypatch):
    monkeypatch.setenv("CTD_SETTINGS", str(tmp_path / "s.json"))
    at = AppTest.from_file(str(ROOT / "app" / "pages" / "settings.py"), default_timeout=60).run()
    at.text_input(key="set_url").set_value("file:///etc/passwd")
    next(b for b in at.button if "Save" in b.label).click()
    at.run()
    assert any("http" in e.value for e in at.error) and not (tmp_path / "s.json").exists()
