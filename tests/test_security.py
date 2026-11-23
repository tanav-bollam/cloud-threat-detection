"""Regression tests for the findings of the code and security review."""
import os
import re
import stat
import sys
import threading
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import duckdb
import pytest

from app import data as D
from src import reporting
from src.integrations import webhook as W
from src.pipeline import ingest

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------------------------- analyst SQL allowlist
BLOCKED = [
    "SELECT content FROM read_text('C:/Windows/win.ini')", "SELECT * FROM read_csv('x.csv')", "SELECT * FROM read_csv_auto('x')", "SELECT * FROM read_json('x')",
    "SELECT * FROM read_parquet('x')", "SELECT * FROM parquet_scan('x')", "SELECT * FROM 'C:/Windows/win.ini'", "SELECT * FROM \"file.parquet\"", "SELECT * FROM glob('C:/*')",
    "SELECT getenv('PATH')", "SELECT getenv('CTD_WEBHOOK_URL')", "SELECT current_setting('home_directory')", "SELECT * FROM duckdb_settings()", "SELECT * FROM duckdb_tables()",
    "SELECT * FROM pragma_database_list()", "SELECT * FROM information_schema.tables", "SELECT * FROM main.labels", "SELECT * FROM labels", "SELECT * FROM injections", "SELECT * FROM ttd",
    "SELECT * FROM other.events", "SELECT 1; SELECT 2", "DROP TABLE events", "INSERT INTO events VALUES (1)", "ATTACH 'x.db'", "COPY events TO 'x.csv'", "PRAGMA database_list",
    "INSTALL httpfs", "SET threads=1", "SELECT * FROM events e JOIN read_text('x') t ON true", "SELECT (SELECT content FROM read_text('x'))",
    "WITH t AS (SELECT * FROM read_text('x')) SELECT * FROM t", "", "   ", "SELECT " + "1," * 3000 + "1",
]
ALLOWED = [
    "SELECT * FROM events", "select count(*) from alerts where severity='HIGH'", "WITH t AS (SELECT * FROM events) SELECT identity, count(*) FROM t GROUP BY 1",
    "SELECT e.identity FROM events e JOIN alerts a ON a.identity = e.identity LIMIT 5", "SELECT upper(identity), regexp_matches(user_agent, 'x') FROM events",
    "SELECT * FROM events WHERE identity IN (SELECT identity FROM incidents)", "SELECT * FROM unnest([1,2,3])", "SELECT * FROM generate_series(1, 3)",
    "SELECT date_trunc('hour', event_time) h, count(*) FROM events GROUP BY 1 ORDER BY 1", "SELECT * FROM EVENTS;",
]


@pytest.mark.parametrize("sql", BLOCKED)
def test_unsafe_analyst_queries_are_blocked(sql):
    ok, why = D.is_safe_select(sql)
    assert not ok and why, sql


@pytest.mark.parametrize("sql", ALLOWED)
def test_normal_analyst_queries_still_work(sql):
    ok, why = D.is_safe_select(sql)
    assert ok, (sql, why)


def test_every_allowed_query_actually_runs_and_blocked_files_stay_unread(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("TOP-SECRET")
    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE events(identity VARCHAR, user_agent VARCHAR, event_time TIMESTAMP)")
    con.execute("CREATE TABLE alerts(identity VARCHAR, severity VARCHAR)")
    con.execute("CREATE TABLE incidents(identity VARCHAR)")
    con.execute("INSERT INTO events VALUES ('a','ua','2025-01-01 10:00:00')")
    for sql in ALLOWED:
        ok, _ = D.is_safe_select(sql)
        assert ok
        D.run_readonly(con.cursor(), sql)
    ok, _ = D.is_safe_select(f"SELECT * FROM read_text('{secret.as_posix()}')")
    assert not ok                                                          # and the guard, not luck, is what stopped it
    assert "TOP-SECRET" in con.execute(f"SELECT content FROM read_text('{secret.as_posix()}')").fetchone()[0]


def test_expensive_query_is_stopped_by_the_timeout_and_rows_are_capped():
    con = duckdb.connect(":memory:")
    con.execute("CREATE TABLE events AS SELECT range AS x FROM range(10)")
    t0 = time.time()
    with pytest.raises(TimeoutError):
        D.run_readonly(con.cursor(), "SELECT count(*) FROM events a, events b, events c, events d, events e, events f, events g, events h, events i, events j, events k", timeout_s=1.0)
    assert time.time() - t0 < 10
    assert len(D.run_readonly(con.cursor(), "SELECT * FROM events a, events b", row_limit=7)) == 7


# ---------------------------------------------------------------------------------------------- webhook SSRF
@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://169.254.1.1/x", "http://[fe80::1]/x", "http://0.0.0.0/x", "http://224.0.0.1/x"])
def test_webhook_never_contacts_metadata_or_reserved_addresses(url):
    assert W.destination_error(url)
    with pytest.raises(ValueError):
        W._http_post(url, {}, 1.0)


def test_loopback_allowed_by_default_but_blocked_in_strict_mode(monkeypatch):
    assert W.destination_error("http://127.0.0.1:9/x") is None
    monkeypatch.setenv("CTD_WEBHOOK_STRICT", "1")
    assert W.destination_error("http://127.0.0.1:9/x") and W.destination_error("http://10.0.0.5/x") and W.destination_error("http://192.168.1.2/x")
    assert W.destination_error("http://127.0.0.1:9/x", strict=False) is None


def test_webhook_does_not_follow_redirects():
    hits = []

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            hits.append("target")
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, daemon=True).start()

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self):
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/internal")
            self.end_headers()

        def log_message(self, *a):
            pass

    red = ThreadingHTTPServer(("127.0.0.1", 0), Redirector)
    threading.Thread(target=red.serve_forever, daemon=True).start()
    try:
        with pytest.raises(OSError):                                       # urllib.error.URLError/HTTPError are OSErrors
            W._http_post(f"http://127.0.0.1:{red.server_address[1]}/hook", {"a": 1}, 3.0)
        assert hits == []                                                  # the redirect target was never contacted
    finally:
        target.shutdown()
        red.shutdown()


# ---------------------------------------------------------------------------------------------- report / header injection
EVIL = "evil|x [click](http://attacker.example) <script>alert(1)</script> `tick` **b**\nnewline"


def test_md_escape_neutralises_markdown_html_and_table_breaks():
    import markdown
    out = reporting.md_escape(EVIL)
    assert "\n" not in out and "<script" not in out
    html = markdown.markdown(f"| a | b |\n|---|---|\n| {out} | ok |", extensions=["tables"])
    assert "<script" not in html and "<a " not in html and html.count("<td>") == 2 and "<strong>" not in html


def test_report_with_hostile_log_values_stays_well_formed():
    inc = {"incident_id": "INC-1", "title": EVIL, "severity": "HIGH", "risk_score": 50, "status": "Open", "first_seen": "t0", "last_seen": "t1", "identities": [EVIL],
           "ips": [EVIL], "tactics": [], "techniques": [], "sources": ["rule"]}
    alerts = [{"detected_at": "t", "severity": "HIGH", "source": "rule", "title": EVIL, "identity": EVIL, "detail": EVIL, "reasons": []}]
    tl = [{"time": "t", "identity": EVIL, "ip": EVIL, "event": EVIL, "region": EVIL, "error": EVIL, "risk": EVIL}]
    md = reporting.to_markdown(reporting.build_report(inc, alerts, tl, [], notes=EVIL))
    assert "<script" not in md and "](http://attacker.example)" not in md
    for line in md.splitlines():
        if line.startswith("| ") and "|---" not in line and "Time (UTC)" not in line:
            assert len(re.split(r"(?<!\\)\|", line)) - 2 in (6, 7), line      # alert rows have 6 cells, timeline rows 7: no cell was split


# ---------------------------------------------------------------------------------------------- ingest hardening
def test_gunzip_refuses_a_decompression_bomb(monkeypatch):
    bomb = zlib.compress(b"0" * 5_000_000)                                # placeholder; real gzip below
    import gzip
    bomb = gzip.compress(b"0" * 5_000_000)
    monkeypatch.setattr(ingest, "MAX_DECOMPRESSED_BYTES", 1_000_000)
    with pytest.raises(ValueError, match="bomb"):
        ingest._gunzip(bomb)
    assert ingest._gunzip(gzip.compress(b"[]")) == b"[]"


def test_unreadable_files_are_skipped_and_reported_not_fatal(tmp_path, monkeypatch):
    import gzip
    import json
    (tmp_path / "good.json").write_text(json.dumps({"Records": [{"eventID": "a", "eventTime": "2020-01-01T00:00:00Z", "eventName": "X"}]}))
    (tmp_path / "corrupt.json.gz").write_bytes(b"this is not gzip data at all")
    (tmp_path / "bomb.json.gz").write_bytes(gzip.compress(b"0" * 3_000_000))
    monkeypatch.setattr(ingest, "MAX_DECOMPRESSED_BYTES", 1_000_000)
    errors: list[str] = []
    recs = list(ingest.iter_records([tmp_path], errors))
    assert len(recs) == 1 and len(errors) == 2 and any("bomb" in e for e in errors)


def test_corrupt_tar_is_reported(tmp_path):
    (tmp_path / "bad.tar").write_bytes(b"not a tar")
    errors: list[str] = []
    assert list(ingest.iter_records([tmp_path / "bad.tar"], errors)) == [] and errors


# ---------------------------------------------------------------------------------------------- downloads, container, files
def test_flaws_download_is_pinned_by_sha256(tmp_path):
    import scripts.load_flaws as L
    assert re.fullmatch(r"[0-9a-f]{64}", L.EXPECTED_SHA256)
    f = tmp_path / "x"
    f.write_bytes(b"hello")
    assert L.sha256_of(f) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_container_runs_unprivileged_and_publishes_localhost_only():
    d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert re.search(r"^USER app$", d, re.M) and "useradd" in d
    c = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert '"127.0.0.1:8501:8501"' in c
    assert (ROOT / "SECURITY.md").read_text(encoding="utf-8").startswith("# Security policy")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_settings_file_is_owner_only(tmp_path):
    from src import settings as S
    p = tmp_path / "s.json"
    S.save(S.Settings(webhook_url="https://example.org/h"), p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_local_only_files_are_ignored_by_git_and_docker():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    di = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for name in ("docs/INTERVIEW.md", "PROGRESS.md", "DECISIONS_AND_CONCERNS.md"):
        assert name in gi and name in di


# ---------------------------------------------------------------------------------------------- destructive footgun
def test_fresh_engine_refuses_to_delete_a_non_database_or_its_own_seed(tmp_path, trained):
    from src.pipeline import storage
    from src.pipeline.live import LiveEngine
    base, model = trained
    victim = tmp_path / "important.txt"
    victim.write_text("do not delete me, I am not a database")
    with pytest.raises(ValueError, match="not a DuckDB"):
        LiveEngine(victim, base, model, speed=0, scale=0.03, world_seed=9, days=1)
    assert victim.read_text().startswith("do not delete")
    snap = tmp_path / "snap.duckdb"
    storage.connect(snap).close()
    with pytest.raises(ValueError, match="same file as the seed"):
        LiveEngine(snap, base, model, speed=0, scale=0.03, world_seed=9, days=1, seed_db=snap)
    assert snap.exists()
    live = tmp_path / "live.duckdb"
    storage.connect(live).close()                                          # a real (old) DuckDB file is replaced as before
    eng = LiveEngine(live, base, model, speed=0, scale=0.03, world_seed=9, days=1)
    eng.close()


def test_tactic_chain_escapes_html():
    from app import common as C
    assert "<script>" not in C.tactic_chain(["<script>alert(1)</script>"])
