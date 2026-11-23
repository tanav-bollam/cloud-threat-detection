import json
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from app import data as D
from src import reporting

PAGES = Path(__file__).resolve().parents[1] / "app" / "pages"


def run_page(name, **state):
    at = AppTest.from_file(str(PAGES / name), default_timeout=90)
    for k, v in state.items():
        at.session_state[k] = v
    return at.run()


def button(at, label_part):
    return next(b for b in at.button if label_part in b.label)


# ------------------------------------------------------------------------------------------------ data layer
def test_kpis_and_overview_queries(dash_engine):
    c = dash_engine.cursor()
    k = D.kpis(c)
    assert k["events_total"] > 0 and k["alerts"] > 0 and k["identities"] > 5
    assert k["open_by_sev"]["CRITICAL"] + k["open_by_sev"]["HIGH"] >= 1
    assert not D.events_over_time(c, hours=24).empty
    assert not D.top_risky_identities(c).empty
    ips = D.top_source_ips(c, n=20, hours=24)
    assert {"country", "network", "kind"} <= set(ips.columns)
    assert not D.latest_alerts(c).empty


def test_incident_timeline_tags_flagged_events(dash_engine):
    c = dash_engine.cursor()
    incs = D.incident_list(c)
    top = incs.sort_values(["rank", "risk_score"], ascending=False).iloc[0].to_dict()
    inc = D.get_incident(c, top["incident_id"])
    al = D.incident_alerts(c, inc["incident_id"])
    tl = D.incident_timeline(c, inc, al, dash_engine.org_known_ips)
    assert not tl.empty and set(tl["flag"]) <= {"CONTEXT", "ANOMALOUS WINDOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert (tl["flag"].isin(["HIGH", "CRITICAL"])).any()
    assert tl["event_time"].is_monotonic_increasing
    assert D.raw_event(c, tl.iloc[0]["event_id"])["eventID"] == tl.iloc[0]["event_id"]


def test_forensics_sql_builder_filters(dash_engine):
    c = dash_engine.cursor()
    victim = next(iter(dash_engine.truth.inj.values()))["victim"]
    sql, params = D.build_forensics_sql({"identity": victim, "errors_only": False})
    out = D.df(c, sql, params)
    assert len(out) > 0 and (out["identity"] == victim).all()
    sql, params = D.build_forensics_sql({"event_name": "stoplogging"})           # case-insensitive substring
    assert (D.df(c, sql, params)["event_name"] == "StopLogging").all() or D.df(c, sql, params).empty
    sql, params = D.build_forensics_sql({"errors_only": True})
    assert D.df(c, sql, params)["error_code"].notna().all()


@pytest.mark.parametrize("sql,ok", [
    ("SELECT * FROM events", True), ("with x as (select 1) select * from x", True), ("select count(*) from alerts;", True),
    ("DROP TABLE events", False), ("SELECT 1; DELETE FROM events", False), ("INSERT INTO events VALUES (1)", False),
    ("COPY events TO 'x.csv'", False), ("SELECT * FROM labels", False), ("select * from injections", False),
    ("SELECT * FROM read_csv('c:/secrets.csv')", False), ("", False), ("PRAGMA database_list", False)])
def test_sql_guard(sql, ok):
    assert D.is_safe_select(sql)[0] is ok


def test_pivots(dash_engine):
    c = dash_engine.cursor()
    inj = next(iter(dash_engine.truth.inj.values()))
    p = D.pivot_ip(c, inj["attacker_ip"])
    assert not p["identities"].empty and p["geo"].country != "ZZ"
    q = D.pivot_identity(c, inj["victim"])
    assert inj["attacker_ip"] in set(q["ips"]["source_ip"]) and "country" in q["ips"].columns


# ------------------------------------------------------------------------------------------------ report export
def test_report_contents(dash_engine):
    c = dash_engine.cursor()
    top = D.incident_list(c).sort_values(["rank", "risk_score"], ascending=False).iloc[0]
    inc = D.get_incident(c, top["incident_id"])
    al = D.incident_alerts(c, inc["incident_id"])
    tl = D.incident_timeline(c, inc, al, dash_engine.org_known_ips)
    fl = tl[tl["flag"] != "CONTEXT"]
    raw = D.raw_events(c, list(fl["event_id"]))
    rep = reporting.build_report(inc, json.loads(al.drop(columns=["matched_event_ids"]).to_json(orient="records", date_format="iso")),
                                 [{"time": str(r.event_time), "identity": r.identity, "ip": r.source_ip, "event": r.event_name, "region": r.aws_region,
                                   "error": r.error_code, "risk": r.flag} for r in fl.itertuples()], raw, notes="checked with owner")
    md = reporting.to_markdown(rep)
    for part in ("# Incident", "## Summary", "## Alerts", "## Timeline", "## Affected resources", "## Recommended response", "checked with owner", inc["title"]):
        assert part in md
    assert rep["recommended_response"] and json.dumps(rep, default=str)


def test_affected_resources_and_playbook():
    recs = [{"requestParameters": {"bucketName": "acme-prod", "userName": "mallory", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}},
            {"requestParameters": {"createVolumePermission": {"add": {"items": [{"userId": "999988887777"}]}}}},
            {"requestParameters": {}, "responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLEEXAMPLE1"}}}]
    res = reporting.affected_resources(recs)
    assert res["S3 bucket"] == ["acme-prod"] and res["External account"] == ["999988887777"] and "Access key created" in res
    steps = reporting.recommended_steps(["T1562.008"], ["Defense Evasion"])
    assert any("StartLogging" in s for s in steps) and len(steps) == len(set(steps))


# ------------------------------------------------------------------------------------------------ pages render (Streamlit AppTest)
def test_overview_page(dash_engine):
    at = run_page("overview.py")
    assert not at.exception
    labels = {m.label for m in at.metric}
    assert {"Events / min", "Events processed", "Identities monitored", "Alerts raised", "Open incidents"} <= labels
    assert any("CRITICAL" in m.value or "HIGH" in m.value for m in at.markdown)


def test_incidents_page(dash_engine):
    at = run_page("incidents.py")
    assert not at.exception
    assert len(at.dataframe) >= 2                          # incidents + alerts tables
    inc_tbl = at.dataframe[0].value
    assert "Severity" in inc_tbl.columns and len(inc_tbl) >= 1
    assert inc_tbl["Severity"].str.contains("CRITICAL|HIGH|MEDIUM|LOW").all()      # label + symbol, never colour alone


def test_investigation_page_and_status_save(dash_engine):
    c = dash_engine.cursor()
    top = D.incident_list(c).sort_values(["rank", "risk_score"], ascending=False).iloc[0]
    at = run_page("investigation.py", selected_incident=top["incident_id"])
    assert not at.exception, at.exception
    assert any("Timeline" in s.value for s in at.subheader)
    assert any("Export report" in s.value for s in at.subheader)
    at.selectbox(key=f"st_{top['incident_id']}").select("Investigating")
    at.text_area(key=f"nt_{top['incident_id']}").set_value("looked at CloudTrail gap")
    button(at, "Save status").click()
    at.run()
    row = D.get_incident(dash_engine.cursor(), top["incident_id"])
    assert row["status"] == "Investigating" and row["notes"] == "looked at CloudTrail gap"


def test_forensics_page_search_and_sql(dash_engine):
    victim = next(iter(dash_engine.truth.inj.values()))["victim"]
    at = run_page("forensics.py")
    assert not at.exception
    at.text_input(key="f_identity").set_value(victim)
    button(at, "Search").click()
    at.run()
    tbl = at.dataframe[0].value
    assert len(tbl) > 0 and (tbl["identity"] == victim).all()
    at.text_area(key="sql_text").set_value("SELECT count(*) AS n FROM events")
    button(at, "Run query").click()
    at.run()
    assert not at.exception and any("n" in getattr(d.value, "columns", []) for d in at.dataframe)
    at.text_area(key="sql_text").set_value("DROP TABLE events")
    button(at, "Run query").click()
    at.run()
    assert any("Read-only" in e.value or "Only SELECT" in e.value for e in at.error)
    assert dash_engine.cursor().execute("SELECT count(*) FROM events").fetchone()[0] > 0


def test_forensics_pivot_from_investigation_state(dash_engine):
    ip = next(iter(dash_engine.truth.inj.values()))["attacker_ip"]
    at = run_page("forensics.py", pivot_ip=ip)
    assert not at.exception
    assert at.text_input(key="f_ip").value == ip
    tbl = at.dataframe[0].value
    assert len(tbl) > 0 and (tbl["source_ip"] == ip).all()


def test_simulator_page_inject_and_results(dash_engine):
    before = dash_engine.stats()["injections"]
    at = run_page("simulator.py")
    assert not at.exception
    at.selectbox(key="sim_scenario").select("S4: Defense evasion (disable logging/detection)")
    button(at, "Inject attack").click()
    at.run()
    assert not at.exception and any("Injected S4" in s.value for s in at.success)
    assert dash_engine.stats()["injections"] == before + 1
    at.run()
    tbl = at.dataframe[0].value
    assert {"Injection", "Scenario", "Detected", "Time to detect (sim s)"} <= set(tbl.columns) and len(tbl) >= before + 1
