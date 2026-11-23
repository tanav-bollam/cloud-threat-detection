import json

import pytest

from src import navigator as N
from src.detection.rules_engine import load_rules


def test_coverage_layer_is_valid_and_covers_every_rule_technique():
    layer = N.coverage_layer()
    assert N.validate_layer(layer) == []
    assert layer["versions"]["layer"] == "4.5" and layer["domain"] == "enterprise-attack"
    claimed = {(r.mitre_technique, N.tactic_shortname(r.mitre_tactic)) for r in load_rules()}
    got = {(t["techniqueID"], t["tactic"]) for t in layer["techniques"]}
    assert got == claimed
    assert sum(t["score"] for t in layer["techniques"]) == len(load_rules())          # every rule counted exactly once
    cloud_logs = next(t for t in layer["techniques"] if t["techniqueID"] == "T1685.002")
    assert cloud_logs["tactic"] == "defense-impairment" and cloud_logs["score"] >= 4 and "R001" in cloud_logs["comment"]
    json.dumps(layer)                                                                  # serialisable


def test_current_attack_names_are_used_not_the_revoked_ones():
    ids = {t["techniqueID"] for t in N.coverage_layer()["techniques"]}
    assert not any(i.startswith("T1562") for i in ids)
    assert {"T1685", "T1685.002", "T1686.001", "T1666", "T1530"} <= ids
    assert N.tactic_shortname("Defense Impairment") == "defense-impairment" and N.tactic_shortname("Defense Evasion") is None


def alert(tid, tac, sev, title="t"):
    return {"mitre_technique": tid, "mitre_tactic": tac, "severity": sev, "title": title}


def test_incident_layer_scores_highest_severity_per_technique_and_skips_unmapped_alerts():
    inc = {"incident_id": "INC-1", "title": "Multi-stage activity on alice"}
    alerts = [alert("T1685.002", "Defense Impairment", "CRITICAL", "Trail stopped"), alert("T1685.002", "Defense Impairment", "HIGH", "Trail weakened"),
              alert("T1098.003", "Privilege Escalation", "HIGH"), alert("T1078.004", "Initial Access", "MEDIUM"),
              alert("", "", "MEDIUM", "anomaly with no technique"), alert("T9999", "Initial Access", "LOW"), alert("T1078.004", "Not a tactic", "LOW")]
    layer = N.incident_layer(inc, alerts)
    by = {t["techniqueID"]: t for t in layer["techniques"]}
    assert "T9999" not in by and "" not in by and len(by) == 3                    # unknown technique, empty technique and unknown tactic are all dropped
    assert by["T1685.002"]["score"] == 4 and "Trail stopped" in by["T1685.002"]["comment"] and by["T1098.003"]["score"] == 3 and by["T1078.004"]["score"] == 2
    assert N.validate_layer(layer) == []
    assert layer["gradient"]["maxValue"] == 4 and layer["name"] == "Incident INC-1"


def test_validator_catches_the_mistakes_we_actually_made():
    base = N.coverage_layer()
    bad = json.loads(json.dumps(base))
    bad["techniques"].append({"techniqueID": "T1562.008", "tactic": "defense-evasion", "score": 1})
    probs = " | ".join(N.validate_layer(bad))
    assert "revoked" in probs and "unknown tactic defense-evasion" in probs
    wrong = json.loads(json.dumps(base))
    wrong["techniques"].append({"techniqueID": "T1530", "tactic": "exfiltration", "score": 1})
    assert "not under tactic exfiltration" in " | ".join(N.validate_layer(wrong))
    dup = json.loads(json.dumps(base))
    dup["techniques"].append(dict(dup["techniques"][0]))
    assert "duplicate" in " | ".join(N.validate_layer(dup))
    worse = {"name": "x", "domain": "nope", "versions": {"layer": "3.0", "navigator": "4.0.0"}}
    p = " | ".join(N.validate_layer(worse))
    assert "versions.layer" in p and "4.9.0" in p and "bad domain" in p
    assert any("bad gradient" in x for x in N.validate_layer({**base, "gradient": {"colors": [], "minValue": 5, "maxValue": 1}}))
