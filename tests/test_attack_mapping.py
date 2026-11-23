"""Every MITRE ATT&CK technique and tactic the project cites must exist in the committed ATT&CK snapshot (config/attack_snapshot.json), not be
revoked/deprecated, and sit under the tactic we claim. This is what caught the revoked T1562 family and the removed 'Defense Evasion' tactic."""
import glob
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SNAP = json.loads((ROOT / "config" / "attack_snapshot.json").read_text(encoding="utf-8"))
TACTIC_BY_NAME = {name: short for short, name in SNAP["tactics"].items()}


def pairs():
    """(where, technique_id, tactic_name_or_None) for everything the project asserts about ATT&CK."""
    out = []
    for f in sorted(glob.glob(str(ROOT / "rules" / "*.yaml"))):
        for r in yaml.safe_load(open(f, encoding="utf-8")):
            out.append((f"{Path(f).name}:{r['id']}", r["mitre_technique"], r["mitre_tactic"]))
    for f in (ROOT / "config" / "scenarios.yaml", ROOT / "config" / "variants" / "held_out" / "scenarios.yaml"):
        d = yaml.safe_load(open(f, encoding="utf-8"))
        for k, v in d["scenarios"].items():
            out.append((f"{f.parent.name}/{f.name}:{k}", v["technique"], v["tactic"]))
        for name, (tech, tactic) in d["event_overrides"].items():
            out.append((f"{f.parent.name}/{f.name}:override {name}", tech, tactic))
    from src.detection.ip_analysis import META
    for rid, m in META.items():
        out.append((f"ip_analysis:{rid}", m[3], m[2]))
    for tech in yaml.safe_load(open(ROOT / "config" / "response_playbook.yaml", encoding="utf-8"))["by_technique"]:
        out.append(("response_playbook", tech, None))
    return out


PAIRS = pairs()


def test_snapshot_is_present_and_current_format():
    assert SNAP["attack_version"] and len(SNAP["tactics"]) >= 14 and len(SNAP["techniques"]) > 500
    assert "defense-impairment" in SNAP["tactics"] and "stealth" in SNAP["tactics"]     # the v19+ split of Defense Evasion
    assert "defense-evasion" not in SNAP["tactics"]


@pytest.mark.parametrize("where,tid,tactic", PAIRS, ids=[f"{w}|{t}" for w, t, _ in PAIRS])
def test_technique_exists_is_current_and_matches_its_tactic(where, tid, tactic):
    t = SNAP["techniques"].get(tid)
    assert t, f"{where}: {tid} is not an ATT&CK technique"
    assert "revoked_by" not in t, f"{where}: {tid} is REVOKED (replaced by {t.get('revoked_by')})"
    assert not t.get("deprecated"), f"{where}: {tid} is deprecated"
    if tactic:
        assert tactic in TACTIC_BY_NAME, f"{where}: '{tactic}' is not an ATT&CK tactic name"
        assert TACTIC_BY_NAME[tactic] in t["tactics"], f"{where}: {tid} ({t['name']}) is not under '{tactic}'; it is under {t['tactics']}"


def test_anomaly_feature_tactics_are_real_tactics():
    cfg = yaml.safe_load(open(ROOT / "config" / "detector.yaml", encoding="utf-8"))
    for feature, tactic in cfg["scoring"]["anomaly_feature_tactics"].items():
        assert tactic in TACTIC_BY_NAME, f"{feature} -> {tactic}"


def test_playbook_tactic_keys_are_real_tactics():
    by_tactic = yaml.safe_load(open(ROOT / "config" / "response_playbook.yaml", encoding="utf-8"))["by_tactic"]
    for tactic in by_tactic:
        assert tactic in TACTIC_BY_NAME, tactic
