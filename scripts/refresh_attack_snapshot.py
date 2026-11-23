"""Refresh config/attack_snapshot.json from MITRE's published ATT&CK STIX data (enterprise-attack).

  python scripts/refresh_attack_snapshot.py                    # downloads ~55 MB from github.com/mitre-attack/attack-stix-data
  python scripts/refresh_attack_snapshot.py --from-file data/raw/enterprise-attack.json

The snapshot (a few hundred KB) lets the tests check that every technique and tactic the project cites still exists in ATT&CK, is not revoked or
deprecated, and sits under the tactic we claim, and lets the Navigator export use the right tactic short-names, all without network access.
ATT&CK changes: v19/v20 split "Defense Evasion" into "Stealth" and "Defense Impairment" and revoked T1562 and its sub-techniques; this snapshot is how
the project noticed. Re-run this and the tests after each ATT&CK release.
"""
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parents[1] / "config" / "attack_snapshot.json"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-file", default=None)
    a = ap.parse_args()
    if a.from_file:
        raw = Path(a.from_file).read_bytes()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "cloud-threat-detection-research/0.1"})
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
    bundle = json.loads(raw)
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}

    def ext_id(o):
        for e in o.get("external_references", []):
            if e.get("source_name") == "mitre-attack":
                return e.get("external_id")
        return None

    coll = next((o for o in objs if o["type"] == "x-mitre-collection"), {})
    tactics = {o["x_mitre_shortname"]: o["name"] for o in objs if o["type"] == "x-mitre-tactic"}
    revoked_by = {}
    for r in objs:
        if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by" and r["source_ref"] in by_id and r["target_ref"] in by_id:
            revoked_by[r["source_ref"]] = ext_id(by_id[r["target_ref"]])
    techniques = {}
    for o in objs:
        if o["type"] != "attack-pattern" or not ext_id(o):
            continue
        t = {"name": o["name"], "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", []))}
        if o.get("revoked"):
            t["revoked_by"] = revoked_by.get(o["id"])
        if o.get("x_mitre_deprecated"):
            t["deprecated"] = True
        techniques[ext_id(o)] = t
    snap = {"source": URL, "attack_version": coll.get("x_mitre_version"), "modified": coll.get("modified"), "tactics": dict(sorted(tactics.items())),
            "techniques": dict(sorted(techniques.items()))}
    OUT.write_text(json.dumps(snap, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    live = sum(1 for t in techniques.values() if "revoked_by" not in t and not t.get("deprecated"))
    print(f"ATT&CK {snap['attack_version']}: {len(tactics)} tactics, {len(techniques)} techniques ({live} current) -> {OUT} ({OUT.stat().st_size/1e3:.0f} KB)")


if __name__ == "__main__":
    main()
