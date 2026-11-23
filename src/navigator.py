"""MITRE ATT&CK Navigator layer export (layer format v4.5, Navigator 5.x). Free and open source: load the JSON at
https://mitre-attack.github.io/attack-navigator/ ("Open Existing Layer" -> "Upload from local"). Nothing is uploaded by this project.

Two layers:
  coverage_layer(rules)            which techniques (under which tactic) the shipped rules are meant to detect; score = number of rules
  incident_layer(incident, alerts) the techniques an incident exercised; score = highest alert severity (1 LOW .. 4 CRITICAL)

Technique and tactic names are validated against config/attack_snapshot.json (ATT&CK enterprise data), so a layer never cites a technique that
has been revoked or placed under a tactic it does not belong to. Format reference: github.com/mitre-attack/attack-navigator layers/spec/v4.5.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
NAVIGATOR_VERSION = "5.3.2"       # latest Navigator release when this was written (spec: must be >= 4.9.0 for layer format 4.5)
LAYER_FORMAT = "4.5"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_SNAPSHOT: Optional[dict] = None
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")


def snapshot() -> dict:
    global _SNAPSHOT
    if _SNAPSHOT is None:
        _SNAPSHOT = json.loads((ROOT / "config" / "attack_snapshot.json").read_text(encoding="utf-8"))
    return _SNAPSHOT


def tactic_shortname(name: str) -> Optional[str]:
    for short, nm in snapshot()["tactics"].items():
        if nm.lower() == name.lower() or short == name.lower():
            return short
    return None


def _versions() -> dict:
    return {"attack": str(snapshot()["attack_version"]).split(".")[0], "navigator": NAVIGATOR_VERSION, "layer": LAYER_FORMAT}


def _layer(name: str, description: str, techniques: list[dict], gradient: dict, legend: list[dict]) -> dict:
    return {"name": name, "versions": _versions(), "domain": "enterprise-attack", "description": description, "filters": {"platforms": ["IaaS"]},
            "sorting": 3, "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True, "showAggregateScores": False,
                                      "countUnscored": False, "expandedSubtechniques": "annotated"},
            "hideDisabled": False, "techniques": techniques, "gradient": gradient, "legendItems": legend, "metadata": [], "links": [],
            "showTacticRowBackground": False, "tacticRowBackground": "#dddddd", "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False}


def coverage_layer(rules: Optional[Iterable] = None, name: str = "Cloud Threat Detection: rule coverage") -> dict:
    """One entry per (technique, tactic) the rules claim; score = how many rules claim it."""
    if rules is None:
        from src.detection.rules_engine import load_rules
        rules = load_rules()
    cells: dict[tuple, list] = {}
    for r in rules:
        short = tactic_shortname(r.mitre_tactic)
        if short and r.mitre_technique:
            cells.setdefault((r.mitre_technique, short), []).append(r)
    techs = [{"techniqueID": tid, "tactic": tac, "score": len(rs), "comment": "; ".join(f"{r.id} {r.title}" for r in sorted(rs, key=lambda x: x.id))[:900],
              "enabled": True, "metadata": [], "links": [], "showSubtechniques": "." in tid}
             for (tid, tac), rs in sorted(cells.items())]
    top = max((t["score"] for t in techs), default=1)
    return _layer(name, f"Techniques the {sum(len(v) for v in cells.values())} shipped detection rules are written to detect (score = number of rules). "
                        "This is intended coverage, not measured detection quality; see docs/RESULTS.md and docs/REAL_DATA_FINDINGS.md for measurements.",
                  techs, {"colors": ["#d0e2fb", "#1c5cab"], "minValue": 1, "maxValue": max(top, 2)},
                  [{"label": "1 rule", "color": "#d0e2fb"}, {"label": f"{max(top, 2)}+ rules", "color": "#1c5cab"}])


def incident_layer(incident: dict, alerts: Iterable[dict], name: Optional[str] = None) -> dict:
    """Techniques one incident exercised; score = highest alert severity among the alerts that cite the technique."""
    cells: dict[tuple, dict] = {}
    for a in alerts:
        tid, tac = a.get("mitre_technique"), tactic_shortname(a.get("mitre_tactic") or "")
        info = snapshot()["techniques"].get(tid or "")
        if not tid or not _TID.match(tid) or not tac or not info or "revoked_by" in info or info.get("deprecated"):
            continue                                    # never emit a technique ATT&CK does not currently have
        c = cells.setdefault((tid, tac), {"score": 0, "titles": []})
        c["score"] = max(c["score"], SEVERITY_RANK.get(str(a.get("severity")).upper(), 1))
        if a.get("title") not in c["titles"]:
            c["titles"].append(a.get("title"))
    techs = [{"techniqueID": tid, "tactic": tac, "score": c["score"], "comment": "; ".join(map(str, c["titles"][:5])), "enabled": True, "metadata": [], "links": [],
              "showSubtechniques": "." in tid} for (tid, tac), c in sorted(cells.items())]
    return _layer(name or f"Incident {incident.get('incident_id', '')}", f"{incident.get('title', '')}. Score = highest alert severity (1 LOW, 2 MEDIUM, 3 HIGH, 4 CRITICAL).",
                  techs, {"colors": ["#fff3b0", "#d03b3b"], "minValue": 1, "maxValue": 4},
                  [{"label": "LOW", "color": "#fff3b0"}, {"label": "CRITICAL", "color": "#d03b3b"}])


def validate_layer(layer: dict) -> list[str]:
    """Structural check against the v4.5 layer spec and the ATT&CK snapshot. Returns a list of problems (empty = valid)."""
    snap, probs = snapshot(), []
    for k in ("name", "domain", "versions"):
        if k not in layer:
            probs.append(f"missing required field {k}")
    v = layer.get("versions", {})
    if v.get("layer") != LAYER_FORMAT:
        probs.append(f"versions.layer must be {LAYER_FORMAT}")
    if tuple(int(x) for x in str(v.get("navigator", "0")).split(".")[:2]) < (4, 9):
        probs.append("versions.navigator must be at least 4.9.0")
    if layer.get("domain") not in ("enterprise-attack", "mobile-attack", "ics-attack"):
        probs.append("bad domain")
    lay = layer.get("layout", {})
    if lay.get("layout", "side") not in ("side", "flat", "mini") or lay.get("aggregateFunction", "average") not in ("average", "min", "max", "sum") \
            or lay.get("expandedSubtechniques", "none") not in ("none", "all", "annotated"):
        probs.append("bad layout values")
    seen = set()
    for t in layer.get("techniques", []):
        tid, tac = t.get("techniqueID", ""), t.get("tactic")
        if not _TID.match(tid):
            probs.append(f"bad techniqueID {tid}")
            continue
        info = snap["techniques"].get(tid)
        if not info:
            probs.append(f"{tid} is not an ATT&CK technique")
        elif "revoked_by" in info or info.get("deprecated"):
            probs.append(f"{tid} is revoked/deprecated")
        if tac and tac not in snap["tactics"]:
            probs.append(f"{tid}: unknown tactic {tac}")
        elif tac and info and tac not in info["tactics"]:
            probs.append(f"{tid} is not under tactic {tac}")
        if (tid, tac) in seen:
            probs.append(f"duplicate {tid}/{tac}")
        seen.add((tid, tac))
        if not isinstance(t.get("score", 0), (int, float)):
            probs.append(f"{tid}: score must be a number")
    g = layer.get("gradient")
    if g and (not g.get("colors") or "minValue" not in g or "maxValue" not in g or g["minValue"] > g["maxValue"]):
        probs.append("bad gradient")
    return probs
