"""Rule coverage over real Stratus Red Team CloudTrail samples (one file per technique, from Yamato-Security/suzaku-sample-data).

Deliberately small and self-contained (only ingest + rules engine) so the same function can be run against an older checkout of the
rules to produce a reproducible 'before' number."""
from __future__ import annotations

import collections
import hashlib
from pathlib import Path
from typing import Optional

from src.detection.rules_engine import RulesEngine, load_rules
from src.pipeline.ingest import iter_records

# Rules that fire on generic behaviour rather than a specific technique: a hit from only these does not count as technique coverage.
GENERIC = {"R022", "R023"}


def stratus_coverage(root: str | Path, rule_ids: Optional[set] = None) -> dict:
    root = Path(root)
    rules = [r for r in load_rules() if rule_ids is None or r.id in rule_ids]
    meta = {r.id: r for r in rules}
    seen: dict[str, Path] = {}
    rows = []
    for f in sorted(root.rglob("*.json")):
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        if digest in seen:                     # the repo ships each technique under two names; count it once
            continue
        seen[digest] = f
        recs = sorted(iter_records([f]), key=lambda r: r["eventTime"])
        if not recs:
            continue
        region = collections.Counter(r.get("awsRegion") for r in recs).most_common(1)[0][0]
        acct = collections.Counter(r.get("recipientAccountId") for r in recs).most_common(1)[0][0]
        # the samples are anonymised (fake region names), so treat the file's own region as 'home' to avoid crediting the non-home-region rule
        eng = RulesEngine(rules=rules, context={"account_id": acct, "home_regions": [region]})
        fired = collections.Counter(a.rule_id for r in recs for a in eng.evaluate(r))
        specific = sorted(k for k in fired if k not in GENERIC)
        rows.append({"tactic": f.parent.name, "technique": f.stem, "file": str(f.relative_to(root)), "events": len(recs),
                     "event_names": sorted({r["eventName"] for r in recs}), "fired": dict(fired), "specific": specific,
                     "generic_only": bool(fired) and not specific,
                     "rule_titles": {k: meta[k].title for k in fired}})
    return {"techniques": len(rows), "covered_specific": sum(1 for r in rows if r["specific"]), "covered_any": sum(1 for r in rows if r["fired"]),
            "rules_evaluated": len(rules), "rows": rows}
