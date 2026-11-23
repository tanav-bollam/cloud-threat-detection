"""Evaluate the VPC-flow correlation rules (FL001-FL003) against ground truth. Writes reports/flow_correlation.json.

  python scripts/generate_flows.py --db data/test.duckdb ; python scripts/generate_flows.py --db data/val.duckdb
  python scripts/evaluate_flows.py
Precision = share of flow alerts whose linked CloudTrail event is a labeled attack event. Recall = share of the relevant labeled attack events
(successful S7 launches, DeleteFlowLogs in S4, world-open SG ingress in S7) that got a flow alert. FP/day is measured on the benign validation week.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.detection.flow_correlation import flow_alerts  # noqa: E402
from src.pipeline import storage  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    tcon = storage.connect(str(ROOT / "data" / "test.duckdb"), read_only=True)
    vcon = storage.connect(str(ROOT / "data" / "val.duckdb"), read_only=True)
    alerts = flow_alerts(tcon)
    mal = {e for (e,) in tcon.execute("SELECT event_id FROM labels WHERE is_malicious").fetchall()}
    relevant = {
        "FL001": {e for (e,) in tcon.execute("SELECT e.event_id FROM events e JOIN labels l USING (event_id) WHERE e.event_name='RunInstances' AND e.error_code IS NULL "
                                             "AND l.is_malicious AND l.scenario_id='S7'").fetchall()},
        "FL002": {e for (e,) in tcon.execute("SELECT e.event_id FROM events e JOIN labels l USING (event_id) WHERE e.event_name='DeleteFlowLogs' AND l.is_malicious").fetchall()},
        "FL003": {e for (e,) in tcon.execute("SELECT e.event_id FROM events e JOIN labels l USING (event_id) WHERE e.event_name='AuthorizeSecurityGroupIngress' AND l.is_malicious").fetchall()},
    }
    out = {"test_flow_records": tcon.execute("SELECT count(*) FROM flows").fetchone()[0], "rules": {}}
    for rid, rel in relevant.items():
        got = [a for a in alerts if a.rule_id == rid]
        tp = [a for a in got if a.event_id in mal]
        hit = {a.event_id for a in tp}
        out["rules"][rid] = {"alerts": len(got), "true_positive_alerts": len(tp), "precision": round(len(tp) / len(got), 3) if got else None,
                             "relevant_attack_events": len(rel), "attack_events_detected": len(rel & hit), "recall": round(len(rel & hit) / len(rel), 3) if rel else None}
    vdays = (vcon.execute("SELECT max(event_time) - min(event_time) FROM events").fetchone()[0]).total_seconds() / 86400
    val = flow_alerts(vcon)
    out["validation_week"] = {"days": round(vdays, 2), "flow_records": vcon.execute("SELECT count(*) FROM flows").fetchone()[0], "false_positive_alerts": len(val),
                              "fp_per_day": round(len(val) / vdays, 2)}
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "flow_correlation.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
