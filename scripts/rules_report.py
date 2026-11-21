"""Run the rules engine over a dataset and report coverage per scenario + false positives (rules-only baseline)."""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import duckdb
import pandas as pd

from src.detection.rules_engine import RulesEngine
from src.evaluation import score

path = sys.argv[1] if len(sys.argv) > 1 else "data/week.duckdb"
con = duckdb.connect(path, read_only=True)
t0 = time.time()
eng = RulesEngine()
alerts = []
cur = con.execute("SELECT raw FROM events ORDER BY event_time, event_id")
while True:
    rows = cur.fetchmany(50_000)
    if not rows:
        break
    for (raw,) in rows:
        for a in eng.evaluate(json.loads(raw)):
            alerts.append(a.to_dict())
df = pd.DataFrame(alerts)
span = con.execute("SELECT (max(event_time)-min(event_time)) FROM events").fetchone()[0].total_seconds() / 86400
print(f"evaluated in {time.time()-t0:.0f}s; {len(df)} alerts over {span:.1f} days")
res = score(df, con, span)
print(json.dumps({k: v for k, v in res.items() if k != "ttd_seconds"}, indent=1))
print("\nalerts by rule:\n", df.groupby(["rule_id", "title"]).size().to_string())
print("\nrules-only TTD (s): median", pd.Series(res["ttd_seconds"]).median())
Path("reports").mkdir(exist_ok=True)
json.dump(res, open("reports/rules_only.json", "w"), indent=1)
