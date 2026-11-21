"""Summary stats for a generated DuckDB dataset."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import duckdb

path = sys.argv[1] if len(sys.argv) > 1 else "data/cloudtrail.duckdb"
con = duckdb.connect(path, read_only=True)
q = lambda s: con.execute(s).fetchdf()
print(q("SELECT count(*) events, count(DISTINCT identity) identities, min(event_time) first, max(event_time) last FROM events").to_string(index=False))
print("\nEvents by identity type:\n", q("SELECT identity_type, count(*) n FROM events GROUP BY 1 ORDER BY 2 DESC").to_string(index=False))
print("\nTop event names:\n", q("SELECT event_name, count(*) n FROM events GROUP BY 1 ORDER BY 2 DESC LIMIT 10").to_string(index=False))
print("\nError rate:", q("SELECT round(100.0*count(error_code)/count(*),2) pct FROM events").pct[0], "%")
print("\nEvents per hour of day (UTC):\n", q("SELECT hour(event_time) h, count(*) n FROM events GROUP BY 1 ORDER BY 1").set_index("h").n.to_dict())
print("\nLabels:\n", q("SELECT coalesce(scenario_id,'benign') scenario, is_malicious, count(*) n FROM labels GROUP BY 1,2 ORDER BY 1").to_string(index=False))
print("\nInjections:\n", q("SELECT scenario_id, count(*) instances, sum(n_events) events FROM injections GROUP BY 1 ORDER BY 1").to_string(index=False))
