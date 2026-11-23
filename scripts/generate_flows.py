"""Add synthetic VPC Flow Logs to an existing dataset (a `flows` table), correlated with its CloudTrail events.

  python scripts/generate_flows.py --db data/test.duckdb
  python scripts/generate_flows.py --db data/val.duckdb --config-dir config/variants/held_out
Idempotent: re-running replaces the table. Needs the dataset's events (and its labels, if present, to know which launches are simulated mining).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

for _i, _a in enumerate(sys.argv):
    if _a == "--config-dir" and _i + 1 < len(sys.argv):
        os.environ["CTD_CONFIG_DIR"] = sys.argv[_i + 1]

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.generator.flows import generate_flows  # noqa: E402
from src.generator.world import load_yaml  # noqa: E402
from src.pipeline import storage  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--config-dir", default=None)
    a = ap.parse_args()
    t0 = time.time()
    con = storage.connect(a.db)
    df = generate_flows(con, load_yaml("org.yaml"), a.seed)
    n = storage.insert_flows(con, df)
    print(f"{n:,} flow records in {a.db} ({time.time()-t0:.0f}s); by action: {df['action'].value_counts().to_dict() if n else {}}")
    con.close()


if __name__ == "__main__":
    main()
