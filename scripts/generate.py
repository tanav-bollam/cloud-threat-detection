"""Generate a synthetic CloudTrail dataset into DuckDB.

  python scripts/generate.py --days 1 --seed 7 --out data/day1.duckdb
  python scripts/generate.py --days 7 --attacks S1,S3,S4 --count 20 --out data/week.duckdb
  python scripts/generate.py --days 3 --attacks S1+S2+S3+S4+S5 --count 3     # '+' = chained kill chain
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.generator.dataset import generate_dataset  # noqa: E402
from src.pipeline import storage  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--world-seed", type=int, default=None, help="identity/IP universe (default: same as --seed)")
    ap.add_argument("--start", default=None, help="YYYY-MM-DD (default from config)")
    ap.add_argument("--scale", type=float, default=None, help="volume multiplier")
    ap.add_argument("--attacks", default="", help="comma list of S1..S9, or chains like S1+S2+S3")
    ap.add_argument("--count", type=int, default=1, help="instances of each attack")
    ap.add_argument("--stealth", type=float, default=0.0)
    ap.add_argument("--out", default="data/cloudtrail.duckdb")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        if not a.overwrite:
            sys.exit(f"{out} exists; pass --overwrite")
        out.unlink()
    t0 = time.time()
    attacks = [x for x in a.attacks.split(",") if x]
    ds = generate_dataset(seed=a.seed, days=a.days, start=a.start, scale=a.scale, attacks=attacks, count=a.count, stealth=a.stealth, world_seed=a.world_seed)
    print(f"generated {len(ds.events):,} events ({len(ds.injections)} injections) in {time.time()-t0:.1f}s")
    con = storage.connect(out)
    n = storage.insert_events(con, ds.events)
    storage.insert_injections(con, ds.injections)
    con.close()
    print(f"wrote {n:,} events to {out} ({out.stat().st_size/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
