"""Ingest CloudTrail exports (files, folders, .json/.json.gz/.tar) into a DuckDB database the detectors can read.

  python scripts/ingest_cloudtrail.py path/to/exports --out data/mine.duckdb
Replaces an AWS API pull: export your trail's S3 logs (or `aws cloudtrail lookup-events` output) however you like, then point this at the files.
No AWS SDK or credentials are used by this project.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pipeline import ingest, storage  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists() and a.overwrite:
        out.unlink()
    con = storage.connect(out)
    t0 = time.time()
    stats = ingest.ingest(con, a.paths, progress=lambda s, i: print(f"  {s:,} records read, {i:,} inserted ({time.time()-t0:.0f}s)", flush=True))
    n = con.execute("SELECT count(*) FROM events").fetchone()[0]
    lo, hi = con.execute("SELECT min(event_time), max(event_time) FROM events").fetchone()
    print(f"{stats}\n{n:,} events in {out} spanning {lo} -> {hi} ({time.time()-t0:.0f}s)")
    con.close()


if __name__ == "__main__":
    main()
