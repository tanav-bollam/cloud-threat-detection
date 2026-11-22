"""Download the public flaws.cloud CloudTrail dataset (Scott Piper / Summit Route) and load it into DuckDB.

  python scripts/load_flaws.py                      # download (252 MB), extract, ingest -> data/flaws.duckdb
  python scripts/load_flaws.py --from-dir DIR       # ingest already-downloaded files (e.g. the copy in Yamato-Security/suzaku-sample-data)

Source verified live: https://summitroute.com/downloads/flaws_cloudtrail_logs.tar (HTTP 200, 251,688,960 bytes, 20 gzip members, ~1.9M events).
Write-up: https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/
IP addresses and account IDs in the dataset are anonymized, so geolocation-based signals are not meaningful on it.
"""
from __future__ import annotations

import argparse
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.pipeline import ingest, storage  # noqa: E402

URL = "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar"
EXPECTED_BYTES = 251_688_960


def download(dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size == EXPECTED_BYTES:
        print(f"already downloaded: {dest}")
        return
    print(f"downloading {URL} ...")
    req = urllib.request.Request(URL, headers={"User-Agent": "cloud-threat-detection-research/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
        total = int(r.headers.get("Content-Length", 0))
        got, t0 = 0, time.time()
        while chunk := r.read(1 << 20):
            f.write(chunk)
            got += len(chunk)
            if int((time.time() - t0)) % 10 == 0:
                print(f"  {got/1e6:.0f}/{total/1e6:.0f} MB", end="\r", flush=True)
    if dest.stat().st_size != EXPECTED_BYTES:
        sys.exit(f"unexpected size {dest.stat().st_size} (expected {EXPECTED_BYTES}); the source may have changed, verify before using")
    print(f"\nsaved {dest} ({dest.stat().st_size:,} bytes)")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--from-dir", default=None)
    ap.add_argument("--raw-dir", default="data/raw")
    ap.add_argument("--out", default="data/flaws.duckdb")
    ap.add_argument("--overwrite", action="store_true")
    a = ap.parse_args()
    out = Path(a.out)
    if out.exists():
        if not a.overwrite:
            sys.exit(f"{out} exists; pass --overwrite")
        out.unlink()
    if a.from_dir:
        src = Path(a.from_dir)
    else:
        tar = Path(a.raw_dir) / "flaws_cloudtrail_logs.tar"
        download(tar)
        src = Path(a.raw_dir) / "flaws_extracted"
        if not src.exists():
            with tarfile.open(tar) as t:
                t.extractall(src, filter="data")
    con = storage.connect(out)
    t0 = time.time()
    stats = ingest.ingest(con, [src], progress=lambda s, i: print(f"  {s:,} records read, {i:,} inserted ({time.time()-t0:.0f}s)", flush=True))
    n = con.execute("SELECT count(*) FROM events").fetchone()[0]
    lo, hi = con.execute("SELECT min(event_time), max(event_time) FROM events").fetchone()
    print(f"{stats}\n{n:,} events spanning {lo} -> {hi} in {out} ({time.time()-t0:.0f}s)")
    import json
    Path("reports").mkdir(exist_ok=True)
    json.dump({**stats, "events": n, "first": str(lo), "last": str(hi), "source_url": URL, "source_bytes": EXPECTED_BYTES, "ingest_seconds": round(time.time() - t0)},
              open("reports/flaws_ingest.json", "w"), indent=1)


if __name__ == "__main__":
    main()
