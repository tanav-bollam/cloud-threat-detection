"""Record the small committed demo: pre-trained models + ~24 simulated hours of activity with attacks already detected.

  python scripts/build_demo.py            # needs trained models in models/ (python scripts/train.py)
Writes demo/models/{baseline,anomaly_global}.joblib and demo/demo_snapshot.duckdb (target: about 20 MB in total).
The live dashboard copies the snapshot as its starting database and continues the stream from 2025-01-13 09:00, so the Overview, Incidents and
Investigation pages are populated the moment the app opens, with no training and no AWS account.
"""
from __future__ import annotations

import shutil
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib

from src.detection.iforest import AnomalyModel
from src.pipeline.live import LiveEngine

DEMO = Path("demo")
START, HOUR = "2025-01-12", 9.0
# (scenario spec, hours after the start) - a kill chain, a brute force, impossible travel, crypto-mining and persistence over one day
INJECTIONS = [("S1+S3+S4", 5.0), ("S8", 9.5), ("S9", 15.0), ("S7", 18.0), ("S6", 21.0)]


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    scale = float(sys.argv[1]) if len(sys.argv) > 1 else 0.08
    models = Path("models")
    base = joblib.load(models / "baseline.joblib")
    model = AnomalyModel.load(models / "anomaly_global.joblib")
    DEMO.mkdir(exist_ok=True)
    (DEMO / "models").mkdir(exist_ok=True)
    tmp = Path("data/demo_build.duckdb")
    start = datetime.strptime(START, "%Y-%m-%d") + timedelta(hours=HOUR)
    eng = LiveEngine(tmp, base, model, speed=0, scale=scale, seed=4242, start=START, start_hour=HOUR, days=2, until=start + timedelta(hours=24), seed_db=None)
    for spec, h in INJECTIONS:
        eng.inject(spec, at=start + timedelta(hours=h))
    t0 = time.time()
    eng.start()
    assert eng.wait(1800), "build did not finish"
    if eng.detector.error:
        raise eng.detector.error
    s = eng.stats()
    cur = eng.cursor()
    n_inc = cur.execute("SELECT count(*) FROM incidents").fetchone()[0]
    det = cur.execute("SELECT count(*) FROM ttd").fetchone()[0]
    det_total = cur.execute("SELECT count(*) FROM injections").fetchone()[0]
    eng.close()
    shutil.copyfile(tmp, DEMO / "demo_snapshot.duckdb")
    for f in (tmp, Path(str(tmp) + ".wal")):
        if f.exists():
            f.unlink()
    shutil.copyfile(models / "baseline.joblib", DEMO / "models" / "baseline.joblib")
    shutil.copyfile(models / "anomaly_global.joblib", DEMO / "models" / "anomaly_global.joblib")
    total = sum(f.stat().st_size for f in DEMO.rglob("*") if f.is_file())
    print(f"{s['events']:,} events, {s['alerts']} alerts, {n_inc} incidents, {det}/{det_total} injected attack stages detected in {time.time()-t0:.0f}s")
    print(f"demo/ is {total/1e6:.1f} MB (snapshot {(DEMO/'demo_snapshot.duckdb').stat().st_size/1e6:.1f} MB)")


if __name__ == "__main__":
    main()
