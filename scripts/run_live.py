"""Run the live pipeline headless: stream events, inject attacks, report time-to-detect.

  python scripts/run_live.py --speed 0 --sim-hours 6 --inject S1+S3+S4@3600 --inject S9@9000     # as fast as possible, deterministic
  python scripts/run_live.py --speed 120 --duration 90 --inject S1+S2+S3+S4+S5@20                  # 120 sim-sec per wall-sec; inject at +20s
Injection offsets are seconds after the simulated start (sim seconds). Writes reports/live_ttd.json.
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib

from src.detection.iforest import AnomalyModel
from src.detection.triage import SuppressionList
from src.pipeline.live import LiveEngine


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/live.duckdb")
    ap.add_argument("--models", default="models")
    ap.add_argument("--no-anomaly", action="store_true")
    ap.add_argument("--speed", type=float, default=0.0, help="sim seconds per wall second; 0 = as fast as possible")
    ap.add_argument("--scale", type=float, default=0.3)
    ap.add_argument("--start", default="2025-01-13")
    ap.add_argument("--start-hour", type=float, default=9.0)
    ap.add_argument("--sim-hours", type=float, default=6.0, help="stop after this much simulated time")
    ap.add_argument("--duration", type=float, default=None, help="max wall seconds")
    ap.add_argument("--inject", action="append", default=[], help="SPEC@sim_seconds_after_start, e.g. S1+S3+S4@3600")
    ap.add_argument("--stealth", type=float, default=0.0)
    a = ap.parse_args()

    base = joblib.load(Path(a.models) / "baseline.joblib")
    model = None if a.no_anomaly else AnomalyModel.load(Path(a.models) / "anomaly_global.joblib")
    start = datetime.strptime(a.start, "%Y-%m-%d") + timedelta(hours=a.start_hour)
    eng = LiveEngine(a.db, base, model, speed=a.speed, scale=a.scale, start=a.start, start_hour=a.start_hour,
                     until=start + timedelta(hours=a.sim_hours), suppressions=SuppressionList(path="reports/suppressions_live.json"))
    schedule = []
    for item in a.inject:
        spec, off = item.split("@")
        schedule.append((spec, float(off)))
    t_build = time.time()
    if a.speed <= 0:
        for spec, off in schedule:                       # pre-schedule at explicit sim times so the stream stays time-ordered
            eng.inject(spec, at=start + timedelta(seconds=off), stealth=a.stealth)
    else:
        def injector():
            for spec, off in sorted(schedule, key=lambda x: x[1]):
                while eng.streamer.sim_now() < start + timedelta(seconds=off) and not eng.stop_flag.is_set():
                    time.sleep(0.05)
                ids = eng.inject(spec, stealth=a.stealth)
                print(f"[sim {eng.streamer.sim_now():%H:%M:%S}] injected {spec} -> {ids}", flush=True)
        threading.Thread(target=injector, daemon=True).start()
    print(f"engine ready in {time.time()-t_build:.1f}s; streaming from {start} (speed={a.speed or 'max'})", flush=True)
    t0 = time.time()
    eng.start()
    last = 0.0
    while not eng.wait(1.0):
        if eng.detector.error:
            raise eng.detector.error
        if time.time() - last > 5:
            s = eng.stats()
            print(f"  wall {s['wall_elapsed_s']:>5.0f}s | sim {s['sim_now']:%H:%M:%S} | events {s['events']:>8,} | alerts {s['alerts']:>3} | backlog {s['backlog']:>5} | step {s['last_step_ms']} ms", flush=True)
            last = time.time()
        if a.duration and time.time() - t0 > a.duration:
            eng.stop()
            break
    wall = time.time() - t0
    s = eng.stats()
    print(f"\nprocessed {s['events']:,} events in {wall:.1f}s wall ({s['events']/wall:,.0f} events/s), {s['anomaly_steps']} anomaly steps, {s['alerts']} alerts")
    cur = eng.cursor()
    ttd = cur.execute("SELECT injection_id, scenario_id, detected_by, round(ttd_sim_s,1) ttd_sim_s, round(ttd_wall_s,2) ttd_wall_s, round(pipeline_latency_ms,1) latency_ms FROM ttd ORDER BY injection_id").fetchdf()
    inj = cur.execute("SELECT count(*) FROM injections").fetchone()[0]
    print(f"\ntime-to-detect ({len(ttd)}/{inj} injections detected):\n{ttd.to_string(index=False)}")
    inc = cur.execute("SELECT incident_id, severity, risk_score, title, status FROM incidents ORDER BY risk_score DESC LIMIT 8").fetchdf()
    print(f"\ntop incidents:\n{inc.to_string(index=False)}")
    out = {"events": s["events"], "wall_s": round(wall, 1), "events_per_s": round(s["events"] / wall), "alerts": s["alerts"], "injections": inj,
           "detected": len(ttd), "ttd_sim_p50_s": float(ttd.ttd_sim_s.median()) if len(ttd) else None,
           "ttd_sim_p95_s": float(ttd.ttd_sim_s.quantile(0.95)) if len(ttd) else None,
           "pipeline_latency_p50_ms": float(ttd.latency_ms.median()) if len(ttd) else None,
           "pipeline_latency_p95_ms": float(ttd.latency_ms.quantile(0.95)) if len(ttd) else None, "per_injection": ttd.to_dict("records")}
    Path("reports").mkdir(exist_ok=True)
    json.dump(out, open("reports/live_ttd.json", "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
