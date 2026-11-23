"""Held-out generator variant: does the METHOD generalise to an organisation it was never tuned on?

  python scripts/run_variant.py            # ~10 min -> reports/metrics_variant.json

A second synthetic organisation (config/variants/held_out/: other regions, time zones, headcount, API mixes, analysts doing heavy S3 reads,
attackers with ordinary-looking user agents and instance sizes the rules do not list). The detector CODE and CONFIG are unchanged; what is
re-learned is exactly what a new customer would re-learn: per-identity baselines, the IsolationForest and its threshold, from that
organisation's own benign data. Rules and the IP layer are used as shipped.
Resumable: every finished step (data files, models, metrics) is skipped on re-run; pass --force to redo everything.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VARIANT_DIR = ROOT / "config" / "variants" / "held_out"
PY = sys.executable
ATTACKS = "S1,S2,S3,S4,S5,S6,S7,S8,S9,S1+S2+S3+S4+S5"


def run(cmd: list[str], env: dict) -> None:
    print("  $", " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env=env)
    if r.returncode:
        sys.exit(f"step failed ({r.returncode}): {' '.join(map(str, cmd))}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--keep-data", action="store_true", help="keep the ~3 GB of generated variant datasets")
    a = ap.parse_args()
    env = {**os.environ, "CTD_CONFIG_DIR": str(VARIANT_DIR), "PYTHONIOENCODING": "utf-8"}
    t0 = time.time()
    data = {"train": ROOT / "data" / "variant_train.duckdb", "val": ROOT / "data" / "variant_val.duckdb", "test": ROOT / "data" / "variant_test.duckdb"}
    gen = ROOT / "scripts" / "generate.py"
    steps = {
        "train": ["--seed", "111", "--world-seed", "77", "--days", "10", "--start", "2024-12-27"],
        "val": ["--seed", "212", "--world-seed", "77", "--days", "7", "--start", "2025-01-06"],
        "test": ["--seed", "313", "--world-seed", "77", "--days", "7", "--start", "2025-01-06", "--attacks", ATTACKS, "--count", "6"],
    }
    for name, extra in steps.items():
        if data[name].exists() and not a.force:
            print(f"[skip] {name} data exists")
            continue
        print(f"[generate] {name}", flush=True)
        run([PY, str(gen), *extra, "--config-dir", str(VARIANT_DIR), "--out", str(data[name]), "--overwrite"], env)
    models = ROOT / "models_variant"
    if (models / "anomaly_global.joblib").exists() and not a.force:
        print("[skip] variant models exist")
    else:
        print("[train] baseline + IsolationForest on the variant's own benign data", flush=True)
        run([PY, str(ROOT / "scripts" / "train.py"), "--train", str(data["train"]), "--val", str(data["val"]), "--out", str(models)], env)
    out_dir = ROOT / "reports" / "variant"
    if (out_dir / "metrics.json").exists() and not a.force:
        print("[skip] variant metrics exist")
    else:
        print("[evaluate] rules + IsolationForest + IP layer on the held-out week", flush=True)
        run([PY, str(ROOT / "scripts" / "evaluate.py"), "--test", str(data["test"]), "--val", str(data["val"]), "--models", str(models), "--out-dir", str(out_dir)], env)
    shutil.copyfile(out_dir / "metrics.json", ROOT / "reports" / "metrics_variant.json")
    print(f"done in {time.time()-t0:.0f}s -> reports/metrics_variant.json")
    if not a.keep_data:
        for p in data.values():
            for f in (p, Path(str(p) + ".wal")):
                if f.exists():
                    f.unlink()
        shutil.rmtree(models, ignore_errors=True)
        shutil.rmtree(out_dir, ignore_errors=True)
        print("removed the generated variant data, models and scratch reports (re-run regenerates them)")


if __name__ == "__main__":
    main()
