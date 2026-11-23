#!/usr/bin/env bash
# Regenerate every measured artifact in dependency order (sequential: memory). Usage: bash scripts/run_chain.sh   (log: logs/chain.log)
set -u
PY=.venv/Scripts/python.exe
step() { echo "=== $(date +%H:%M:%S) $*"; "$@" || echo "!!! FAILED: $*"; }
step $PY scripts/train.py
step $PY scripts/evaluate.py --cache
step $PY scripts/compare_models.py
step $PY scripts/robustness.py
step $PY scripts/run_live.py --speed 0 --sim-hours 3 --inject "S1+S2+S3+S4+S5@1500"
step $PY scripts/run_variant.py
step $PY scripts/validate_real.py
step $PY scripts/make_results.py
echo "=== $(date +%H:%M:%S) CHAIN DONE"
