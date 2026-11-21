# CLAUDE.md — cloud-threat-detection

Defensive AWS CloudTrail threat detection: synthetic logs + labeled attacks -> rules + IsolationForest + IP layer -> incidents -> Streamlit.
Full spec: `SPEC.md`. Progress: `PLAN.md`. Everything must be free/open source; no AWS account, no boto3, no hosted Streamlit.

## Commands (Windows; venv is `.venv`, Python 3.12)
- Test: `.venv/Scripts/python.exe -m pytest -q`
- Generate: `.venv/Scripts/python.exe scripts/generate.py --days 7 --attacks S1,S3 --count 3 --out data/week.duckdb --overwrite`
  (`S1+S2+S3` = chained kill chain; `--scale 0.05` for small/fast data; `--stealth 0..1`)
- Data for training/eval: `generate.py --seed 101 --world-seed 42 --days 10 --start 2024-12-27 --out data/train.duckdb` (benign), `--seed 202 ... --days 7 --start 2025-01-06 --out data/val.duckdb` (benign), `--seed 303 ... --attacks S1,...,S9,S1+S2+S3+S4+S5 --count 6 --out data/test.duckdb`
- Train: `scripts/train.py` -> models/ ; Evaluate: `scripts/evaluate.py [--cache] [--mode global|per_group]` -> reports/metrics.json ; Rules only: `scripts/rules_report.py`
- Live: `scripts/run_live.py --speed 150 --sim-hours 3 --inject S1+S2+S3+S4+S5@1500` (speed 0 = max, deterministic; writes reports/live_ttd.json). Live code: `src/pipeline/live.py` (LiveEngine)
- Dashboard: `.venv/Scripts/python.exe -m streamlit run app/streamlit_app.py` (needs models/). Pages in app/pages, data layer app/data.py (no Streamlit, unit-tested), shared app/common.py. Page tests use streamlit.testing AppTest + tests/conftest.py `dash_engine`.
- Results pipeline: `scripts/evaluate.py --cache` -> `scripts/robustness.py` (needs the layers cache, ~12 min) -> `scripts/run_live.py` -> `scripts/make_results.py` (writes docs/RESULTS.md, docs/DETECTIONS.md). Never hand-edit those docs.
- Summarize: `.venv/Scripts/python.exe scripts/summarize.py data/week.duckdb`

## Conventions
- Imports are `from src.generator...`; pytest has `pythonpath=["."]`; scripts insert the repo root into `sys.path`.
- Generator is deterministic: all randomness from `random.Random(f"<purpose>-{seed}")`; no global RNG, no wall clock.
- **Labels are a sidecar table** (`labels`, `injections`). Detector code MUST NOT read them; only evaluation code may.
- Geo/ASN comes from `src/generator/geo.py:lookup()` (synthetic registry; stand-in for DB-IP Lite).
- Every number in `docs/RESULTS.md` must come from a script run (`scripts/evaluate.py` -> `reports/metrics.json`).
- Verify any external URL with a live request before depending on it.
- IAM/Route53/CloudFront events always log region us-east-1 (global services).
- Commit after each phase; commit messages end with the Co-Authored-By trailer.
