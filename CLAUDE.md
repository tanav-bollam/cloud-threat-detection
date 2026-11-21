# CLAUDE.md — cloud-threat-detection

Defensive AWS CloudTrail threat detection: synthetic logs + labeled attacks -> rules + IsolationForest + IP layer -> incidents -> Streamlit.
Full spec: `SPEC.md`. Progress: `PLAN.md`. Everything must be free/open source; no AWS account, no boto3, no hosted Streamlit.

## Commands (Windows; venv is `.venv`, Python 3.12)
- Test: `.venv/Scripts/python.exe -m pytest -q`
- Generate: `.venv/Scripts/python.exe scripts/generate.py --days 7 --attacks S1,S3 --count 3 --out data/week.duckdb --overwrite`
  (`S1+S2+S3` = chained kill chain; `--scale 0.05` for small/fast data; `--stealth 0..1`)
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
