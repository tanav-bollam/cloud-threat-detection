# PLAN

Decisions: no boto3 pull (use `scripts/ingest_cloudtrail.py` file ingestor + public datasets); no Streamlit Cloud/HF Spaces
(local Docker + static GitHub Pages showcase). Stretch goals skipped except possibly ATT&CK Navigator export.

- [x] Phase 1: schema + benign generator (personas, noise, DuckDB)   — `src/generator/{schema,world,benign,catalog,geo}.py`
- [x] Phase 2: attack scenarios S1–S9 + chains + sidecar labels + CLI  — `src/generator/{attacks,dataset}.py`, `scripts/generate.py`
- [x] Phase 3: rules engine + 24 YAML rules + tests (68 tests pass; rules-only: 8/9 scenarios, 1.1 FP alerts/day)
- [x] Phase 4: features + IsolationForest + SHAP + evaluate.py (83 tests pass; reports/metrics.json)
- [x] Phase 5: IP layer + scoring + incidents (100 tests pass; combined incident recall 9/9 scenarios, 6/6 kill chains in one incident, 0 HIGH+ false-positive incidents/day on a benign week)
- [x] Phase 6: streaming pipeline + live injection + time-to-detect (109 tests pass; real-time replay: 9/9 injections detected, pipeline latency p50 368 ms)
- [x] Phase 7: Streamlit dashboard (134 tests pass; Overview, Alerts & Incidents, Investigation + report export, Forensics, Attack Simulator; verified in a real browser)
- [x] Phase 8: Detection Quality page + ablations + robustness (143 tests pass; combined recall 100% -> 86.9% as stealth rises; docs/RESULTS.md + DETECTIONS.md generated)
- [x] Phase 9: real-data validation + file ingestor (193 tests pass; real Stratus coverage 12/35 before -> 33/35 post-hoc; flaws.cloud 1.23M unique events)
- [x] Phase 10: Docker, demo snapshot, webhook, Settings, CI, README, static showcase (fresh clone + new venv: 212 passed, 1 skipped)

## Decisions & findings so far
- Anomaly model: **global** (persona = identity-type features) beats per-group: anomaly-only incident recall 0.952 vs 0.905 (reports/metrics*.json).
- Train/val/test share one world (`--world-seed 42`) but use independent event streams (seeds 101/202/303). Training: 10 days (first 5 build the
  baseline, last 5 give training windows). Threshold calibrated on a benign validation week to ~6 flagged windows/day.
- Bugs caught by tests along the way: err_ratio NULL-averaging (silently inflated), IAM region logging, per-run Lambda rates leaking into train/test drift.
- CAVEAT for Phase 8: rules were written knowing the synthetic scenarios, so rules recall (1.0 on S1-S8) is optimistic; the stealth/robustness
  study and the real-data runs (flaws.cloud, Stratus samples) are the honest checks.
- Live architecture: DuckDB allows one writing process, so `LiveEngine` runs streamer + detector as threads in ONE process (the Streamlit app
  will host it and read through `engine.cursor()`). The detector is event-time driven: identical alert ids at replay speed 0 and 20000 (tested).
- Ground truth (labels, injections, TTD) is owned by `GroundTruth` in the harness; a test asserts the `Detector` class never mentions it.
- TTD semantics: sim TTD = alert detected_at - first malicious event of the injection (anomaly alerts detect at window END, so ~5-15 sim-min
  worst case); an anomaly alert opened earlier that later absorbs an injection counts at the time of absorption. Pipeline latency is only
  meaningful at real-time speeds (at speed 0 the queue is pre-filled).
- Dashboard: `streamlit run app/streamlit_app.py` hosts the LiveEngine in-process (env knobs: CTD_SPEED, CTD_SCALE, CTD_DB, CTD_MODELS,
  CTD_SIM_HOURS, CTD_DAYS, CTD_WORLD_SEED). Needs `python scripts/train.py` first (models/ is git-ignored; Phase 10 adds a demo snapshot/auto-train).
- Colour: dataviz reference palette on a dark surface; severity always = symbol + label + status colour, never colour alone.
- Bugs caught by page tests/screenshots: eager dict.get default crashed the timeline; MITRE chain was ordered by first matched event
  (an early anomaly window put Persistence before Initial Access) -> now ordered by DETECTION time.
- Analyst SQL box is SELECT/WITH only and cannot see ground-truth tables (labels/injections/ttd); only the Attack Simulator reads those.
- Phase 8: graded stealth (0.25 victim UA, 0.5 victim region + same-country IP, 0.75 business hours, pace x(1+20s)). Only S1 collapses at high
  stealth; IP layer collapses at 0.6; rules fall once the UA stops looking offensive (rules' S1 recall at stealth 0 was largely the UA rule R022).
- docs/RESULTS.md and docs/DETECTIONS.md are GENERATED (`scripts/make_results.py`); never edit by hand. A test proves numbers come from the JSON.
- Per-scenario precision is one-vs-rest against the shared benign background (prevalence-dependent); FP/day on the benign week is the honest number.
- Phase 9 (real data): `scripts/load_flaws.py` (tar -> ingest, verified URL + size + 20/20 SHA-256 match with the samples repo), `scripts/ingest_cloudtrail.py`
  (any CloudTrail export, no AWS SDK), `scripts/validate_real.py` -> reports/real_data.json -> docs/REAL_DATA_FINDINGS.md (generated) + the Real Data page.
- Honest real-data number: 12/35 Stratus techniques covered by the ORIGINAL 24 rules (measured at commit 18f7504 in a pristine worktree). The 33/35 after is POST-HOC
  (17 rules R025-R041 written after reading those samples) and is a regression check only. Two shipped rules were wrong on real shapes (R017, R009).
- Real data also forced: engine-level dedupe of single-event rules (flaws.cloud 847,927 -> 7,078 alerts), R018 per-IP/hour dedupe, R023 excludes AWSService principals
  (SANS lab: 177 -> 13 alerts), lenient flatten/ingest, geo registry switch (`geo.set_enabled(False)` for real data; IPs are anonymized).
- flaws.cloud: 1,939,207 records = 1,225,784 unique events (37% exact duplicates by eventID). Aug-2019 surge (66.7x median month, Level6 RunInstances, 100% errors) found from
  raw counts; rules+anomaly both detect it, anomaly model flags ~4.7 windows/day vs a 0.5/day calibration (threshold does not transfer across regimes).
- Test lesson: parametrize reads FIXTURES at import time; merging fixtures after the decorators silently skipped 17 rules' tests until moved before them.

## Phase 10 notes (packaging) and final state
- Demo: demo/ is ~20.7 MB (models 5 MB + snapshot 15.7 MB; whole .git is ~8 MB). `LiveEngine(seed_db=...)` copies the snapshot as the starting DB and the stream
  continues from 2025-01-13 09:00, so a fresh container opens populated (6 incidents) with no training. `app/common.py` falls back to demo/models when models/ is absent.
- Verified for real: `docker compose up` from a cold container -> overview content in ~10 s; fresh `git clone` + new venv + `pip install -r requirements.txt` -> full suite passes.
- NOT verifiable here: GitHub Actions (ci.yml, pages.yml are written and YAML-valid but have never run on GitHub). No remote exists; nothing was pushed.
- Bugs found while packaging: `.gitignore` `models/` also ignored demo/models (now `/models/`); `LiveEngine.stop()` joined an unstarted thread; webhook `drain()` raced with in-flight sends.
- Webhook is off by default, http(s)-only, rate-limited, never raises into the pipeline; tested against a real local HTTP server. No real Discord/Slack endpoint was ever contacted.
- Stretch goals (ATT&CK Navigator export, VPC flow logs, autoencoder, Ollama summaries) were not done.
