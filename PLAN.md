# PLAN

Decisions: no boto3 pull (use `scripts/ingest_cloudtrail.py` file ingestor + public datasets); no Streamlit Cloud/HF Spaces
(local Docker + static GitHub Pages showcase). Stretch goals skipped except possibly ATT&CK Navigator export.

- [x] Phase 1: schema + benign generator (personas, noise, DuckDB)   — `src/generator/{schema,world,benign,catalog,geo}.py`
- [x] Phase 2: attack scenarios S1–S9 + chains + sidecar labels + CLI  — `src/generator/{attacks,dataset}.py`, `scripts/generate.py`
- [x] Phase 3: rules engine + 24 YAML rules + tests (68 tests pass; rules-only: 8/9 scenarios, 1.1 FP alerts/day)
- [x] Phase 4: features + IsolationForest + SHAP + evaluate.py (83 tests pass; reports/metrics.json)
- [ ] Phase 5: IP layer + scoring + incidents
- [ ] Phase 6: streaming pipeline + live injection + time-to-detect
- [ ] Phase 7: Streamlit dashboard
- [ ] Phase 8: Detection Quality page + ablations + robustness
- [ ] Phase 9: real-data validation (flaws.cloud, Stratus samples) + file ingestor
- [ ] Phase 10: Docker, demo snapshot, webhook, CI, README, static showcase
