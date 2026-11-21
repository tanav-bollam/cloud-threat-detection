# SPEC: Cloud Threat Detection System (AWS CloudTrail Security Monitoring)

> Give this file to Claude Code as `SPEC.md` at the root of a new, empty repo.
> Build it **one phase at a time** (see "Build Phases"). Stop after each phase, run it, and show the output.
> This is a **defensive** security tool. It analyzes logs and never attacks anything.

## 1. What we are building

A cloud security monitoring tool for AWS audit logs. It:
1. **Generates realistic synthetic AWS CloudTrail logs.** Normal activity comes from simulated users, admins and service roles. Labeled attack scenarios (compromised credentials, recon, privilege escalation, defense evasion, exfiltration, persistence, crypto-mining) are injected on top.
2. **Detects threats** with three layers:
   - a rules engine for high-risk API calls
   - **IsolationForest** behavioral anomaly detection per identity and time window
   - IP/access-pattern analysis (new IPs, impossible travel, one IP used by many identities)
3. **Raises live alerts.** Events stream in continuously, are scored on sliding windows, and become alerts that are grouped into incidents with severity and a MITRE ATT&CK mapping.
4. **Provides an interactive Streamlit dashboard** for incident triage, investigation and forensics: timelines, raw event JSON, IP/identity pivots, "why was this flagged" explanations and an exportable incident report.

Everything runs locally on a laptop CPU with **no AWS account and no cost**. Ingesting real CloudTrail from your own AWS account is optional.

### The demo (what someone sees in 60 seconds)
1. `docker compose up`, then open the dashboard. The **Overview** shows live event throughput, open alerts by severity, top risky identities and a map/table of source IPs.
2. In the **Attack Simulator** panel, click "Inject: Compromised access key → privilege escalation → disable CloudTrail".
3. Within seconds, alerts appear: *"Access key AKIA…XYZ used from new country + unusual user agent"*, then *"AttachUserPolicy AdministratorAccess"*, then **CRITICAL** *"cloudtrail:StopLogging"*. They are grouped into one **incident**.
4. Open the incident. You see a timeline of everything that identity did, a severity score, MITRE tactics (Initial Access → Privilege Escalation → Defense Evasion), the features that made IsolationForest flag it, and the raw CloudTrail JSON.
5. Click the attacker IP to pivot to every identity and event tied to it. Mark the incident as "Investigating" and export a Markdown/JSON incident report.
6. The **Detection Quality** page shows precision/recall per attack type and time-to-detect, measured against the generator's ground-truth labels.
7. The **Real Data** page runs the detector over the public flaws.cloud CloudTrail dataset (real attack traffic) and shows what it finds.

## 2. Tech stack (all free / open source)

| Concern | Choice |
|---|---|
| Language | Python 3.11+ |
| Log generation | Custom generator (Faker + NumPy), output conforms to the real CloudTrail record schema |
| Storage | **DuckDB** (fast analytics over millions of events; reads JSON/Parquet directly) |
| Streaming | Generator → local queue (Python `multiprocessing.Queue`, or Redis if you want an extra container) → detector worker |
| ML | **scikit-learn** `IsolationForest`; **SHAP** `TreeExplainer` for per-alert explanations |
| Rules | YAML rule definitions (Sigma-inspired), evaluated in Python |
| GeoIP (optional) | **DB-IP Lite** free country/city database (CC BY 4.0). The generator also attaches its own synthetic geo so nothing is required |
| Threat intel (optional) | Public Tor exit-node list; a local IP blocklist file |
| Dashboard | **Streamlit** + Plotly + `streamlit-aggrid` (or `st.dataframe`) |
| Alert delivery | In-app toasts + optional Discord/Slack incoming webhook (free) |
| Real AWS (optional) | `boto3` CloudTrail `lookup_events` (read-only) against **your own** account's free 90-day Event history |
| Tests | pytest, hypothesis |
| Hosting | Streamlit Community Cloud or Hugging Face Spaces (free tiers; confirm current limits), or local Docker |
| CI | GitHub Actions |

## 3. CloudTrail schema & synthetic generator

> **Claude Code: before writing the generator, read the official AWS "CloudTrail record contents" documentation and a few real sample records (flaws.cloud, Stratus Red Team samples). Match field names, nesting and value formats exactly.**

Each event must include at least: `eventVersion, eventTime, eventSource, eventName, awsRegion, sourceIPAddress, userAgent, userIdentity{type, principalId, arn, accountId, accessKeyId, userName, sessionContext{…mfaAuthenticated…}}, requestParameters, responseElements, errorCode, errorMessage, requestID, eventID, readOnly, eventType, managementEvent, recipientAccountId`.

Each generated event also carries a **sidecar label** stored in a separate table, never inside the CloudTrail record, so the detector can't cheat: `{eventID, is_malicious, scenario_id, technique, mitre_tactic}`.

### 3a. Benign baseline: "a normal week in a 50-person startup"
`config/org.yaml` defines:
- **Personas**:
  - developers: EC2/S3/Lambda/Logs, working hours, 1–2 home IPs + office IP, `aws-cli` / `Boto3` / console user agents
  - admins: IAM changes, rare but legitimate
  - data analysts: Athena/S3 reads
  - CI/CD service role: high-volume and very regular, from a fixed IP range, assumed-role identity
  - Lambda execution roles
  - break-glass root: should almost never appear
- Per-persona API mix (weighted `eventName` distributions), active hours with weekday/weekend patterns, home regions, typical error rates (e.g. occasional `AccessDenied`), and session behavior (ConsoleLogin → activity → idle).
- Realistic noise: on-call engineers working at night, a developer travelling (new IP, same country), a new hire's first week, scheduled admin maintenance. These are benign but unusual, so they test the false-positive rate.
- Configurable scale: default 7 simulated days ≈ 1–3M events; streaming mode emits events at real-time or accelerated speed.

### 3b. Attack scenarios (labeled, injectable)
Model each scenario on documented attacker behavior: MITRE ATT&CK Cloud techniques, the **Stratus Red Team** technique catalog, and traildiscover.cloud. Each scenario is a sequence of CloudTrail events with realistic timing.

| ID | Scenario | Key signals in the logs |
|---|---|---|
| S1 | Leaked access key used from attacker infrastructure | Known identity, **new IP/ASN/country**, new user agent (e.g. scripted tooling), off-hours |
| S2 | Reconnaissance / enumeration | Burst of `List*`/`Describe*`/`Get*` across many services, high `AccessDenied` ratio, `GetCallerIdentity` first |
| S3 | IAM privilege escalation | `CreateAccessKey` for *another* user, `AttachUserPolicy`/`PutUserPolicy` with admin rights, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, `PassRole` + `CreateFunction` |
| S4 | Defense evasion | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, GuardDuty `DeleteDetector`, `DeleteFlowLogs` |
| S5 | Data exfiltration | Spike in S3 `GetObject` from a new IP, `PutBucketPolicy`/`PutBucketAcl` making a bucket public, `ModifySnapshotAttribute` sharing a snapshot with an external account |
| S6 | Persistence | `CreateUser`, new access keys, backdoor role trust policy to an external account, Lambda backdoor |
| S7 | Crypto-mining | `RunInstances` of large GPU instance types in a region the org never uses, `RequestSpotInstances` |
| S8 | Console brute force / risky login | Many failed `ConsoleLogin`, then success; root login; login without MFA |
| S9 | Impossible travel | Same identity from two distant geos within minutes |

Scenarios can be scheduled in batch generation (`--attacks S1,S3,S4 --count 20`) or **injected live** from the dashboard. Chained "kill chain" combos (S1→S2→S3→S4→S5) are supported.

## 4. Detection engine

### 4a. Rules layer (`rules/*.yaml`)
- Each rule has: `id, title, severity, mitre_tactic, mitre_technique, condition` (event field matches, optional thresholds over a window), `description` and `false_positive_notes`.
- Ship ~20 rules covering S3–S8: e.g. CloudTrail tampering, GuardDuty disabled, admin policy attached, public bucket policy, snapshot shared externally, root usage, console login without MFA, N failed logins.
- Rules fire instantly on single events. They are precise but only catch what they know.

### 4b. Behavioral anomaly layer (IsolationForest)
- Aggregate events per **identity × 15-minute window** (sliding, with a 5-minute step).
- Feature vector per window (compute each relative to *that identity's own* 30-day/7-day baseline where noted):
  - event count; distinct `eventName`s; distinct services; `readOnly` ratio; error ratio (`AccessDenied` etc.)
  - share of high-risk API calls (IAM writes, logging changes, sharing/permission changes)
  - `List/Describe/Get` burst ratio (recon signature)
  - new-IP flag, new-ASN flag, new-country flag, new-user-agent flag, new-region flag (vs baseline)
  - hour-of-day deviation from the identity's usual hours; weekend flag
  - geo distance / implied travel speed since the previous event
  - bytes/objects read from S3 (from `requestParameters`/`additionalEventData` where available) vs baseline
- Train on benign-only historical windows; standardize features; tune `contamination` and `n_estimators`.
- Train per persona group, or globally with persona as a feature. Compare both and document the choice.
- **Explainability:** SHAP values per flagged window, shown as "top 5 reasons" in the UI. Example: `new_country=1 (+0.31)`, `iam_write_share=0.4 (+0.22)`.

### 4c. IP / access-pattern layer
- One IP used by many unrelated identities. An identity seen from many IPs in a short window. Tor exit / blocklisted IPs (optional lists). Impossible travel (speed > ~900 km/h).

### 4d. Scoring, alerts and incidents
- Combined risk score per window/event = weighted rules severity + anomaly score + IP signals. Severity levels: `LOW / MEDIUM / HIGH / CRITICAL`. All weights and thresholds live in config.
- **Alerts** are deduplicated, then **grouped into incidents**: same identity or same source IP within a time gap. Each incident gets a title, severity (the max), a MITRE tactic chain, first/last seen, entities involved and status (`Open / Investigating / Resolved / False Positive`).
- Triage feedback: marking an alert "False Positive" stores it. Show how it would change thresholds (suppression list) without auto-retraining.

## 5. Live pipeline

```
generator (batch or streaming, + live injection) ──► queue ──► detector worker
                                                                 │  rules (per event)
                                                                 │  windows → IsolationForest
                                                                 │  IP layer
                                                                 ▼
                                    DuckDB: events, labels, windows, alerts, incidents
                                                                 │
                                    Streamlit dashboard (auto-refresh) ◄─┘
                                    + optional Discord/Slack webhook for HIGH/CRITICAL
```
- The worker writes in micro-batches. The dashboard refreshes every few seconds (`st.fragment(run_every=…)` or `st_autorefresh`).
- Track **time-to-detect**: injection time → first alert.

## 6. Dashboard pages (Streamlit)

1. **Overview:** KPIs (events/min, open incidents by severity, identities monitored), alert stream, top risky identities, top source IPs/countries, events-over-time chart with alert markers.
2. **Alerts & Incidents:** sortable/filterable queue; status changes; bulk actions.
3. **Incident Investigation:** timeline (Plotly) of every event by the involved identities/IPs, colored by risk; MITRE chain; SHAP "why flagged"; raw CloudTrail JSON viewer; analyst notes; **Export report** (Markdown + JSON) with summary, timeline, affected resources and recommended response steps.
4. **Forensics Search:** query by identity, access key, IP, eventName, region and time range (DuckDB SQL behind a form, plus a raw SQL box); click-to-pivot on any IP/identity/key.
5. **Attack Simulator:** pick a scenario or kill chain, target identity and speed, then inject. Shows what was injected (ground truth) so you can compare it with what was detected.
6. **Detection Quality:** per-scenario precision/recall/F1, false positives per simulated day, time-to-detect distribution, and a comparison of rules-only vs IsolationForest-only vs combined. Values are read from `reports/metrics.json`.
7. **Real Data:** results of running the detector on the flaws.cloud dataset (see section 7).
8. **Settings:** thresholds, contamination, rule toggles, webhook URL.

## 7. Real-world validation (free data)

- **flaws.cloud public CloudTrail dataset** (Scott Piper / Summit Route): roughly 1.9M real events from people attacking the flaws.cloud training site, with IPs and account IDs anonymized. Write `scripts/load_flaws.py` to download it (confirm the current URL) and load it into DuckDB. Run the detector over it. Document notable findings in `docs/REAL_DATA_FINDINGS.md` (e.g. enumeration bursts, credential misuse). There are no ground-truth labels, so the evaluation is qualitative.
- **Stratus Red Team sample logs**: the public `Yamato-Security/suzaku-sample-data` repo contains CloudTrail logs generated by detonating Stratus Red Team techniques. Check that your rules fire on each relevant technique and record the result in a coverage table.
- **Optional, your own AWS account:** `scripts/pull_cloudtrail.py` uses read-only `lookup_events` to pull your account's recent management events into the same pipeline. Use a least-privilege IAM user with `cloudtrail:LookupEvents` only, keep credentials in env vars, and never commit them. This makes the "AWS" on the resume literally true at zero cost.

## 8. Evaluation (`scripts/evaluate.py` → `reports/metrics.json`)

- Generate a held-out week with a fixed seed and N injected instances of each scenario.
- **Event-level and incident-level** precision/recall/F1 per scenario. An incident counts as detected if any of its alerts overlaps the injected scenario's events.
- False-positive alerts per simulated day (benign-only week).
- Time-to-detect p50/p95.
- Ablation: rules only / IsolationForest only / IP layer only / combined.
- Robustness: vary the attacker's stealth (slower recon, using the victim's usual region/user agent) and show how recall drops. This makes an excellent interview talking point.
- Write `docs/RESULTS.md` from the generated metrics, not by hand.

## 9. Repo layout

```
cloud-threat-detection/
  config/{org.yaml,scenarios.yaml,detector.yaml}
  rules/*.yaml
  src/
    generator/{personas.py,benign.py,attacks.py,schema.py,stream.py}
    detection/{rules_engine.py,features.py,iforest.py,ip_analysis.py,scoring.py,incidents.py,explain.py}
    pipeline/{worker.py,storage.py}
    integrations/{webhook.py,aws_pull.py}
  app/streamlit_app.py  + app/pages/*.py
  scripts/{generate.py,train.py,evaluate.py,load_flaws.py,pull_cloudtrail.py}
  data/demo_snapshot.duckdb   (small committed dataset for instant offline demo)
  reports/  docs/{ARCHITECTURE.md,DETECTIONS.md,RESULTS.md,REAL_DATA_FINDINGS.md}
  tests/
  Dockerfile, docker-compose.yml
  .github/workflows/ci.yml
  README.md
```

## 10. Testing

- **Schema conformance:** every generated event validates against a pydantic model of the CloudTrail record. Spot-check against real sample records.
- **Determinism:** same seed → identical dataset.
- **Rules:** each rule has a positive and a negative test fixture (include real Stratus Red Team sample events where available).
- **Features:** hand-computed windows for small fixtures; new-IP/new-country logic; impossible-travel speed math.
- **End-to-end:** inject S1→S4 into a small benign stream; assert one incident with severity ≥ HIGH and the correct MITRE chain within X seconds.
- Labels never leak into detector inputs (assert that the detector never reads the label table).

## 11. Build phases (stop after each)

1. **Schema + benign generator** (personas, 1 simulated day) → JSON/Parquet → DuckDB. Show summary stats.
2. **Attack scenarios S1–S9** with sidecar labels; batch generation CLI.
3. **Rules engine + ~20 rules + tests.**
4. **Feature windows + IsolationForest + SHAP**; offline evaluation script and first metrics.
5. **IP/access-pattern layer + scoring + incident grouping.**
6. **Streaming pipeline + live injection + time-to-detect.**
7. **Streamlit dashboard** (Overview, Incidents, Investigation, Forensics, Simulator).
8. **Detection Quality page + ablations + robustness study.**
9. **Real-data validation** (flaws.cloud, Stratus samples); optional AWS pull script.
10. **Docker, demo snapshot, webhook alerts, free hosting, CI, README** with screenshots/GIF.

## 12. Acceptance criteria

- `docker compose up` runs the full live demo offline, with no AWS account.
- Injecting any scenario from the UI produces a correctly labeled incident with an explanation.
- `reports/metrics.json` and `docs/RESULTS.md` hold measured precision/recall, false positives per day and time-to-detect, plus the ablation table.
- Detector has been run on the flaws.cloud data, with findings documented.
- CI green.

## 13. Resume alignment & interview prep

- After building, consider adding a measured number to the bullets, e.g. "detected X/9 attack scenarios with Y% recall at Z false positives/day; median time-to-detect N s".
- Be ready to explain:
  - why IsolationForest suits unlabeled security data (anomalies are isolated in fewer random splits)
  - why per-identity baselines matter
  - why rules and ML complement each other
  - how you avoided label leakage
  - what makes synthetic data unrealistic, and how flaws.cloud partly addresses that
  - which CloudTrail events matter most for incident response (`StopLogging`, IAM writes, sharing changes)

## 14. Stretch goals

- Map detections to the MITRE ATT&CK Navigator layer JSON (free) and export a coverage heatmap.
- Add VPC Flow Logs or S3 server access logs (synthetic) and correlate them with CloudTrail.
- Swap IsolationForest for an autoencoder or LOF and compare.
- An LLM-written incident summary, as an optional local model via Ollama (free), clearly labeled as AI-generated.
