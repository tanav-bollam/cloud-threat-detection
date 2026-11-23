"""Validate the detectors on REAL public CloudTrail data and write reports/real_data.json (docs/REAL_DATA_FINDINGS.md is generated from it).

Datasets (all public; see docs for sources):
  * Stratus Red Team technique samples (Yamato-Security/suzaku-sample-data, aws/stratus-red-team.cloud): rule coverage per technique.
  * flaws.cloud (Summit Route): ~1.2M unique real events from people attacking a training site. No labels; findings are qualitative, plus one
    event visible in the raw counts (a 20x volume surge in Aug 2019) used as an independent check.
  * Invictus-IR (32 Stratus attacks, one account) and the SANS-504 S3 ransomware lab: rule hits and gaps.

  python scripts/validate_real.py [--samples data/raw/suzaku-sample-data/aws] [--flaws data/flaws.duckdb]

Real IPs are anonymized, so the synthetic geo registry is switched off (geo-based signals are silent on real data by design).
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import numpy as np
import pandas as pd

from src.detection.explain import explain, format_reasons
from src.detection.features import HIGH_RISK, compute_windows, fit_baseline, load_events
from src.detection.iforest import AnomalyModel, windows_to_alerts
from src.detection.ip_analysis import IpAnalyzer
from src.detection.rules_engine import load_rules
from src.detection.scoring import load_config
from src.generator import geo
from src.pipeline import ingest, storage
from src.pipeline.batch import combine, rules_alerts
from src.stratus_coverage import stratus_coverage

PRIME_MARK = "post-hoc"


def log(msg: str) -> None:
    print(msg, flush=True)


def integrity(samples: Path) -> dict | None:
    """The original Summit Route tarball and the copy inside the samples repository must be byte-identical (SHA-256 per member)."""
    import hashlib
    import tarfile
    tar = Path("data/raw/flaws_cloudtrail_logs.tar")
    repo = samples / "flaws.cloud"
    if not tar.exists() or not repo.exists():
        return None
    same = total = 0
    with tarfile.open(tar) as t:
        for m in t:
            if not m.isfile():
                continue
            total += 1
            p = repo / Path(m.name).name
            if p.exists() and hashlib.sha256(t.extractfile(m).read()).hexdigest() == hashlib.sha256(p.read_bytes()).hexdigest():
                same += 1
    return {"tar_bytes": tar.stat().st_size, "members": total, "identical_to_repo_copy": same}


def overview(con) -> dict:
    q = lambda s: con.execute(s).fetchall()
    n, ids, ips, uas, lo, hi = q("SELECT count(*), count(DISTINCT identity), count(DISTINCT source_ip), count(DISTINCT user_agent), min(event_time), max(event_time) FROM events")[0]
    return {"events": n, "identities": ids, "source_ips": ips, "user_agents": uas, "first": str(lo), "last": str(hi),
            "identity_types": dict(q("SELECT identity_type, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC")),
            "top_events": q("SELECT event_name, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC LIMIT 10"),
            "top_identities": q("SELECT identity, count(*) FROM events GROUP BY 1 ORDER BY 2 DESC LIMIT 8"),
            "error_events": q("SELECT count(*) FROM events WHERE error_code IS NOT NULL")[0][0]}


def rule_table(alerts, rules_meta, con) -> list[dict]:
    by = collections.defaultdict(list)
    for a in alerts:
        by[a.rule_id].append(a)
    rows = []
    for rid, al in sorted(by.items(), key=lambda kv: -len(kv[1])):
        ids = collections.Counter(a.identity for a in al)
        times = sorted(a.event_time for a in al)
        rows.append({"rule_id": rid, "title": rules_meta[rid].title, "severity": rules_meta[rid].severity, "tactic": rules_meta[rid].mitre_tactic,
                     "alerts": len(al), "identities": len(ids), "top_identity": ids.most_common(1)[0][0], "first": times[0], "last": times[-1],
                     "sample_event": al[0].event_name or al[0].detail})
    return rows


def small_dataset(name: str, paths: list[Path]) -> dict:
    """Ingest into memory, run the rules with the dataset's own account/region as 'home', report hits and unalerted high-risk APIs."""
    con = storage.connect(":memory:")
    stats = ingest.ingest(con, paths)
    ov = overview(con)
    acct = con.execute("SELECT account_id FROM events GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
    region = con.execute("SELECT aws_region FROM events GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
    rules = load_rules()
    meta = {r.id: r for r in rules}
    alerts = rules_alerts(con, context={"account_id": acct, "home_regions": [region]})
    alerted = {e for a in alerts for e in set(a.matched_event_ids) | {a.event_id}}
    hr = con.execute("SELECT event_name, event_id FROM events WHERE event_name IN (" + ",".join(f"'{n}'" for n in HIGH_RISK) + ")").fetchall()
    cnt = collections.Counter(n for n, _ in hr)
    cov = collections.Counter(n for n, e in hr if e in alerted)
    gap = [{"event_name": n, "events": c, "alerted": cov[n]} for n, c in cnt.most_common() if cov[n] < c]
    con.close()
    return {"name": name, "ingest": stats, "overview": ov, "home_region_assumed": region, "rules": rule_table(alerts, meta, None), "alerts": len(alerts),
            "alerted_events": len(alerted), "high_risk_gap": gap[:12]}


def flaws(db: str, fp_per_day: float, ingest_stats: dict | None) -> dict:
    geo.set_enabled(False)
    con = duckdb.connect(db, read_only=True)
    cfg = load_config()
    ov = overview(con)
    out = {"overview": ov, "ingest": ingest_stats}
    acct = con.execute("SELECT account_id FROM events GROUP BY 1 ORDER BY count(*) DESC LIMIT 1").fetchone()[0]
    ctx = {"account_id": acct, "home_regions": ["us-west-2"]}        # flaws.cloud is hosted in us-west-2
    out["rule_context"] = {"home_regions": ctx["home_regions"], "note": "assumed: the training site lives in us-west-2"}
    # ---- the volume surge, found from raw monthly counts (no labels involved)
    mon = con.execute("SELECT date_trunc('month', event_time) m, count(*) n FROM events GROUP BY 1 ORDER BY 1").fetchdf()
    med = float(mon["n"].median())
    surge = mon[mon["n"] > 10 * med]
    s_start = pd.Timestamp(surge["m"].iloc[0]) if len(surge) else None
    s_end = (s_start + pd.offsets.MonthBegin(1)) if s_start is not None else None
    out["monthly_median_events"] = med
    out["surge"] = None
    t0 = time.time()
    log("flaws: rules over the full timeline ...")
    alerts_r = rules_alerts(con, context=ctx)
    meta = {r.id: r for r in load_rules()}
    out["rules"] = {"alerts": len(alerts_r), "by_rule": rule_table(alerts_r, meta, con), "seconds": round(time.time() - t0)}
    log("flaws: same rules with deduplication off (to measure the flood) ...")
    out["rules"]["alerts_without_dedupe"] = len(rules_alerts(con, context=ctx, dedupe_s=0))
    if s_start is None:
        return out
    ev = load_events(con)
    pre, post = ev[ev["event_time"] < s_start], ev[ev["event_time"] >= s_start]
    top_id, top_name = con.execute("SELECT identity, event_name FROM events WHERE event_time >= ? AND event_time < ? GROUP BY 1,2 ORDER BY count(*) DESC LIMIT 1", [s_start, s_end]).fetchone()
    surge_ids = {r[0] for r in con.execute("SELECT event_id FROM events WHERE event_time >= ? AND event_time < ? AND event_name = ?", [s_start, s_end, top_name]).fetchall()}
    onset = pd.Timestamp(con.execute("SELECT min(event_time) FROM events WHERE event_time >= ? AND event_time < ? AND identity = ? AND event_name = ?", [s_start, s_end, top_id, top_name]).fetchone()[0])
    n_surge_month = int(mon[mon["m"] == s_start]["n"].iloc[0])
    out["surge"] = {"month": str(s_start.date())[:7], "events_in_month": n_surge_month, "x_median": round(n_surge_month / med, 1), "dominant_identity": top_id,
                    "dominant_event": top_name, "dominant_events": len(surge_ids), "onset": str(onset),
                    "regions_touched": int(con.execute("SELECT count(DISTINCT aws_region) FROM events WHERE event_time >= ? AND event_time < ? AND event_name = ?", [s_start, s_end, top_name]).fetchone()[0]),
                    "errors_share": round(con.execute("SELECT avg((error_code IS NOT NULL)::INT) FROM events WHERE event_time >= ? AND event_time < ? AND event_name = ?", [s_start, s_end, top_name]).fetchone()[0], 3)}
    # ---- unsupervised model trained on the pre-surge history of the SAME data
    log("flaws: baseline + IsolationForest on pre-surge history ...")
    span = s_start - pre["event_time"].min()
    b_end, tr_end = pre["event_time"].min() + span * 0.6, pre["event_time"].min() + span * 0.85
    early = fit_baseline(pre[pre["event_time"] < b_end])
    train = compute_windows(pre[pre["event_time"] < tr_end], early, min_start=b_end)
    calib = compute_windows(pre, early, min_start=tr_end)
    model = AnomalyModel(mode="global", n_estimators=300, max_samples=512, random_state=7).fit(train)
    calib_days = (s_start - tr_end).total_seconds() / 86400
    model.calibrate(calib, fp_per_day, calib_days)
    base = fit_baseline(pre)
    log("flaws: scoring the surge period ...")
    feats = compute_windows(post, base)
    scores = model.score(feats)
    flagged = model.flag(feats, scores)
    reasons = {}
    if flagged.any():
        idx = np.where(flagged)[0]
        top = idx[np.argsort(-scores[idx])][:400]
        rs = explain(model, feats.iloc[top], 5)
        reasons = {(feats.at[i, "identity"], feats.at[i, "wstart"]): r for i, r in zip(top, rs)}
    ml_alerts = windows_to_alerts(feats, scores, flagged, post, reasons, model.threshold_for(feats))
    ip_alerts = IpAnalyzer(cfg["ip"], base).evaluate_frame(post)
    r_post = [a for a in alerts_r if a.event_time >= str(s_start)[:10]]
    layers = {"rules": r_post, "anomaly": ml_alerts, "ip": ip_alerts}
    post_days = (post["event_time"].max() - post["event_time"].min()).total_seconds() / 86400
    res = {"training_windows": len(train), "calibration_windows": len(calib), "calibration_fp_per_day_target": fp_per_day,
           "train_period": f"{pre['event_time'].min().date()} -> {tr_end.date()}", "scored_period": f"{post['event_time'].min().date()} -> {post['event_time'].max().date()}",
           "scored_days": round(post_days), "scored_windows": len(feats), "flagged_windows": int(flagged.sum())}
    combos = {"rules": ("rules",), "anomaly": ("anomaly",), "ip": ("ip",), "combined": ("rules", "anomaly", "ip")}
    cap = {}
    for name, combo in combos.items():
        al, inc = combine(layers, combo, base, cfg)
        pred = {e for a in al for e in set(a.matched_event_ids) | {a.event_id}}
        covered = len(pred & surge_ids)
        hit = [a for a in al if (set(a.matched_event_ids) | {a.event_id}) & surge_ids]
        first = min((pd.Timestamp(a.detected_at.rstrip("Z")) for a in hit), default=None)
        cap[name] = {"alerts": len(al), "incidents": len(inc), "incidents_per_day": round(len(inc) / post_days, 2),
                     "surge_events_covered": covered, "surge_events_covered_pct": round(100 * covered / max(len(surge_ids), 1), 1),
                     "surge_detected": bool(hit), "minutes_from_onset_to_first_alert": None if first is None else round((first - onset).total_seconds() / 60, 1)}
    res["by_layer"] = cap
    _, inc_all = combine(layers, combos["combined"], base, cfg)
    res["top_incidents"] = [{"severity": i.severity, "risk": i.risk_score, "title": i.title, "identities": i.identities[:3], "first_seen": i.first_seen, "tactics": i.tactics,
                             "sources": i.sources, "alerts": i.n_alerts} for i in sorted(inc_all, key=lambda i: -i.risk_score)[:10]]
    ctx_events = post.groupby("identity")["event_name"].agg(lambda s: s.value_counts().index[0]).to_dict()
    out_anoms = []
    for a in sorted([x for x in ml_alerts if not (s_start <= pd.Timestamp(x.event_time.rstrip("Z")) < s_end)], key=lambda x: -x.score)[:10]:
        out_anoms.append({"identity": a.identity, "when": a.event_time, "score": round(a.score, 3), "margin": round(a.margin, 3), "reasons": format_reasons(a.reasons),
                          "events_in_window": len(a.matched_event_ids), "identity_most_common_event": ctx_events.get(a.identity)})
    res["top_anomalies_outside_surge"] = out_anoms
    res["flagged_windows_in_surge_month"] = int(sum(1 for a in ml_alerts if s_start <= pd.Timestamp(a.event_time.rstrip("Z")) < s_end))
    out["ml"] = res
    return out


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", default="data/raw/suzaku-sample-data/aws")
    ap.add_argument("--flaws", default="data/flaws.duckdb")
    ap.add_argument("--fp-per-day", type=float, default=0.5)
    ap.add_argument("--out", default="reports/real_data.json")
    ap.add_argument("--skip-flaws", action="store_true")
    a = ap.parse_args()
    t0 = time.time()
    samples = Path(a.samples)
    res: dict = {"geo_synthetic_registry": "disabled for all real data (IPs are anonymized)"}
    res["sources"] = {"samples_repo": "https://github.com/Yamato-Security/suzaku-sample-data", "flaws_tar": "https://summitroute.com/downloads/flaws_cloudtrail_logs.tar",
                      "flaws_blog": "https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/"}
    res["flaws_integrity"] = integrity(samples)
    import subprocess
    try:
        res["samples_commit"] = subprocess.run(["git", "-C", str(samples.parent), "rev-parse", "--short", "HEAD"], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:       # noqa: BLE001
        res["samples_commit"] = None
    # ---- Stratus coverage
    log("stratus: coverage per technique ...")
    before = json.load(open("reports/stratus_coverage_before.json")) if Path("reports/stratus_coverage_before.json").exists() else None
    after = stratus_coverage(samples / "stratus-red-team.cloud")
    res["stratus"] = {"before": None if before is None else {k: before[k] for k in ("techniques", "covered_specific", "covered_any", "rules_evaluated", "measured_at_commit")},
                      "after": {k: after[k] for k in ("techniques", "covered_specific", "covered_any", "rules_evaluated")},
                      "rows": [{"tactic": r["tactic"], "technique": r["technique"], "events": r["events"], "event_names": r["event_names"][:4],
                                "before": None if before is None else next((b["fired"] for b in before["rows"] if b["technique"] == r["technique"]), None),
                                "after": r["fired"], "after_specific": r["specific"], "rule_titles": r["rule_titles"]} for r in after["rows"]]}
    # ---- small datasets
    for key, folder in (("invictus", "invictus-ir"), ("sans", "SANS-504-S3-ransomware-lab")):
        log(f"{key}: ingest + rules ...")
        res[key] = small_dataset(key, [samples / folder])
    # ---- flaws
    if not a.skip_flaws and Path(a.flaws).exists():
        st = json.load(open("reports/flaws_ingest.json")) if Path("reports/flaws_ingest.json").exists() else None
        res["flaws"] = flaws(a.flaws, a.fp_per_day, st)
    geo.set_enabled(True)
    Path(a.out).parent.mkdir(exist_ok=True)
    json.dump(res, open(a.out, "w"), indent=1, default=str)
    log(f"done in {time.time()-t0:.0f}s -> {a.out}")


if __name__ == "__main__":
    main()
