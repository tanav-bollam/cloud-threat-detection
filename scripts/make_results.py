"""Generate docs/RESULTS.md and docs/DETECTIONS.md from reports/*.json and the rule/config files.

  python scripts/make_results.py

Every number in RESULTS.md is read from a metrics file produced by a script; none is typed here. The prose around the numbers is
qualitative (definitions, caveats). Re-run after scripts/evaluate.py / robustness.py / run_live.py.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import yaml

from src.detection.features import FEATURES, HIGH_RISK
from src.detection.ip_analysis import META as IP_META
from src.detection.rules_engine import load_rules

ROOT = Path(__file__).resolve().parents[1]
REPORTS, DOCS = ROOT / "reports", ROOT / "docs"
SCEN_NAMES = {k: v["name"] for k, v in yaml.safe_load((ROOT / "config" / "scenarios.yaml").read_text(encoding="utf-8"))["scenarios"].items()}
LAYER_LABEL = {"rules_only": "Rules only", "anomaly_only": "IsolationForest only", "ip_only": "IP layer only", "rules+ip": "Rules + IP",
               "rules+anomaly": "Rules + IsolationForest", "combined": "Combined (rules + IsolationForest + IP)"}


def load(name: str):
    p = REPORTS / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def table(headers: list[str], rows: list[list], align: list[str] | None = None) -> str:
    align = align or ["l"] + ["r"] * (len(headers) - 1)
    sep = ["---:" if a == "r" else ":---" for a in align]
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(sep) + " |"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def f(x, nd=2, pct=False):
    if x is None:
        return "n/a"
    return f"{x*100:.1f}%" if pct else (f"{x:.{nd}f}".rstrip("0").rstrip(".") if isinstance(x, float) else str(x))


def pctl(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    k = (len(s) - 1) * q
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def extra_sections() -> list[str]:
    """Sections 9-11 (VPC flow correlation, held-out generator variant, alternative models). Each appears only when its report exists."""
    md: list[str] = []
    fl = load("flow_correlation.json")
    if fl:
        rows = [[rid, d["alerts"], f(d["precision"], pct=True) if d["precision"] is not None else "n/a", f"{d['attack_events_detected']}/{d['relevant_attack_events']}",
                 f(d["recall"], pct=True) if d["recall"] is not None else "n/a"] for rid, d in fl["rules"].items()]
        v = fl["validation_week"]
        md += ["## 9. VPC Flow Log correlation (stretch)\n",
               "Synthetic flow logs are generated from the CloudTrail events and labels (`scripts/generate_flows.py`), then three correlation rules join them back to CloudTrail: "
               "FL001 mining-port traffic from an instance an identity launched, FL002 a deleted flow log that stops reporting, FL003 a world-open security group that the internet then reaches.\n",
               table(["Rule", "Alerts", "Precision", "Attack events caught", "Recall"], rows, ["l", "r", "r", "r", "r"]),
               f"\nBenign validation week: **{v['false_positive_alerts']}** flow alerts ({v['fp_per_day']}/day) over {v['flow_records']:,} flow records.\n",
               "**Read this carefully:** the flow logs and the attacks come from the same generator, so FL001 and FL003 are close to circular (the generator emits exactly the traffic the rule looks for). "
               "They show the correlation machinery works end to end; they are not evidence of real-world detection quality. FL002 recall is below 100% by construction: only the first "
               "DeleteFlowLogs of a log can produce silence, repeated deletes of an already-silent log cannot.\n"]
    var, main = load("metrics_variant.json"), load("metrics.json")
    if var and main:
        def row(name, d):
            c, r = d["layers"]["combined"], d["layers"]["rules_only"]
            return [name, f(r["test_week"]["injection_recall"], pct=True), f(c["test_week"]["injection_recall"], pct=True), f(c["test_week"]["incident_precision"], pct=True),
                    f(c["test_week"]["fp_incidents_per_day"]), f(c["benign_week"]["fp_incidents_per_day"]), f(c["event_level"]["precision"], pct=True),
                    f"{c['test_week']['chains_in_single_incident']}/{c['test_week']['chains']}"]
        md += ["## 10. Held-out generator variant (does the method transfer to a new organisation?)\n",
               "A second synthetic organisation (`config/variants/held_out/`: other regions, time zones, headcount, API mixes, heavy-S3 analysts, attackers with ordinary user agents and unlisted instance sizes). "
               "Detector code and config are unchanged; only the per-identity baselines, the IsolationForest and its threshold are re-learned from that organisation's own benign data (`scripts/run_variant.py`).\n",
               table(["Organisation", "Rules-only recall", "Combined recall", "Incident precision", "FP incidents/day (test week)", "FP incidents/day (benign week)", "Event precision", "Chains in one incident"],
                     [row("Tuned-on (main)", main), row("Held-out variant", var)], ["l", "r", "r", "r", "r", "r", "r", "r"]),
               "\nRules-only recall falls on the variant (the rules were written against the main organisation) and the learned layers recover it. Both organisations come from the same generator, so this tests "
               "robustness to configuration differences, not to real-world traffic. It is a fairer test than reusing the organisation the rules were written against, not a proof of generalisation.\n"]
    mc = load("model_comparison.json")
    if mc:
        rows = []
        for name, d in mc["models"].items():
            a, c = d["anomaly_only"], d["combined"]
            rows.append([name, f"{d['auroc']:.4f}", f"{d['average_precision']:.3f}", f(a["incident_recall"], pct=True), f(a["incident_precision"], pct=True), f(c["incident_recall"], pct=True),
                         f(c["fp_incidents_per_day"]), d["explanations"], d["train_seconds"] if d["train_seconds"] is not None else "(pre-trained)"])
        md += ["## 11. Anomaly model comparison: IsolationForest vs LOF vs autoencoder\n",
               f"Same {mc['training_windows']:,} benign training windows, same validation-week calibration to ~{mc['target_flagged_windows_per_day']} flagged windows/day, same {mc['test_windows']:,}-window test week "
               f"({mc['attack_windows']} overlap an injected attack). AUROC and average precision are threshold-free; the other columns use the calibrated threshold. "
               "LOF is fit on distinct windows (it is degenerate on exact duplicates). The autoencoder is a small scikit-learn MLP (no deep-learning dependency).\n",
               table(["Model", "AUROC", "Avg precision", "Anomaly-only recall", "Anomaly-only precision", "Combined recall", "Combined FP incidents/day", "Explanations", "Train s"], rows,
                     ["l", "r", "r", "r", "r", "r", "r", "l", "r"]),
               "\nIsolationForest ranks attacks best (AUROC/AP). The other two reach higher anomaly-only recall only because they flag more test windows at the same validation budget. IsolationForest is also the only one with SHAP explanations, which the dashboard and incident reports rely on, so it stays the default. "
               "The autoencoder is close but flags more windows (and raises HIGH/CRITICAL false positives when combined); LOF ranks worst. Synthetic attacks are an easy target for all three.\n"]
    return md


def results_md() -> str:
    g, pg, rob, live = load("metrics.json"), load("metrics_per_group.json"), load("robustness.json"), load("live_ttd.json")
    if not g:
        return "# Results\n\nNo metrics yet. Run `python scripts/train.py && python scripts/evaluate.py`.\n"
    L = g["layers"]
    C = L["combined"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = ["# Results\n", f"> Generated by `scripts/make_results.py` on {now} from `reports/*.json`. **Do not edit by hand**: every number below comes from a script run.\n"]
    md += ["## 1. Setup\n",
           f"- **Test week:** {g['test_days']} simulated days with **{g['injections']} injected attack stages** (labeled ground truth, hidden from the detectors): "
           f"the standalone scenarios S1-S9 plus the stages of {C['test_week']['chains']} chained kill chains (S1→S2→S3→S4→S5; each stage counts separately).",
           f"- **False-positive week:** a separate benign-only week ({g['val_days']} days, same identities, independent event stream). "
           "False positives per day are measured here, so they are not diluted by attacks.",
           "- **Training:** benign-only data from the same synthetic organisation (10 days: the first 5 build per-identity baselines, the last 5 give training windows). "
           f"The anomaly threshold is calibrated on the benign week to about {g['detector_config']['target_fp_windows_per_day']} flagged windows/day.",
           "- **Definitions.** *Incident recall* = share of injected attacks overlapped by at least one incident. *Event-level* precision/recall = over individual "
           "CloudTrail events placed in alerts. *Time to detect* = simulated seconds from the attack's first malicious event to the first alert that covers it "
           "(anomaly alerts are raised when their 15-minute window completes, so they lag rules).\n"]
    md += ["## 2. Headline (combined detector)\n",
           table(["Metric", "Value"], [
               ["Injected attacks detected (incident level)", f"{C['test_week']['injection_recall']*100:.1f}%  ({round(C['test_week']['injection_recall']*g['injections'])}/{g['injections']})"],
               ["Incident precision (test week)", f"{C['test_week']['incident_precision']*100:.1f}%"],
               ["False-positive incidents per day (benign week)", f(C['benign_week']['fp_incidents_per_day'])],
               ["False-positive HIGH/CRITICAL incidents per day", f(C['benign_week']['fp_high_or_critical_per_day'])],
               ["Kill chains consolidated into ONE incident", f"{C['test_week']['chains_in_single_incident']}/{C['test_week']['chains']}"],
               ["Event-level precision / recall", f"{C['event_level']['precision']*100:.1f}% / {C['event_level']['recall']*100:.1f}%"],
               ["Time to detect p50 / p95 (simulated s)", f"{f(C['ttd_p50_s'])} / {f(C['ttd_p95_s'])}"]], ["l", "r"]), ""]

    md += ["## 3. Ablation: which layer contributes what\n",
           table(["Layers", "Incident recall", "Incident precision", "FP incidents/day", "FP HIGH+CRIT/day", "Event P", "Event R", "TTD p50 (s)", "TTD p95 (s)"],
                 [[LAYER_LABEL[k], f(v["test_week"]["injection_recall"], pct=True), f(v["test_week"]["incident_precision"], pct=True), f(v["benign_week"]["fp_incidents_per_day"]),
                   f(v["benign_week"]["fp_high_or_critical_per_day"]), f(v["event_level"]["precision"], pct=True), f(v["event_level"]["recall"], pct=True),
                   f(v["ttd_p50_s"]), f(v["ttd_p95_s"])] for k, v in L.items()]), ""]
    sc = sorted(C["per_scenario"])
    md += ["Incident-level recall per scenario and layer:\n",
           table(["Layers"] + sc, [[LAYER_LABEL[k]] + [f(v["test_week"]["recall_by_scenario"].get(s), pct=True) for s in sc] for k, v in L.items()],
                 ["l"] + ["r"] * len(sc)), "",
           "Scenarios: " + "; ".join(f"**{s}** {SCEN_NAMES[s]}" for s in sc) + ".\n"]

    md += ["## 4. Per-scenario precision / recall / F1 (combined detector)\n",
           table(["Scenario", "Injections", "Incident P", "Incident R", "Incident F1", "Event P", "Event R", "Event F1"],
                 [[f"{s}: {SCEN_NAMES[s]}", v["injections"], f(v["incident"]["precision"], pct=True), f(v["incident"]["recall"], pct=True), f(v["incident"]["f1"], pct=True),
                   f(v["event"]["precision"], pct=True), f(v["event"]["recall"], pct=True), f(v["event"]["f1"], pct=True)] for s, v in C["per_scenario"].items()]),
           "\n*Precision is one-vs-rest against the benign background: every scenario is charged all of the test week's false-positive incidents/events. "
           "It therefore depends on how many attacks were injected relative to benign activity (synthetic prevalence) and should be read together with the "
           "prevalence-independent false-positives-per-day figure above.*\n"]

    if pg:
        P = pg["layers"]
        md += ["## 5. Global model vs per-group models\n",
               table(["Variant", "Anomaly-only incident recall", "Combined incident recall", "FP incidents/day (combined)", "Anomaly-only event precision"],
                     [["Global (identity type as features)", f(L["anomaly_only"]["test_week"]["injection_recall"], pct=True), f(C["test_week"]["injection_recall"], pct=True),
                       f(C["benign_week"]["fp_incidents_per_day"]), f(L["anomaly_only"]["event_level"]["precision"], pct=True)],
                      ["Per group (human vs service role)", f(P["anomaly_only"]["test_week"]["injection_recall"], pct=True), f(P["combined"]["test_week"]["injection_recall"], pct=True),
                       f(P["combined"]["benign_week"]["fp_incidents_per_day"]), f(P["anomaly_only"]["event_level"]["precision"], pct=True)]]),
               "\nThe global model is the default because it scored at least as well on anomaly-only recall (the layer the choice affects); per-group splits the "
               "small human population further.\n"]

    ttd = C["ttd_sim_s"]
    if ttd:
        md += ["## 6. Time-to-detect distribution (combined, simulated seconds)\n",
               table(["p10", "p50", "p75", "p90", "p95", "max", "n"], [[f(pctl(ttd, q), 0) for q in (0.1, 0.5, 0.75, 0.9, 0.95)] + [f(max(ttd), 0), len(ttd)]]),
               "\nRules and the IP layer alert on the triggering event (near-zero TTD); the long tail is attacks first caught by the anomaly layer, which alerts when its "
               "15-minute window completes.\n"]

    if rob:
        lv = rob["levels"]
        keys = ["rules_only", "anomaly_only", "ip_only", "combined"]
        md += ["## 7. Robustness to a stealthier attacker\n",
               "Same benign traffic at every level; only the attacks change. Each level adds to the previous one, and attacker pace is slowed by 1 + 20×stealth at every level.\n",
               table(["Stealth", "What the attacker does"] + [LAYER_LABEL[k] for k in keys],
                     [[str(x), rob["notes"].get(str(x), "")] + [f(rob["results"][str(x)][k]["incident_recall"], pct=True) for k in keys] for x in lv], ["l", "l"] + ["r"] * len(keys)), ""]
        last = str(lv[-1])
        md += ["Per-scenario incident recall of the **combined** detector as stealth rises:\n",
               table(["Stealth"] + sc, [[str(x)] + [f(rob["results"][str(x)]["combined"]["recall_by_scenario"].get(s), pct=True) for s in sc] for x in lv], ["l"] + ["r"] * len(sc)), "",
               f"At stealth {last} the combined detector detects {f(rob['results'][last]['combined']['incident_recall'], pct=True)} of attacks "
               f"(from {f(rob['results'][str(lv[0])]['combined']['incident_recall'], pct=True)} at stealth {lv[0]}); rules alone fall to "
               f"{f(rob['results'][last]['rules_only']['incident_recall'], pct=True)}. Median time-to-detect for the combined detector at that level is "
               f"{f(rob['results'][last]['combined']['ttd_p50_s'])} s.\n"]
        lastres = rob["results"][last]
        fell = [(s, lastres["combined"]["recall_by_scenario"].get(s)) for s in sc if (lastres["combined"]["recall_by_scenario"].get(s) or 0) < 0.999]
        md += [f"**Per layer at the highest stealth level ({last}):**\n",
               table(["Layers"] + sc, [[LAYER_LABEL[k]] + [f(lastres[k]["recall_by_scenario"].get(s), pct=True) for s in sc] for k in keys], ["l"] + ["r"] * len(sc)), ""]
        md += ["**Reading it.** " + (("Scenarios the combined detector no longer reliably catches at that level: "
               + ", ".join(f"{s} ({SCEN_NAMES[s]}, {f(v, pct=True)})" for s, v in fell) + ". ") if fell else "The combined detector still catches every scenario at that level. ")
               + "Detection that depends on *where/how* the attacker connects (user agent, country, region, network, hours) is what erodes; detection that depends on *what* "
               "the attacker does (e.g. stopping CloudTrail, attaching admin policies) is much more durable, because the attacker still has to perform those actions. "
               "S9 (impossible travel) is unaffected by the stealth setting because its geography is the attack itself, so its flat line is not evidence of robustness. "
               "An attacker who stays read-only and low-volume is not modeled here and would be harder still.\n"]

    if live:
        md += ["## 8. Live pipeline (real-time replay)\n",
               table(["Metric", "Value"], [["Injections detected", f"{live['detected']}/{live['injections']}"], ["Events processed", f"{live['events']:,}"],
                                           ["Wall time (s)", live["wall_s"]], ["Time to detect p50 / p95 (simulated s)", f"{f(live['ttd_sim_p50_s'])} / {f(live['ttd_sim_p95_s'])}"],
                                           ["Event-to-alert pipeline latency p50 / p95 (ms)", f"{f(live['pipeline_latency_p50_ms'], 0)} / {f(live['pipeline_latency_p95_ms'], 0)}"]], ["l", "r"]),
               "\nMeasured headless at real-time replay speed. Latency rises when the dashboard is rendering in the same process.\n"]

    md += extra_sections()
    md += ["## 12. Caveats: read before quoting any number\n",
           "- **Synthetic data.** Benign traffic and attacks come from the same generator family, so metrics are optimistic compared with a real account. "
           "Real-data checks (flaws.cloud, Stratus Red Team samples) are reported separately in `docs/REAL_DATA_FINDINGS.md`.",
           "- **Rules were written knowing the scenarios.** High rule recall on S1-S8 is expected; the robustness table above is the fairer view of what rules can do "
           "against a careful attacker.",
           "- **Stealth is a model, not reality.** The levels remove specific signals (user agent, region/country, hours, pace). Real adversaries vary in other ways.",
           "- **Small samples.** Each scenario has a handful of injections per week, so per-scenario recall moves in large steps (one missed attack is a double-digit percentage swing).",
           "- **FP rates depend on the calibrated threshold** (a target number of flagged benign windows per day) and on the synthetic noise models (on-call nights, a traveling developer, "
           "onboarding, maintenance). Real organisations are noisier.",
           "- **Labels never reach the detectors** (enforced by tests), but the thresholds were tuned while looking at these same attack types, so some optimism remains.\n"]
    return "\n".join(md)


FEATURE_DOC = {
    "log_n": "log(1 + events in the window)", "n_distinct_names": "distinct API names called", "n_services": "distinct AWS services touched",
    "read_ratio": "share of read-only calls", "err_ratio": "share of AccessDenied/Unauthorized errors", "high_risk_share": "share of high-risk APIs (IAM writes, logging/detection changes, sharing/permission changes, compute launch)",
    "recon_ratio": "share of List/Describe/Get management calls (enumeration signature)", "new_ip": "share of events from an IP never seen for this identity",
    "new_asn": "... from a network (ASN) never seen", "new_country": "... from a country never seen", "new_ua": "... with a user agent never seen", "new_region": "... in a region never used by the identity",
    "hour_rarity": "how unusual the hour of day is for this identity (1 = never active then)", "is_weekend": "window contains a weekend event",
    "log_max_dist": "log km between consecutive events' locations", "log_max_speed": "log implied travel speed (km/h) between consecutive events",
    "bytes_z": "S3 bytes read vs the identity's baseline (z-score)", "volume_z": "event count vs the identity's baseline (z-score)",
    "log_n_ips": "log distinct source IPs", "login_fail": "log failed console logins", "type_user": "identity is an IAM user", "type_role": "identity is an assumed role", "type_root": "identity is root"}


def detections_md() -> str:
    cfg = yaml.safe_load((ROOT / "config" / "detector.yaml").read_text(encoding="utf-8"))
    rules = load_rules()
    from src.navigator import snapshot
    md = ["# Detections\n", "> Generated by `scripts/make_results.py` from `rules/*.yaml`, `config/detector.yaml` and the feature definitions.\n",
          f"MITRE mappings follow ATT&CK enterprise v{snapshot()['attack_version']} (a test checks them against `config/attack_snapshot.json`). "
          "[`attack_coverage_layer.json`](attack_coverage_layer.json) is an ATT&CK Navigator layer of what the rules are written to detect: open it at "
          "<https://mitre-attack.github.io/attack-navigator/> via *Open Existing Layer, Upload from local*. It shows intended coverage, not measured quality.\n",
          "## Rules (Sigma-inspired YAML, evaluated per event; thresholds and sequences are windowed)\n",
          table(["ID", "Severity", "MITRE", "Title", "What it detects", "Known false positives"],
                [[r.id, r.severity, f"{r.mitre_tactic} / {r.mitre_technique}", r.title, r.description, r.false_positive_notes] for r in rules],
                ["l", "l", "l", "l", "l", "l"]), "",
          "## IP / access-pattern layer\n", table(["ID", "Severity", "MITRE", "Title", "What it detects"], [[k, v[1], f"{v[2]} / {v[3]}", v[0], v[4]] for k, v in IP_META.items()], ["l"] * 5),
          "\nThresholds (`config/detector.yaml`):\n", "```yaml\n" + yaml.safe_dump({"ip": cfg["ip"]}, sort_keys=False) + "```\n",
          "## Behavioural anomaly layer (IsolationForest)\n",
          f"Identity × {cfg['windows']['size_min']}-minute windows sliding every {cfg['windows']['step_min']} minutes. Features are computed against the identity's own baseline "
          "(known IPs, networks, countries, user agents, regions, active hours, typical volume). Trained on benign windows only; the alert threshold is calibrated on a benign "
          "validation week. Each flagged window carries SHAP reasons.\n",
          table(["Feature", "Meaning"], [[f"`{k}`", FEATURE_DOC.get(k, "")] for k in FEATURES], ["l", "l"]),
          f"\nHigh-risk API set used by `high_risk_share`: {', '.join(HIGH_RISK)}.\n",
          "## Scoring and incidents\n", "```yaml\n" + yaml.safe_dump({"scoring": cfg["scoring"], "incidents": cfg["incidents"]}, sort_keys=False) + "```\n",
          "Alerts get a 0-100 risk (rule severity points, anomaly margin over the threshold, or IP signal points). Alerts for the same identity or non-organisation IP within the gap join one "
          "incident; an identity tied to a HIGH+ alert stays linked for the longer gap. Incident severity is the max alert severity, escalated by tactic count and risk. "
          "The MITRE chain is ordered by *detection* time.\n"]
    return "\n".join(md)


README_START, README_END = "<!-- RESULTS:START -->", "<!-- RESULTS:END -->"


def readme_block() -> str:
    """The 'Results at a glance' table for README.md. Every number is read from reports/*.json."""
    g, rob, real, live = load("metrics.json"), load("robustness.json"), load("real_data.json"), load("live_ttd.json")
    if not g:
        return "## Results at a glance\n\nNo measurements yet: run `python scripts/train.py && python scripts/evaluate.py && python scripts/make_results.py`.\n"
    C = g["layers"]["combined"]
    rows = [["Attack stages detected (synthetic held-out week)", f"{C['test_week']['injection_recall']*100:.1f}% of {g['injections']}"],
            ["False-positive incidents per day (benign week)", f"{f(C['benign_week']['fp_incidents_per_day'])} ({f(C['benign_week']['fp_high_or_critical_per_day'])} HIGH or CRITICAL)"],
            ["Kill chains grouped into one incident", f"{C['test_week']['chains_in_single_incident']}/{C['test_week']['chains']}"],
            ["Time to detect, median / p95 (simulated s)", f"{f(C['ttd_p50_s'])} / {f(C['ttd_p95_s'])}"]]
    if rob:
        lv = rob["levels"]
        rows.append(["Recall against a stealthy attacker", f"{rob['results'][str(lv[-1])]['combined']['incident_recall']*100:.1f}% at stealth {lv[-1]} (from {rob['results'][str(lv[0])]['combined']['incident_recall']*100:.0f}% at {lv[0]})"])
    if live:
        rows.append(["Live pipeline: event to alert (median)", f"{f(live['pipeline_latency_p50_ms'], 0)} ms, {live['detected']}/{live['injections']} injections detected"])
    st = (real or {}).get("stratus")
    if st and st["before"]:
        rows.append(["**Real** Stratus techniques covered, original rules (held-out)", f"**{st['before']['covered_specific']}/{st['before']['techniques']}** ({st['before']['covered_specific']/st['before']['techniques']*100:.0f}%)"])
        rows.append(["...after adding rules for the gaps (post-hoc, not independent)", f"{st['after']['covered_specific']}/{st['after']['techniques']} ({st['after']['covered_specific']/st['after']['techniques']*100:.0f}%)"])
    fl = (real or {}).get("flaws")
    if fl and fl.get("surge") and fl.get("ml"):
        cb = fl["ml"]["by_layer"]["combined"]
        rows.append([f"flaws.cloud {fl['surge']['month']} surge ({fl['surge']['x_median']}× normal volume)", f"detected; {cb['surge_events_covered_pct']}% of its events covered"])
    return ("## Results at a glance\n\n" + table(["Measure", "Result"], rows, ["l", "l"]) +
            "\n\nGenerated from `reports/*.json`. Synthetic numbers are optimistic (the detectors and generator share an author); the real-data rows are the honest ones. "
            "See [`docs/RESULTS.md`](docs/RESULTS.md) and [`docs/REAL_DATA_FINDINGS.md`](docs/REAL_DATA_FINDINGS.md).\n")


def update_readme(path: Path | None = None) -> bool:
    p = path or ROOT / "README.md"
    if not p.exists():
        return False
    text = p.read_text(encoding="utf-8")
    if README_START not in text or README_END not in text:
        return False
    a, b = text.index(README_START) + len(README_START), text.index(README_END)
    p.write_text(text[:a] + "\n" + readme_block() + text[b:], encoding="utf-8")
    return True


def main() -> None:
    DOCS.mkdir(exist_ok=True)
    (DOCS / "RESULTS.md").write_text(results_md(), encoding="utf-8")
    (DOCS / "DETECTIONS.md").write_text(detections_md(), encoding="utf-8")
    from src import navigator
    (DOCS / "attack_coverage_layer.json").write_text(json.dumps(navigator.coverage_layer(), indent=1), encoding="utf-8")
    from scripts.real_findings import real_md          # imported lazily: real_findings imports helpers from this module
    (DOCS / "REAL_DATA_FINDINGS.md").write_text(real_md(), encoding="utf-8")
    print("wrote docs/RESULTS.md, docs/DETECTIONS.md and docs/REAL_DATA_FINDINGS.md" + (" and the README results block" if update_readme() else ""))


if __name__ == "__main__":
    main()
