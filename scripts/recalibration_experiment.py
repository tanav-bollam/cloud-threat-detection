"""Does recalibrating the anomaly threshold (or refreshing the baseline) help when the data drifts? Measured on flaws.cloud.

  python scripts/recalibration_experiment.py            # ~5 min -> reports/recalibration_experiment.json

The model is trained only on the history before the August 2019 surge (the same setup as scripts/validate_real.py), then scored over the rest.
Variants of the alert threshold: static (calibrated once), median + k*MAD, trailing quantile, trailing quantile with the storm guard
(src/detection/calibration.py). Variants of the baseline: frozen at the end of training, refreshed weekly from the trailing 30 days, and the same
with events from already-flagged windows kept OUT of the refresh (so an attacker cannot launder itself into 'normal').
Reported: flagged windows in the surge month, flagged windows per day outside it, and the median window score.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import duckdb
import numpy as np
import pandas as pd

from src.detection.calibration import AdaptiveThreshold
from src.detection.features import compute_windows, fit_baseline, load_events
from src.detection.iforest import AnomalyModel
from src.generator import geo

TARGET = 0.5
SURGE = (pd.Timestamp("2019-08-01"), pd.Timestamp("2019-09-01"))


def quarantine_mask(hist: pd.DataFrame, flagged: list) -> np.ndarray:
    """True for events that fall inside a previously flagged (identity, 15-minute window), via merged intervals per identity."""
    mask = np.zeros(len(hist), dtype=bool)
    if not flagged:
        return mask
    hid, ht = hist["identity"].to_numpy(), hist["event_time"].to_numpy()
    by_id: dict = {}
    for ident, w in flagged:
        by_id.setdefault(ident, []).append(w)
    for ident, ws in by_id.items():
        ws = np.sort(np.array(ws, dtype="datetime64[ns]"))
        starts, ends = [], []
        for w in ws:
            e = w + np.timedelta64(15, "m")
            if ends and w <= ends[-1]:
                ends[-1] = max(ends[-1], e)
            else:
                starts.append(w)
                ends.append(e)
        starts, ends = np.array(starts), np.array(ends)
        sel = np.where(hid == ident)[0]
        idx = np.searchsorted(starts, ht[sel], side="right") - 1
        ok = idx >= 0
        inside = np.zeros(len(sel), dtype=bool)
        inside[ok] = ht[sel][ok] < ends[idx[ok]]
        mask[sel[inside]] = True
    return mask


def mad_series(times, scores, seed_t, seed_s, base, k, lookback=30.0, update=7.0, min_windows=300, max_shift=0.15):
    """median + k*1.4826*MAD over the trailing lookback (the variant that made things worse)."""
    t = np.asarray(times, dtype="datetime64[s]").astype("int64") / 86400.0
    order = np.argsort(t, kind="stable")
    ts, ss = t[order], np.asarray(scores)[order]
    st = np.asarray(seed_t, dtype="datetime64[s]").astype("int64") / 86400.0
    allt, alls = np.concatenate([st, ts]), np.concatenate([seed_s, ss])
    o = np.argsort(allt, kind="stable")
    allt, alls = allt[o], alls[o]
    out = np.empty(len(ts))
    b = ts[0]
    while b <= ts[-1]:
        lo, hi = np.searchsorted(allt, b - lookback), np.searchsorted(allt, b)
        pool = alls[lo:hi]
        if len(pool) < min_windows:
            thr = base
        else:
            med = np.median(pool)
            scale = max(1.4826 * np.median(np.abs(pool - med)), 0.01)
            thr = float(np.clip(med + k * scale, base - max_shift, base + max_shift))
        out[np.searchsorted(ts, b):np.searchsorted(ts, b + update)] = thr
        b += update
    res = np.empty(len(ts))
    res[order] = out
    return res


def trailing_quantile_series(times, scores, seed_t, seed_s, base, lookback=30.0, update=7.0, min_windows=300, up=0.05, down=0.10):
    """The unguarded quantile tracker: the same as AdaptiveThreshold but with the storm guard disabled."""
    return AdaptiveThreshold(base=base, target_per_day=TARGET, lookback_days=lookback, update_days=update, max_up=up, max_down=down, min_windows=min_windows,
                             freeze_factor=1e12).series(times, scores, seed_times=seed_t, seed_scores=seed_s)[0]


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    t0 = time.time()
    geo.set_enabled(False)
    con = duckdb.connect("data/flaws.duckdb", read_only=True)
    ev = load_events(con)
    s_start, s_end = SURGE
    pre = ev[ev["event_time"] < s_start]
    span = s_start - pre["event_time"].min()
    b_end, tr_end = pre["event_time"].min() + span * 0.6, pre["event_time"].min() + span * 0.85
    early = fit_baseline(pre[pre["event_time"] < b_end])
    train = compute_windows(pre[pre["event_time"] < tr_end], early, min_start=b_end)
    calib = compute_windows(pre, early, min_start=tr_end)
    model = AnomalyModel(mode="global", n_estimators=300, max_samples=512, random_state=7).fit(train)
    model.calibrate(calib, TARGET, (s_start - tr_end).total_seconds() / 86400)
    base_thr = float(next(iter(model.units.values())).threshold)
    cal_scores = model.score(calib)
    med0 = float(np.median(cal_scores))
    scale0 = max(1.4826 * float(np.median(np.abs(cal_scores - med0))), 0.01)
    k = (base_thr - med0) / scale0
    static_base = fit_baseline(pre)
    post = ev[ev["event_time"] >= s_start]
    days_total = (post["event_time"].max() - s_start).days
    days_outside = days_total - (s_end - s_start).days
    print(f"model ready ({time.time()-t0:.0f}s): base threshold {base_thr:.3f}, k={k:.2f}; scoring {len(post):,} events over {days_total} days", flush=True)

    # ---- (A) threshold strategies on windows scored with the frozen baseline
    feats = compute_windows(post, static_base)
    scores = model.score(feats)
    in_surge = (feats["wstart"] >= s_start) & (feats["wstart"] < s_end)
    wt, st_ = feats["wstart"].to_numpy(), calib["wstart"].to_numpy()
    variants = {
        "static (calibrated once)": np.full(len(scores), base_thr),
        "median + k*MAD, trailing 30d": mad_series(wt, scores, st_, cal_scores, base_thr, k),
        "trailing quantile, no storm guard": trailing_quantile_series(wt, scores, st_, cal_scores, base_thr),
    }
    guarded, frozen = AdaptiveThreshold(base=base_thr, target_per_day=TARGET).series(wt, scores, seed_times=st_, seed_scores=cal_scores)
    variants["trailing quantile + storm guard"] = guarded
    results = {}
    for name, thr in variants.items():
        fl = scores >= thr
        results[name] = {"surge_month_flagged": int(fl[in_surge.to_numpy()].sum()), "outside_flagged": int(fl[~in_surge.to_numpy()].sum()),
                         "outside_per_day": round(float(fl[~in_surge.to_numpy()].sum()) / days_outside, 2), "median_threshold": round(float(np.median(thr)), 3)}
    results["trailing quantile + storm guard"]["frozen_periods"] = int(frozen)
    print("threshold strategies done", round(time.time() - t0), "s", flush=True)

    # ---- (B) rolling baseline refresh (weekly, trailing 30 days), with and without quarantining flagged windows
    LOOK, STEP = pd.Timedelta(days=30), pd.Timedelta(days=7)
    flagged: list = []
    acc = {k_: {"surge": 0, "outside": 0, "medians": []} for k_ in ("frozen baseline", "rolling baseline (quarantine flagged)", "rolling baseline (no quarantine)")}
    end, b = ev["event_time"].max(), s_start
    while b < end:
        nb = min(b + STEP, end + pd.Timedelta(seconds=1))
        chunk = ev[(ev["event_time"] >= b - pd.Timedelta(hours=2)) & (ev["event_time"] < nb)]
        hist = ev[(ev["event_time"] >= b - LOOK) & (ev["event_time"] < b)]
        hist_q = hist[~quarantine_mask(hist, flagged)]
        bases = {"frozen baseline": static_base,
                 "rolling baseline (quarantine flagged)": fit_baseline(hist_q) if len(hist_q) > 500 else static_base,
                 "rolling baseline (no quarantine)": fit_baseline(hist) if len(hist) > 500 else static_base}
        for name, bl in bases.items():
            f = compute_windows(chunk, bl, min_start=b)
            f = f[f["wstart"] < nb]
            sc = model.score(f)
            fl = sc >= base_thr
            ins = ((f["wstart"] >= s_start) & (f["wstart"] < s_end)).to_numpy()
            acc[name]["surge"] += int((fl & ins).sum())
            acc[name]["outside"] += int((fl & ~ins).sum())
            if len(sc):
                acc[name]["medians"].append(float(np.median(sc)))
            if name == "rolling baseline (quarantine flagged)":
                flagged += list(zip(f["identity"][fl], f["wstart"][fl]))
        b = nb
    baselines = {k_: {"surge_month_flagged": v["surge"], "outside_flagged": v["outside"], "outside_per_day": round(v["outside"] / days_outside, 2),
                      "median_window_score": round(float(np.median(v["medians"])), 3)} for k_, v in acc.items()}
    out = {"dataset": "flaws.cloud", "target_per_day": TARGET, "base_threshold": round(base_thr, 3), "calibration_median_score": round(med0, 3),
           "scored_days": int(days_total), "days_outside_surge": int(days_outside), "surge_month": str(s_start.date())[:7],
           "threshold_strategies": results, "baseline_strategies": baselines, "seconds": round(time.time() - t0)}
    Path("reports").mkdir(exist_ok=True)
    json.dump(out, open("reports/recalibration_experiment.json", "w"), indent=1)
    print(json.dumps({"threshold_strategies": results, "baseline_strategies": baselines}, indent=1))


if __name__ == "__main__":
    main()
