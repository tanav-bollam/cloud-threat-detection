"""Adaptive anomaly thresholds: an OPTIONAL library, OFF by default, kept because the experiment behind it is informative.

Why it is off: on the flaws.cloud data none of the recalibration strategies tried (see scripts/recalibration_experiment.py and
docs/REAL_DATA_FINDINGS.md) reduced alerts outside the known attack month without risking the attack itself:
  * median + k*MAD relative to recent scores made things worse (the score distribution became tight, so the threshold fell);
  * a trailing quantile followed the attack upward and masked most of it (the first week of an attack raised the bar for the rest);
  * a trailing quantile WITH the storm guard below kept the attack but also gained nothing, because the alerts outside the attack month
    were genuinely unusual windows (inventory-style sweeps), not drift.
So a once-calibrated threshold is kept by default. This class is the safest of the variants for anyone who wants to try it on their own data.

Design (AdaptiveThreshold):
  - every `update_days`, set the threshold to the quantile of the trailing `lookback_days` of window scores that yields `target_per_day` alerts;
  - clip to [base - max_down, base + max_up] so a slow drift cannot walk the bar arbitrarily far, and the bar may fall further than it may rise;
  - STORM GUARD: if the previous period flagged more than `freeze_factor` times the target rate, an attack may be in progress, so the
    threshold is frozen instead of adapting (otherwise the attack's own scores raise the bar it must clear). It cannot tell an attack from a
    lasting genuine shift, so it freezes for at most `max_freeze_periods` update periods in a row.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass
class AdaptiveThreshold:
    base: float                       # the originally calibrated threshold
    target_per_day: float             # intended flagged windows per day
    lookback_days: float = 30.0
    update_days: float = 7.0
    max_up: float = 0.05
    max_down: float = 0.10
    min_windows: int = 300
    freeze_factor: float = 5.0
    max_freeze_periods: int = 4       # a storm that lasts longer than this many update periods is treated as the new normal (the guard cannot tell the two apart)

    def candidate(self, pool: np.ndarray, span_days: float | None = None) -> float:
        """Threshold that would have flagged `target_per_day` windows a day over `pool` (which spans `span_days`; default: the full lookback)."""
        if len(pool) < self.min_windows:
            return self.base
        budget = max(1, int(round(self.target_per_day * (span_days if span_days is not None else self.lookback_days))))
        q = float(np.quantile(pool, max(0.0, 1.0 - budget / len(pool))))
        return float(np.clip(q, self.base - self.max_down, self.base + self.max_up))

    def series(self, times, scores, seed_times=None, seed_scores=None) -> tuple[np.ndarray, int]:
        """Per-window thresholds for a stretch of scored windows (batch evaluation) and the number of update periods that were frozen.
        History for each update period is the trailing lookback of windows strictly before it (seed windows, e.g. the calibration data, count)."""
        t = np.asarray(times, dtype="datetime64[s]").astype("int64") / 86400.0
        s = np.asarray(scores, float)
        order = np.argsort(t, kind="stable")
        ts, ss = t[order], s[order]
        if seed_times is not None and len(seed_times):
            allt = np.concatenate([np.asarray(seed_times, dtype="datetime64[s]").astype("int64") / 86400.0, ts])
            alls = np.concatenate([np.asarray(seed_scores, float), ss])
            o2 = np.argsort(allt, kind="stable")
            allt, alls = allt[o2], alls[o2]
        else:
            allt, alls = ts, ss
        out_sorted = np.empty(len(ts))
        prev, frozen, streak = self.base, 0, 0
        b = ts[0] if len(ts) else 0.0
        end = ts[-1] if len(ts) else 0.0
        while b <= end:
            pl, ph = np.searchsorted(ts, b - self.update_days), np.searchsorted(ts, b)
            rate_prev = float(np.sum(ss[pl:ph] >= prev)) / self.update_days if ph > pl else 0.0
            if rate_prev > self.freeze_factor * self.target_per_day and streak < self.max_freeze_periods:
                thr, frozen, streak = prev, frozen + 1, streak + 1   # alert storm: do not adapt while it is happening (but not forever)
            else:
                streak = 0
                lo, hi = np.searchsorted(allt, b - self.lookback_days), np.searchsorted(allt, b)
                span = min(self.lookback_days, allt[hi - 1] - allt[lo]) if hi - lo > 1 else None
                thr = self.candidate(alls[lo:hi], span)
            i0, i1 = np.searchsorted(ts, b), np.searchsorted(ts, b + self.update_days)
            out_sorted[i0:i1] = thr
            prev = thr
            b += self.update_days
        out = np.empty(len(ts))
        out[order] = out_sorted
        return out, frozen
