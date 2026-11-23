import numpy as np
import pandas as pd
import pytest

from src.detection.calibration import AdaptiveThreshold

PER_DAY = 400
TARGET = 0.5


def days_of_scores(n_days, loc=0.40, scale=0.05, start="2025-01-01", seed=0):
    r = np.random.default_rng(seed)
    n = n_days * PER_DAY
    times = pd.Timestamp(start) + pd.to_timedelta(np.sort(r.uniform(0, n_days * 86400, n)), unit="s")
    return times.to_numpy(), r.normal(loc, scale, n)


def calibrated(days=14, **kw):
    t, s = days_of_scores(days)
    thr = float(np.quantile(s, 1 - TARGET * days / len(s)))
    return AdaptiveThreshold(base=thr, target_per_day=TARGET, **kw), (t, s), thr


def test_candidate_reproduces_the_calibrated_threshold_on_its_own_distribution():
    at, (t, s), thr = calibrated(days=30, lookback_days=30)
    assert at.candidate(s) == pytest.approx(thr, abs=0.01)


def test_adaptive_threshold_tracks_a_moderate_drift_that_breaks_the_static_one():
    at, (ct, cs), thr = calibrated()
    t, s = days_of_scores(60, loc=0.44, start="2025-02-01", seed=5)           # benign distribution shifts up a little
    static_rate = float(np.mean(s >= thr)) * PER_DAY
    thresholds, _ = at.series(t, s, seed_times=ct, seed_scores=cs)
    late = t >= np.datetime64("2025-03-10")
    adaptive_rate = float(np.mean((s >= thresholds)[late])) * PER_DAY
    assert static_rate > 3 * TARGET and adaptive_rate < static_rate / 2, (static_rate, adaptive_rate)
    assert thresholds[late].mean() > thr + 0.02


def test_an_attack_burst_does_not_raise_the_bar_it_must_clear():
    at, (ct, cs), thr = calibrated()
    t, s = days_of_scores(40, start="2025-02-01", seed=8)
    burst = (t >= np.datetime64("2025-02-14")) & (t < np.datetime64("2025-02-24")) & (np.random.default_rng(9).random(len(t)) < 0.5)
    s = s.copy()
    s[burst] += 0.4                                                           # half of ten days' windows are extreme
    thresholds, frozen = at.series(t, s, seed_times=ct, seed_scores=cs)
    assert frozen >= 1                                                        # the storm guard engaged
    during = (t >= np.datetime64("2025-02-18")) & (t < np.datetime64("2025-02-24"))
    assert thresholds[during].max() <= thr + 1e-9                             # the bar did not rise during the storm
    assert (s >= thresholds)[burst & during].mean() > 0.95                    # and the attack windows stay detected


def test_without_the_guard_the_same_burst_would_be_partly_hidden():
    """Documents why the guard exists: this is the failure seen on real data."""
    at, (ct, cs), thr = calibrated(freeze_factor=1e9)
    t, s = days_of_scores(40, start="2025-02-01", seed=8)
    burst = (t >= np.datetime64("2025-02-14")) & (t < np.datetime64("2025-02-24")) & (np.random.default_rng(9).random(len(t)) < 0.5)
    s = s.copy()
    s[burst] += 0.4
    thresholds, frozen = at.series(t, s, seed_times=ct, seed_scores=cs)
    assert frozen == 0 and thresholds[t >= np.datetime64("2025-02-20")].max() > thr + 0.02


def test_shift_is_clipped_asymmetrically_and_little_history_falls_back():
    at, (ct, cs), thr = calibrated()
    assert at.candidate(cs[:50]) == at.base                                   # fewer than min_windows
    assert at.candidate(np.random.default_rng(2).normal(2.0, 0.05, 5000)) == pytest.approx(at.base + at.max_up)
    assert at.candidate(np.random.default_rng(2).normal(-2.0, 0.05, 5000)) == pytest.approx(at.base - at.max_down)
    assert at.max_down > at.max_up                                            # it may fall further than it may rise


def test_series_is_independent_of_input_order_and_without_history_starts_at_the_base():
    at, (ct, cs), thr = calibrated()
    t, s = days_of_scores(20, start="2025-02-01", seed=11)
    a, _ = at.series(t, s, seed_times=ct, seed_scores=cs)
    perm = np.random.default_rng(3).permutation(len(t))
    b, _ = at.series(t[perm], s[perm], seed_times=ct, seed_scores=cs)
    assert np.allclose(a[perm], b)
    first, _ = at.series(t, s)
    assert first[0] == at.base                                                # no seed, no history yet
