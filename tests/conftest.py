"""Shared fixtures: a tiny trained baseline+model (same world as the live engine) and a running dashboard engine."""
import os
import time
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import pandas as pd
import pytest

from src.detection.features import compute_windows, fit_baseline
from src.detection.iforest import AnomalyModel
from src.generator.dataset import generate_dataset
from src.pipeline import storage

WORLD = 9


@pytest.fixture(scope="session")
def trained():
    ds = generate_dataset(seed=5, world_seed=WORLD, days=3, scale=0.05)
    flat = pd.DataFrame([storage.flatten(r) for r, _ in ds.events]).drop(columns=["raw"])
    flat["event_time"] = pd.to_datetime(flat["event_time"])
    base = fit_baseline(flat)
    feats = compute_windows(flat, base)
    model = AnomalyModel(mode="global", n_estimators=40, max_samples=256, random_state=1).fit(feats)
    model.calibrate(feats, target_windows_per_day=4, days=3.0)
    return base, model


@pytest.fixture(scope="session")
def dash_engine(tmp_path_factory, trained):
    """A live engine started the way the dashboard starts it (env-configured), with a kill chain already injected and detected."""
    d = tmp_path_factory.mktemp("dash")
    base, model = trained
    (d / "models").mkdir()
    joblib.dump(base, d / "models" / "baseline.joblib")
    model.save(d / "models" / "anomaly_global.joblib")
    env = {"CTD_MODELS": str(d / "models"), "CTD_DB": str(d / "live.duckdb"), "CTD_SPEED": "300", "CTD_SCALE": "0.05", "CTD_WORLD_SEED": str(WORLD),
           "CTD_SIM_HOURS": "6", "CTD_DAYS": "1", "CTD_SUPPRESSIONS": str(d / "supp.json"), "CTD_NO_SNAPSHOT": "1"}
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    from app import common as C
    C.get_engine.clear()
    eng = C.get_engine(0)
    time.sleep(1.0)
    eng.inject("S1+S3+S4")
    eng.inject("S9")
    t0 = time.time()
    while time.time() - t0 < 90 and eng.stats()["detected_injections"] < 4:
        time.sleep(0.5)
    assert eng.stats()["detected_injections"] == 4, "setup: injections were not detected in time"
    time.sleep(1.5)       # let incidents settle
    yield eng
    eng.stop()
    C.get_engine.clear()
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
