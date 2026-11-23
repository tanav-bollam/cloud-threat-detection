import numpy as np
import pytest

from src.detection.alt_models import AltAnomalyModel
from src.detection.features import FEATURES
from tests.test_features_model import synthetic_feats


@pytest.mark.parametrize("kind", ["lof", "autoencoder"])
def test_alt_model_ranks_outliers_calibrates_flags_and_pickles(kind, tmp_path):
    train = synthetic_feats(3000)
    m = AltAnomalyModel(kind=kind, random_state=1, max_iter=80).fit(train)
    val = synthetic_feats(2000, seed=1)
    info = m.calibrate(val, target_windows_per_day=5, days=2.0)
    assert info["all"]["budget"] == 10 and abs(int(m.flag(val).sum()) - 10) <= 3
    out = synthetic_feats(1, seed=2)
    out.loc[0, FEATURES] = 10.0
    inlier = synthetic_feats(200, seed=3)
    assert m.score(out)[0] > np.quantile(m.score(inlier), 0.99) and m.flag(out)[0]
    p = tmp_path / "m.joblib"
    m.save(p)
    again = AltAnomalyModel.load(p)
    assert np.allclose(again.score(val), m.score(val)) and again.kind == kind


def test_unknown_kind_and_per_group_are_rejected():
    with pytest.raises(ValueError):
        AltAnomalyModel(kind="nope").fit(synthetic_feats(300))
    with pytest.raises(ValueError):
        AltAnomalyModel(kind="lof", mode="per_group").fit(synthetic_feats(300))


def test_alt_model_plugs_into_the_alert_conversion():
    """The evaluation pipeline only needs score/flag/threshold_for, so these models must work with windows_to_alerts unchanged."""
    import pandas as pd
    from src.detection.iforest import windows_to_alerts
    from tests.test_features_model import ev
    train = synthetic_feats(2000)
    m = AltAnomalyModel(kind="lof").fit(train)
    feats = synthetic_feats(6, seed=4)
    feats["wstart"] = pd.to_datetime(["2025-01-01 10:00", "2025-01-01 10:05", "2025-01-01 12:00", "2025-01-01 13:00", "2025-01-01 14:00", "2025-01-01 15:00"])
    feats["identity"] = "alice"
    events = pd.DataFrame([ev(i, t) for i, t in enumerate(["2025-01-01 10:01", "2025-01-01 12:03", "2025-01-01 13:02"])])
    scores = m.score(feats)
    flagged = np.array([True, True, True, False, False, False])
    alerts = windows_to_alerts(feats, scores, flagged, events, None, m.threshold_for(feats))
    assert len(alerts) == 2 and all(a.source == "anomaly" for a in alerts)
