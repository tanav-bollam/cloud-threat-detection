import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_single_file_showcase_is_fully_self_contained(tmp_path, monkeypatch):
    import scripts.build_showcase as BS
    if not (ROOT / "reports" / "metrics.json").exists():
        pytest.skip("reports not generated")
    monkeypatch.setattr(BS, "SITE", tmp_path / "site")
    BS.main()
    out = BS.build_single_file(tmp_path / "dist" / "page.html")
    text = out.read_text(encoding="utf-8")
    # nothing the page LOADS may be remote (plain <a href> citations to source URLs are fine: they are links, not assets)
    assert not re.search(r'<(?:script|img|iframe|source)[^>]*src="https?://', text), "a remote asset is loaded"
    assert not re.search(r'<link[^>]*href="https?://', text), "a remote stylesheet is loaded"
    assert text.count('src="data:image/png;base64,') >= 1 and 'src="img/' not in text
    assert "Plotly.newPlot" in text and "<script>" in text
    for name in ("RESULTS", "REAL_DATA_FINDINGS", "DETECTIONS"):
        assert f'id="doc-{name}"' in text and f'href="#doc-{name}"' in text
    assert "docs/RESULTS.html" not in text and "../index.html" not in text
    assert "Single-file offline snapshot" in text
