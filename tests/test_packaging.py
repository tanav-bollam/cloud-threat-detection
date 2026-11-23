import ast
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_readme_block_is_regenerated_between_markers_only_and_from_json(tmp_path, monkeypatch):
    import scripts.make_results as MR
    from tests.test_results import fake_metrics
    (tmp_path / "metrics.json").write_text(json.dumps(fake_metrics(recall=0.8123, fp=7.77)))
    monkeypatch.setattr(MR, "REPORTS", tmp_path)
    readme = tmp_path / "README.md"
    readme.write_text(f"# Title\nkeep me before\n{MR.README_START}\nOLD NUMBERS\n{MR.README_END}\nkeep me after\n", encoding="utf-8")
    assert MR.update_readme(readme)
    out = readme.read_text(encoding="utf-8")
    assert "OLD NUMBERS" not in out and "keep me before" in out and "keep me after" in out
    assert "81.2%" in out and "7.77" in out
    assert MR.update_readme(readme) and readme.read_text(encoding="utf-8") == out               # idempotent
    (tmp_path / "no_markers.md").write_text("# nothing here")
    assert not MR.update_readme(tmp_path / "no_markers.md")


def test_the_real_readme_has_markers_and_a_quickstart():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "<!-- RESULTS:START -->" in text and "<!-- RESULTS:END -->" in text
    assert "docker compose up" in text and "MIT License" in text and "No license file" not in text
    lic = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert lic.startswith("MIT License") and "Tanav Bollam" in lic and "WITHOUT WARRANTY OF ANY KIND" in lic
    for rel in re.findall(r"\]\((docs/[^)#]+)\)", text):
        assert (ROOT / rel).exists(), f"README links to missing {rel}"


def test_showcase_builds_from_reports_with_numbers_and_no_stray_external_assets(tmp_path, monkeypatch):
    import scripts.build_showcase as BS
    if not (ROOT / "reports" / "metrics.json").exists():
        pytest.skip("reports not generated")
    monkeypatch.setattr(BS, "SITE", tmp_path / "site")
    BS.main()
    index = (tmp_path / "site" / "index.html").read_text(encoding="utf-8")
    g = json.loads((ROOT / "reports" / "metrics.json").read_text(encoding="utf-8"))
    assert f"{g['layers']['combined']['benign_week']['fp_incidents_per_day']}" in index
    assert "Read the caveats" in index
    if (ROOT / "reports" / "real_data.json").exists():
        assert "REAL Stratus techniques covered" in index
    assert (tmp_path / "site" / "docs" / "RESULTS.html").exists() and (tmp_path / "site" / "docs" / "REAL_DATA_FINDINGS.html").exists()
    hosts = set(re.findall(r'(?:src|href)="(https?://[^/"]+)', index))
    assert hosts <= {"https://cdn.plot.ly"}, hosts                    # only Plotly's public CDN; nothing tracks the visitor


def test_docker_files_are_sane():
    d = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "EXPOSE 8501" in d and "COPY demo" in d and "streamlit" in d and "HEALTHCHECK" in d
    assert "AWS_ACCESS_KEY" not in d and "AWS_SECRET" not in d
    c = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "8501:8501" in c and "AWS_" not in c
    runtime = (ROOT / "requirements-runtime.txt").read_text(encoding="utf-8")
    assert "pytest" not in runtime and "streamlit" in runtime and "duckdb" in runtime
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert ".venv" in ignore and "data" in ignore


def test_gitignore_keeps_the_demo_and_drops_big_data():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert "/models/" in gi and "models/" not in gi                    # `models/` would also have swallowed demo/models
    assert "data/raw/" in gi and "data/*.duckdb" in gi


# Import name -> distribution name, for the packages whose names differ
DIST = {"sklearn": "scikit-learn", "yaml": "pyyaml"}


def test_every_third_party_import_is_in_requirements():
    """Catches 'works on my machine': a package imported by src/, app/ or scripts/ that a fresh pip install would not provide."""
    req = {re.split(r"[=<>]", l)[0].strip().lower() for l in (ROOT / "requirements.txt").read_text().splitlines() if l.strip() and not l.startswith("#")}
    stdlib = set(sys.stdlib_module_names)
    local = {"src", "app", "scripts", "tests"}
    found: dict[str, str] = {}
    for folder in ("src", "app", "scripts"):
        for f in (ROOT / folder).rglob("*.py"):
            for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
                mods = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module else []
                for m in mods:
                    top = m.split(".")[0]
                    if top not in stdlib and top not in local:
                        found.setdefault(top, str(f.relative_to(ROOT)))
    missing = {m: where for m, where in found.items() if DIST.get(m, m).lower() not in req}
    # playwright is used only by an optional local screenshot helper that is not part of the repo
    assert not missing, f"imported but not in requirements.txt: {missing}"
