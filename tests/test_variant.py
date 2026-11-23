import json
import subprocess
import sys
from pathlib import Path

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
VARIANT = ROOT / "config" / "variants" / "held_out"


def generate(tmp_path, *extra):
    out = tmp_path / "v.duckdb"
    cmd = [sys.executable, "scripts/generate.py", "--days", "2", "--scale", "0.05", "--seed", "5", "--world-seed", "7", "--out", str(out), "--overwrite", *extra]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stderr[-800:]
    return duckdb.connect(str(out), read_only=True)


@pytest.fixture(scope="module")
def variant_db(tmp_path_factory):
    d = tmp_path_factory.mktemp("variant")
    con = generate(d, "--config-dir", str(VARIANT), "--attacks", "S1,S2,S5,S7,S8,S9", "--count", "2")
    yield con
    con.close()


@pytest.fixture(scope="module")
def default_db(tmp_path_factory):
    d = tmp_path_factory.mktemp("default")
    con = generate(d, "--attacks", "S7", "--count", "1")
    yield con
    con.close()


def test_variant_changes_the_organisation(variant_db, default_db):
    assert variant_db.execute("SELECT DISTINCT account_id FROM events WHERE identity_type <> 'Root'").fetchall() == [("210987654321",)]
    assert default_db.execute("SELECT DISTINCT account_id FROM events WHERE identity_type <> 'Root'").fetchall() == [("123456789012",)]
    humans = variant_db.execute("SELECT count(DISTINCT identity) FROM events WHERE identity_type = 'IAMUser'").fetchone()[0]
    assert humans <= 18 + 3 + 14 and humans > 15                        # 35 humans at most (default org has 40)
    regions = {r[0] for r in variant_db.execute("""SELECT DISTINCT aws_region FROM events e JOIN labels l USING (event_id)
                                                   WHERE NOT l.is_malicious AND event_source NOT IN ('iam.amazonaws.com','sts.amazonaws.com','signin.amazonaws.com')""").fetchall()}
    assert regions <= {"eu-west-1", "eu-central-1", "us-east-1"}, regions   # benign activity lives in the variant's home regions (CI/maintenance keep us-east-1)


def test_variant_attackers_use_ordinary_user_agents_and_different_instance_sizes(variant_db):
    uas = [r[0] for r in variant_db.execute("SELECT DISTINCT e.user_agent FROM events e JOIN labels l USING (event_id) WHERE l.is_malicious AND e.event_name <> 'ConsoleLogin'").fetchall()]
    assert uas and not any(("kali" in u.lower() or u.startswith(("python-requests", "curl"))) for u in uas), uas
    inst = {json.loads(r[0])["requestParameters"]["instanceType"] for r in variant_db.execute(
        "SELECT e.raw FROM events e JOIN labels l USING (event_id) WHERE l.is_malicious AND e.event_name = 'RunInstances'").fetchall()}
    assert inst and inst <= {"c5.9xlarge", "m5.8xlarge", "g4dn.xlarge", "c6i.16xlarge"}


def test_variant_scenario_sizes_follow_its_config(variant_db):
    n = dict(variant_db.execute("SELECT scenario_id, count(*) FROM labels WHERE is_malicious GROUP BY 1").fetchall())
    per_inj = {r[0]: r[1] for r in variant_db.execute("SELECT scenario_id, max(n_events) FROM injections GROUP BY 1").fetchall()}
    assert per_inj["S5"] <= 40 + 120 and per_inj["S2"] <= 91 + 2           # S5 <= 120 reads + a handful of follow-up events, S2 <= 90 recon calls + 1
    assert per_inj["S8"] <= 12 + 1 + 2                                     # <= 12 failures + the success + two follow-ups
    assert n.get("S7", 0) > 0


def test_default_config_is_untouched_by_the_override_mechanism(default_db):
    # S7 in the default org uses GPU families from config/scenarios.yaml
    insts = {json.loads(r[0])["requestParameters"]["instanceType"] for r in default_db.execute(
        "SELECT e.raw FROM events e JOIN labels l USING (event_id) WHERE l.is_malicious AND e.event_name = 'RunInstances'").fetchall()}
    assert insts <= {"p3.16xlarge", "g5.48xlarge", "p4d.24xlarge", "c5.18xlarge"}


def test_variant_files_have_every_key_the_generator_reads():
    import yaml
    base_org = yaml.safe_load((ROOT / "config" / "org.yaml").read_text())
    var_org = yaml.safe_load((VARIANT / "org.yaml").read_text())
    for k in base_org:
        assert k in var_org
    for p in base_org["personas"]:
        assert set(base_org["personas"][p]) == set(var_org["personas"][p]), p
    base_sc = yaml.safe_load((ROOT / "config" / "scenarios.yaml").read_text())
    var_sc = yaml.safe_load((VARIANT / "scenarios.yaml").read_text())
    assert set(base_sc) == set(var_sc) and set(base_sc["attacker"]) == set(var_sc["attacker"])
