"""Labeled attack scenarios S1-S9 and kill chains. Each event gets a sidecar label (never stored in the record)."""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from . import geo
from .catalog import API, RECON_APIS, flow_log_id_for, hexid
from .world import Principal, World, build_record, console_login, load_yaml

SCEN = load_yaml("scenarios.yaml")
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"
Event = tuple[dict, dict]


@dataclass
class Attacker:
    ip: str
    ua: str
    region: str
    country: str


@dataclass
class Run:
    """State shared across scenarios of one kill chain."""
    world: World
    rng: random.Random
    victim: Principal
    attacker: Attacker
    session: dict
    t: datetime
    pace: float
    injection_id: str = ""
    events: list[Event] = field(default_factory=list)
    spans: dict[str, list[datetime]] = field(default_factory=dict)
    scenario: str = ""

    def tick(self, lo: float, hi: Optional[float] = None) -> None:
        dt = self.rng.uniform(lo, hi if hi is not None else lo)
        self.t += timedelta(seconds=dt * self.pace)

    def ev(self, name: str, *, lo: float = 1.0, hi: Optional[float] = None, error: Optional[str] = None, ctx: Optional[dict] = None,
           region: Optional[str] = None, bytes_out: Optional[int] = None, malicious: bool = True, ip: Optional[str] = None,
           ua: Optional[str] = None, principal: Optional[Principal] = None, session: Optional[dict] = None) -> dict:
        self.tick(lo, hi)
        p = principal or self.victim
        rec = build_record(self.rng, self.t, p, session or self.session, ip or self.attacker.ip, ua or self.attacker.ua,
                           region or self.attacker.region, name, error=error, ctx=ctx)
        if bytes_out is not None:
            rec["additionalEventData"] = {"SignatureVersion": "SigV4", "bytesTransferredIn": 0, "bytesTransferredOut": bytes_out,
                                          "AuthenticationMethod": "AuthHeader"}
        self.add(rec, name, malicious)
        return rec

    def add(self, rec: dict, name: str, malicious: bool = True) -> None:
        sc = SCEN["scenarios"][self.scenario]
        tech, tactic = SCEN["event_overrides"].get(name, [sc["technique"], sc["tactic"]])
        if self.scenario in ("S3", "S6", "S4", "S7", "S5", "S2") and name not in SCEN["event_overrides"]:
            tech, tactic = sc["technique"], sc["tactic"]
        label = {"is_malicious": malicious, "scenario_id": self.scenario, "injection_id": self.injection_id,
                 "technique": tech if malicious else None, "mitre_tactic": tactic if malicious else None}
        self.events.append((rec, label))
        self.spans.setdefault(self.scenario, [self.t, self.t])[1] = self.t

    def other_user(self) -> str:
        humans = [p.name for p in self.world.humans if p.name != self.victim.name]
        return self.rng.choice(humans)


def make_attacker(world: World, rng: random.Random, victim: Principal, stealth: float) -> Attacker:
    """Graded stealth (each level adds to the previous):
       >= 0.25  uses the victim's own user agent (defeats user-agent rules / new-UA features)
       >= 0.50  uses the victim's usual region and a same-country residential IP (defeats new-country/region/ASN, travel and blocklist signals)
       >= 0.75  operates during the victim's working hours (see dataset scheduling) -> hour-of-day looks normal
       always   pace is slowed by 1 + 20*stealth (see AttackRunner.run), which defeats burst/threshold detections."""
    a = SCEN["attacker"]
    victim_ua = list(victim.uas.values())[0][0]
    if stealth >= 0.5:
        return Attacker(geo.random_ip(rng, "US", "residential"), victim_ua, victim.region, "US")
    cc = rng.choice(a["countries"])
    kind = rng.choice(["hosting", "vpn", "residential"])
    try:
        ip = geo.random_ip(rng, cc, kind)
    except ValueError:
        ip = geo.random_ip(rng, cc)
    ua = rng.choice(a["agents"])
    return Attacker(ip, victim_ua if stealth >= 0.25 else ua, rng.choice(["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]), cc)


# ----------------------------------------------------------------------------------------------- scenarios
def s1(r: Run) -> None:
    for name in ["GetCallerIdentity"] + r.rng.sample(["ListBuckets", "ListUsers", "DescribeRegions", "DescribeInstances", "ListRoles", "GetAccountSummary"], r.rng.randint(2, 4)):
        r.ev(name, lo=3, hi=40)


def s2(r: Run) -> None:
    sc = SCEN["scenarios"]["S2"]
    r.ev("GetCallerIdentity", lo=1, hi=5)
    n = r.rng.randint(*sc["events"])
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "eu-central-1"] if r.pace < 5 else [r.attacker.region]
    for _ in range(n):
        name = r.rng.choice(RECON_APIS)
        err = API[name].err_code if r.rng.random() < sc["deny_rate"] else None
        r.ev(name, lo=0.3, hi=2.0, error=err, region=r.rng.choice(regions))


def s3(r: Run) -> None:
    tgt = r.other_user()
    r.ev("ListUsers", lo=2, hi=10)
    r.ev("ListAttachedUserPolicies", lo=2, hi=10, ctx={"target_user": r.victim.name})
    if r.rng.random() < 0.3:
        r.ev("AttachUserPolicy", lo=3, hi=15, error="AccessDenied", ctx={"target_user": r.victim.name, "policy_arn": ADMIN_POLICY})
    r.ev("CreateAccessKey", lo=5, hi=30, ctx={"target_user": tgt})
    r.ev("AttachUserPolicy", lo=5, hi=30, ctx={"target_user": tgt, "policy_arn": ADMIN_POLICY})
    r.ev("PutUserPolicy", lo=5, hi=30, ctx={"target_user": tgt, "policy_name": "support-access", "policy_doc": json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})})
    r.ev("CreateLoginProfile", lo=5, hi=30, ctx={"target_user": tgt})
    ext = r.rng.choice(SCEN["attacker"]["external_accounts"])
    r.ev("UpdateAssumeRolePolicy", lo=5, hi=40, ctx={"role_name": "app-role", "trust_doc": json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ext}:root"}, "Action": "sts:AssumeRole"}]})})
    r.ev("CreateFunction20150331", lo=10, hi=60, ctx={"role_arn": f"arn:aws:iam::{r.world.account}:role/admin-role", "function_name": f"upd-{hexid(r.rng, 5)}"})


def s4(r: Run) -> None:
    must = r.rng.choice(["StopLogging", "DeleteTrail"])
    pool = [x for x in ["UpdateTrail", "PutEventSelectors", "DeleteDetector", "DeleteFlowLogs", "UpdateDetector"]]
    names = [must] + r.rng.sample(pool, r.rng.randint(2, 4))
    r.rng.shuffle(names)
    r.ev("DescribeTrails", lo=2, hi=10)
    for name in names:
        if name == "DeleteDetector":
            r.ev("ListDetectors", lo=2, hi=8)
        if name == "DeleteFlowLogs":       # the attacker removes the REAL flow log of the account's home region, so flow records can be seen to stop
            r.ev(name, lo=3, hi=25, region=r.victim.region, ctx={"flow_log_id": flow_log_id_for(r.world.account, r.victim.region)})
        else:
            r.ev(name, lo=3, hi=25)


def s5(r: Run) -> None:
    sc = SCEN["scenarios"]["S5"]
    r.ev("ListBuckets", lo=2, hi=10)
    bucket = r.rng.choice(["acme-customer-exports", "acme-prod-data", "acme-backups"])
    for _ in range(r.rng.randint(*sc["events"])):
        r.ev("GetObject", lo=0.3, hi=2.5, ctx={"bucket": bucket}, bytes_out=int(r.rng.lognormvariate(14, 1.2)))
    r.ev("PutBucketPolicy", lo=5, hi=30, ctx={"bucket": bucket, "policy": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]}})
    r.ev("PutBucketAcl", lo=5, hi=30, ctx={"bucket": bucket, "acl": ["public-read"]})
    r.ev("CreateSnapshot", lo=5, hi=30)
    r.ev("ModifySnapshotAttribute", lo=5, hi=30, ctx={"external_account": r.rng.choice(SCEN["attacker"]["external_accounts"])})


def s6(r: Run) -> None:
    new = f"svc-{hexid(r.rng, 5)}"
    r.ev("CreateUser", lo=3, hi=20, ctx={"target_user": new})
    r.ev("CreateAccessKey", lo=3, hi=20, ctx={"target_user": new})
    r.ev("AttachUserPolicy", lo=3, hi=20, ctx={"target_user": new, "policy_arn": ADMIN_POLICY})
    r.ev("CreateLoginProfile", lo=3, hi=20, ctx={"target_user": new})
    ext = r.rng.choice(SCEN["attacker"]["external_accounts"])
    r.ev("UpdateAssumeRolePolicy", lo=3, hi=30, ctx={"role_name": "deploy-role", "trust_doc": json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ext}:root"}, "Action": "sts:AssumeRole"}]})})
    r.ev("CreateFunction20150331", lo=10, hi=60, ctx={"function_name": f"cron-{hexid(r.rng, 5)}"})


def s7(r: Run) -> None:
    sc = SCEN["attacker"]
    r.ev("DescribeRegions", lo=2, hi=8)
    r.ev("DescribeImages", lo=2, hi=8)
    for region in r.rng.sample(sc["crypto_regions"], r.rng.randint(1, 3)):
        itype = r.rng.choice(sc["crypto_instances"])
        r.ev("AuthorizeSecurityGroupIngress", lo=3, hi=15, region=region, ctx={"cidr": "0.0.0.0/0"})
        for _ in range(r.rng.randint(1, 3)):
            err = "Client.VcpuLimitExceeded" if r.rng.random() < 0.15 else None
            r.ev("RunInstances", lo=3, hi=30, region=region, error=err, ctx={"instance_type": itype, "count": r.rng.randint(2, 10), "key_name": "miner"})
        r.ev("RequestSpotInstances", lo=3, hi=30, region=region, ctx={"instance_type": itype, "count": r.rng.randint(2, 8)})


def s8(r: Run) -> None:
    sc = SCEN["scenarios"]["S8"]
    root = r.rng.random() < 0.3
    p = r.world.by_persona("root")[0] if root else r.victim
    ua = r.rng.choice(r.world.cfg["user_agents"]["console"])
    failures = r.rng.randint(*sc["failures"])
    for _ in range(failures):
        r.tick(0.8, 6)
        rec = console_login(r.rng, r.t, p, r.attacker.ip, ua, r.world.cfg["org"]["signin_region"], success=False, mfa=False)
        r.add(rec, "ConsoleLogin")
    mfa = r.rng.random() < 0.3 and not root
    r.tick(1, 5)
    session = p.new_session(r.rng, console=True)
    r.add(console_login(r.rng, r.t, p, r.attacker.ip, ua, r.world.cfg["org"]["signin_region"], success=True, mfa=mfa, session=session), "ConsoleLogin")
    for name in r.rng.sample(["ListUsers", "ListAccessKeys", "GetAccountSummary", "ListBuckets"], 2):
        r.ev(name, lo=5, hi=40, ip=r.attacker.ip, ua=ua, principal=p, session=session)


def s9(r: Run) -> None:
    sc = SCEN["scenarios"]["S9"]
    home_ip = r.victim.home_ips[0]
    victim_ua = list(r.victim.uas.values())[0][0]
    anchor = r.ev("DescribeInstances", lo=0, ip=home_ip, ua=victim_ua, region=r.victim.region, malicious=False)  # noqa: F841  (kept: the call advances the RNG, removing it would change generated data)
    h = geo.lookup(home_ip)
    far = [c for c, (_, la, lo) in geo.COUNTRIES.items() if geo.haversine_km(h.lat, h.lon, la, lo) >= sc["min_km"]]
    ip = geo.random_ip(r.rng, r.rng.choice(far))
    r.attacker = Attacker(ip, victim_ua, r.victim.region, geo.lookup(ip).country)
    for name in ["GetCallerIdentity"] + r.rng.sample(["ListBuckets", "DescribeInstances", "ListUsers", "GetObject", "DescribeVolumes"], r.rng.randint(2, 5)):
        r.ev(name, lo=20, hi=150, ua=victim_ua, region=r.victim.region)


SCENARIOS = {"S1": s1, "S2": s2, "S3": s3, "S4": s4, "S5": s5, "S6": s6, "S7": s7, "S8": s8, "S9": s9}


class AttackRunner:
    def __init__(self, world: World, seed: int):
        self.world, self.seed, self.n = world, seed, 0

    def eligible_victims(self) -> list[Principal]:
        return [p for p in self.world.principals if p.persona in ("developers", "admins") and p.start_day == 0]

    def run(self, spec: str, t0: datetime, *, victim: Optional[str] = None, stealth: float = 0.0, speed: float = 1.0,
            rng: Optional[random.Random] = None) -> tuple[list[Event], list[dict]]:
        """spec = 'S3' or a chain like 'S1+S2+S3+S4'. Returns (labeled events, injection rows)."""
        self.n += 1
        rng = rng or random.Random(f"attack-{self.seed}-{self.n}")
        ids = spec.split("+")
        for s in ids:
            if s not in SCENARIOS:
                raise ValueError(f"unknown scenario {s}")
        v = self.world.find(victim) if victim else rng.choice(self.eligible_victims())
        att = make_attacker(self.world, rng, v, stealth)
        run = Run(world=self.world, rng=rng, victim=v, attacker=att, session=v.new_session(rng, console=False), t=t0,
                  pace=(1 + stealth * 20) / max(speed, 1e-6))
        chain_id = f"chain-{self.seed}-{self.n:04d}" if len(ids) > 1 else None
        rows = []
        for i, s in enumerate(ids):
            run.scenario = s
            run.injection_id = f"inj-{self.seed}-{self.n:04d}-{s}"
            before = len(run.events)
            if i:
                run.tick(20, 240)
            SCENARIOS[s](run)
            evs = run.events[before:]
            mal = [e for e in evs if e[1]["is_malicious"]]
            rows.append({"injection_id": run.injection_id, "scenario_id": s, "chain_id": chain_id,
                         "start_time": datetime.strptime(min(e[0]["eventTime"] for e in mal), "%Y-%m-%dT%H:%M:%SZ"),
                         "end_time": datetime.strptime(max(e[0]["eventTime"] for e in mal), "%Y-%m-%dT%H:%M:%SZ"),
                         "victim": v.name, "attacker_ip": run.attacker.ip, "n_events": len(mal), "stealth": stealth})
        return run.events, rows
