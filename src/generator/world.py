"""World model (principals + their network/device habits) and the CloudTrail record builder."""
from __future__ import annotations

import os
import random
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

from . import geo
from .catalog import API, hexid, upper_id

ROOT = Path(__file__).resolve().parents[2]


def load_yaml(name: str) -> dict:
    """Read config/<name>, or <CTD_CONFIG_DIR>/<name> when that directory provides it (used for the held-out generator variant)."""
    override = os.environ.get("CTD_CONFIG_DIR")
    if override and (Path(override) / name).exists():
        return yaml.safe_load((Path(override) / name).read_text(encoding="utf-8"))
    return yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8"))


@dataclass
class Principal:
    name: str                       # IAM userName, or role name for service roles
    kind: str                       # IAMUser | AssumedRole | Root
    persona: str                    # developers | admins | analysts | ci | lambdas | root
    account: str
    tz: int = -5
    access_key: Optional[str] = None            # long-lived AKIA key (IAMUser)
    principal_id: str = ""
    home_ips: list[str] = field(default_factory=list)
    office_ip: Optional[str] = None
    uas: dict[str, list[str]] = field(default_factory=dict)   # kind -> agents
    region: str = "us-east-1"
    start_day: int = 0              # first active day (new hires)
    service_ips: list[str] = field(default_factory=list)
    fav_buckets: list[str] = field(default_factory=list)
    rate_per_hour: float = 0.0      # service roles: steady-state event rate (a property of the workload, fixed per world)
    error_rate: float = 0.02

    @property
    def arn(self) -> str:
        if self.kind == "IAMUser":
            return f"arn:aws:iam::{self.account}:user/{self.name}"
        if self.kind == "Root":
            return f"arn:aws:iam::{self.account}:root"
        return f"arn:aws:iam::{self.account}:role/{self.name}"

    def identity(self, rng: random.Random, session: dict, t: datetime) -> dict:
        """Build the CloudTrail userIdentity block for one session."""
        created = t.strftime("%Y-%m-%dT%H:%M:%SZ")
        if self.kind == "IAMUser":
            ident: dict[str, Any] = {"type": "IAMUser", "principalId": self.principal_id, "arn": self.arn,
                                     "accountId": self.account, "accessKeyId": session["access_key"], "userName": self.name}
            if session.get("console") or session["access_key"].startswith("ASIA"):
                ident["sessionContext"] = {"attributes": {"creationDate": created, "mfaAuthenticated": "true" if session.get("mfa", True) else "false"}}
            return ident
        if self.kind == "Root":
            return {"type": "Root", "principalId": self.account, "arn": self.arn, "accountId": self.account,
                    "accessKeyId": session["access_key"], "userName": "root",
                    "sessionContext": {"attributes": {"creationDate": created, "mfaAuthenticated": "true" if session.get("mfa") else "false"}}}
        sname = session["session_name"]
        return {"type": "AssumedRole", "principalId": f"{self.principal_id}:{sname}",
                "arn": f"arn:aws:sts::{self.account}:assumed-role/{self.name}/{sname}", "accountId": self.account,
                "accessKeyId": session["access_key"],
                "sessionContext": {"attributes": {"creationDate": created, "mfaAuthenticated": "false"},
                                   "sessionIssuer": {"type": "Role", "principalId": self.principal_id, "arn": self.arn,
                                                     "accountId": self.account, "userName": self.name}}}

    def new_session(self, rng: random.Random, console: bool = False, session_name: Optional[str] = None) -> dict:
        if self.kind == "IAMUser" and not console:
            return {"console": False, "access_key": self.access_key, "mfa": False}
        if self.kind == "IAMUser":
            return {"console": True, "access_key": "ASIA" + upper_id(rng, 16), "mfa": True}
        if self.kind == "Root":
            return {"console": True, "access_key": "", "mfa": False}
        return {"console": False, "access_key": "ASIA" + upper_id(rng, 16), "session_name": session_name or f"sess-{hexid(rng, 8)}"}


@dataclass
class World:
    cfg: dict
    account: str
    principals: list[Principal]
    regions: dict[str, float]

    def by_persona(self, persona: str) -> list[Principal]:
        return [p for p in self.principals if p.persona == persona]

    def find(self, name: str) -> Principal:
        for p in self.principals:
            if p.name == name:
                return p
        raise KeyError(name)

    @property
    def humans(self) -> list[Principal]:
        return [p for p in self.principals if p.persona in ("developers", "admins", "analysts")]


_FIRST = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy", "mallory", "niaj", "olivia", "peggy",
          "quinn", "rupert", "sybil", "trent", "uma", "victor", "wendy", "xavier", "yara", "zane", "arlo", "bella", "chen", "dara",
          "eli", "fatima", "gus", "hana", "ines", "jamal", "kira", "liam", "mona", "nico", "omar", "priya", "raj", "sana", "tomas",
          "ulla", "vik", "wen", "yusuf", "zoe"]


def build_world(cfg: dict, seed: int) -> World:
    rng = random.Random(f"world-{seed}")
    org = cfg["org"]
    acct = org["account_id"]
    ua = cfg["user_agents"]
    principals: list[Principal] = []
    names = _FIRST[:]
    rng.shuffle(names)
    used: set[str] = set()

    def uname() -> str:
        for n in names:
            if n not in used:
                used.add(n)
                return n
        n = f"user{len(used)}"
        used.add(n)
        return n

    office_ip = geo.random_ip(rng, "US", "office")
    for persona in ("developers", "admins", "analysts"):
        pc = cfg["personas"][persona]
        for _ in range(pc["count"]):
            p = Principal(name=uname(), kind="IAMUser", persona=persona, account=acct, tz=rng.choice(org["tz_offsets"]),
                          access_key="AKIA" + upper_id(rng, 16), principal_id="AIDA" + upper_id(rng, 17),
                          office_ip=office_ip)
            p.home_ips = [geo.random_ip(rng, "US", "residential") for _ in range(rng.randint(*pc["home_ips"]))]
            kinds = pc["ua_kinds"]
            p.uas = {k: [rng.choice(ua[k])] for k in kinds}
            p.uas["console"] = [rng.choice(ua["console"])]
            p.region = rng.choices(list(org["home_regions"]), weights=list(org["home_regions"].values()))[0]
            principals.append(p)
    ci = cfg["personas"]["ci"]
    nat_base = geo.random_ip(rng, "US", "aws", asn="AS64501").rsplit(".", 1)[0]
    principals.append(Principal(name=ci["role_name"], kind="AssumedRole", persona="ci", account=acct,
                                principal_id="AROA" + upper_id(rng, 17), uas={"terraform": ua["terraform"]},
                                service_ips=[f"{nat_base}.{10 + i}" for i in range(ci["egress_ips"])]))
    lam = cfg["personas"]["lambdas"]
    from .catalog import LAMBDAS
    for i in range(lam["count"]):
        principals.append(Principal(name=f"lambda-{LAMBDAS[i % len(LAMBDAS)]}", kind="AssumedRole", persona="lambdas", account=acct,
                                    principal_id="AROA" + upper_id(rng, 17), uas={"lambda": ua["lambda"]},
                                    service_ips=[geo.random_ip(rng, "US", "aws", asn="AS16509")]))
    principals.append(Principal(name="root", kind="Root", persona="root", account=acct, principal_id=acct,
                                home_ips=[office_ip], uas={"console": [ua["console"][0]]}))
    # noise roles: a new hire that appears on day 2
    nh = cfg["noise"].get("new_hires", 0)
    devs = [p for p in principals if p.persona == "developers"]
    for p in devs[len(devs) - nh:] if nh else []:
        p.start_day = 1
    from .catalog import BUCKETS
    for p in principals:
        p.fav_buckets = rng.sample(BUCKETS, 3)
        p.error_rate = cfg["personas"].get(p.persona, {}).get("error_rate", 0.02)
        if p.persona == "lambdas":
            p.rate_per_hour = rng.uniform(*cfg["personas"]["lambdas"]["rate_per_hour"])
    return World(cfg=cfg, account=acct, principals=principals, regions=org["home_regions"])


# --------------------------------------------------------------------------------------------- records
GLOBAL_SOURCES = {"iam.amazonaws.com", "route53.amazonaws.com", "cloudfront.amazonaws.com"}


def _fmt(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_record(rng: random.Random, t: datetime, p: Principal, session: dict, ip: str, ua: str, region: str,
                 name: str, *, error: Optional[str] = None, ctx: Optional[dict] = None,
                 extra_req: Optional[dict] = None, add_data: Optional[dict] = None) -> dict:
    api = API[name]
    if api.source in GLOBAL_SOURCES:      # global services always log us-east-1
        region = "us-east-1"
    c = {"account": p.account, "region": region}
    if ctx:
        c.update(ctx)
    req = api.req(rng, c) if api.req else None
    if extra_req and req is not None:
        req.update(extra_req)
    rec: dict[str, Any] = {
        "eventVersion": "1.09",
        "userIdentity": p.identity(rng, session, t),
        "eventTime": _fmt(t),
        "eventSource": api.source,
        "eventName": name,
        "awsRegion": region,
        "sourceIPAddress": ip,
        "userAgent": ua,
    }
    sess_issuer = ""  # noqa: F841
    if error:
        rec["errorCode"] = error
        arn = rec["userIdentity"]["arn"]
        svc = api.source.split(".")[0]
        rec["errorMessage"] = (f"User: {arn} is not authorized to perform: {svc}:{name} on resource: *"
                               if error in ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation")
                               else f"{error}: request failed")
    if req is not None:
        rec["requestParameters"] = req
    else:
        rec["requestParameters"] = None
    if not error and api.resp:
        rec["responseElements"] = api.resp(rng, c)
    else:
        rec["responseElements"] = None
    if add_data:
        rec["additionalEventData"] = add_data
    elif api.category == "Data" and name in ("GetObject", "PutObject"):
        sz = int(rng.lognormvariate(9, 1.6))
        rec["additionalEventData"] = {"SignatureVersion": "SigV4", "CipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
                                      "bytesTransferredIn": sz if name == "PutObject" else 0,
                                      "bytesTransferredOut": sz if name == "GetObject" else 0,
                                      "AuthenticationMethod": "AuthHeader", "x-amz-id-2": hexid(rng, 24)}
    rec["requestID"] = hexid(rng, 32).upper() if api.source.startswith("s3") else str(uuid.UUID(int=rng.getrandbits(128), version=4))
    rec["eventID"] = str(uuid.UUID(int=rng.getrandbits(128), version=4))
    rec["readOnly"] = api.read_only
    rec["eventType"] = "AwsApiCall"
    rec["managementEvent"] = api.category == "Management"
    rec["recipientAccountId"] = p.account
    rec["eventCategory"] = api.category
    return rec


def console_login(rng: random.Random, t: datetime, p: Principal, ip: str, ua: str, region: str, *,
                  success: bool = True, mfa: bool = True, session: Optional[dict] = None) -> dict:
    session = session or p.new_session(rng, console=True)
    if p.kind == "Root":
        ident = {"type": "Root", "principalId": p.account, "arn": p.arn, "accountId": p.account, "userName": "root"}
    else:
        ident = {"type": "IAMUser", "principalId": p.principal_id, "arn": p.arn, "accountId": p.account, "userName": p.name}
    rec: dict[str, Any] = {
        "eventVersion": "1.09", "userIdentity": ident, "eventTime": _fmt(t), "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin", "awsRegion": region, "sourceIPAddress": ip, "userAgent": ua,
        "requestParameters": None,
        "responseElements": {"ConsoleLogin": "Success" if success else "Failure"},
        "additionalEventData": {"LoginTo": f"https://console.aws.amazon.com/console/home?region={region}", "MobileVersion": "No",
                                "MFAUsed": "Yes" if mfa else "No"},
        "requestID": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "eventID": str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        "readOnly": False, "eventType": "AwsConsoleSignIn", "managementEvent": True, "recipientAccountId": p.account,
        "eventCategory": "Management",
    }
    if not success:
        rec["errorMessage"] = "Failed authentication"
    return rec
