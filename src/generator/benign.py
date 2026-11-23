"""Benign baseline generator: a normal week in a ~50-person startup, including benign-but-unusual noise."""
from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Optional

from . import geo
from .catalog import API, hexid
from .world import Principal, World, build_record, console_login

Event = tuple[dict, Optional[dict]]   # (cloudtrail record, label-or-None)


def _noise_label(kind: str) -> dict:
    return {"is_malicious": False, "scenario_id": f"N_{kind}", "injection_id": None, "technique": None, "mitre_tactic": None}


def _pick_name(rng: random.Random, names: list[str], weights: list[float]) -> str:
    return rng.choices(names, weights=weights)[0]


def _err(rng: random.Random, name: str) -> str:
    return "ThrottlingException" if rng.random() < 0.1 else API[name].err_code


class BenignGenerator:
    def __init__(self, world: World, seed: int, start: datetime, days: int, scale: float | None = None):
        self.w, self.cfg = world, world.cfg
        self.start, self.days = start, days
        self.scale = self.cfg["org"].get("volume_scale", 1.0) if scale is None else scale
        self.rng = random.Random(f"benign-{seed}")
        self.events: list[Event] = []
        self.signin_region = self.cfg["org"]["signin_region"]

    # ------------------------------------------------------------------ helpers
    def _emit(self, rec: dict, label: Optional[dict] = None) -> None:
        self.events.append((rec, label))

    def _ctx(self, p: Principal) -> dict:
        return {"bucket": self.rng.choice(p.fav_buckets) if self.rng.random() < 0.85 else None}

    def _region(self, p: Principal) -> str:
        return p.region if self.rng.random() < 0.95 else self.rng.choice(list(self.w.regions))

    def _api_run(self, p: Principal, session: dict, t: datetime, n: int, ip: str, ua: str, mix: dict, gap_s: float,
                 err_rate: float, label: Optional[dict] = None, region: Optional[str] = None) -> datetime:
        rng = self.rng
        names, weights = list(mix), list(mix.values())
        region = region or self._region(p)
        for _ in range(n):
            t += timedelta(seconds=rng.expovariate(1 / gap_s) + 0.2)
            if rng.random() < 0.03:
                t += timedelta(seconds=rng.uniform(300, 1200))
            name = _pick_name(rng, names, weights)
            error = _err(rng, name) if rng.random() < err_rate else None
            self._emit(build_record(rng, t, p, session, ip, ua, region, name, error=error, ctx=self._ctx(p)), label)
        return t

    def _human_ip(self, p: Principal, day: int, travel: Optional[dict]) -> str:
        pc = self.cfg["personas"][p.persona]
        if travel and p.name == travel["name"] and travel["days"][0] <= day <= travel["days"][1]:
            return travel["ip"]
        if p.office_ip and self.rng.random() < pc["office_prob"]:
            return p.office_ip
        return self.rng.choice(p.home_ips)

    def _human_session(self, p: Principal, t0: datetime, ip: str, console: bool, n: int, err_rate: float,
                       label: Optional[dict] = None, mix: Optional[dict] = None) -> None:
        pc = self.cfg["personas"][p.persona]
        rng = self.rng
        session = p.new_session(rng, console)
        if console:
            ua = p.uas["console"][0]
            self._emit(console_login(rng, t0, p, ip, ua, self.signin_region, success=True, mfa=True, session=session), label)
        else:
            ua = rng.choice([u for k, v in p.uas.items() if k != "console" for u in v])
        self._api_run(p, session, t0 + timedelta(seconds=rng.uniform(2, 15)), n, ip, ua, mix or pc["api_mix"], pc["mean_gap_s"], err_rate, label)

    # ------------------------------------------------------------------ personas
    def _humans(self, travel: Optional[dict], newhire_names: set[str]) -> None:
        rng = self.rng
        for p in self.w.humans:
            pc = self.cfg["personas"][p.persona]
            for day in range(self.days):
                if day < p.start_day:
                    continue
                date = self.start + timedelta(days=day)
                prob = pc["weekday_prob"] if date.weekday() < 5 else pc["weekend_prob"]
                if rng.random() > prob:
                    continue
                for _ in range(rng.randint(*pc["sessions_per_day"])):
                    h = pc["hours"]
                    local = min(h["max"], max(h["min"], rng.gauss(h["mean"], h["sd"])))
                    t0 = date + timedelta(hours=local - p.tz)
                    n = max(3, int(rng.lognormvariate(pc["events_per_session"]["mu"], pc["events_per_session"]["sigma"]) * self.scale))
                    err = 0.08 if p.name in newhire_names and day <= p.start_day + 4 else p.error_rate
                    ip = self._human_ip(p, day, travel)
                    label = _noise_label("travel") if travel and p.name == travel["name"] and travel["days"][0] <= day <= travel["days"][1] else \
                        _noise_label("newhire") if p.name in newhire_names and day <= p.start_day + 4 else None
                    self._human_session(p, t0, ip, rng.random() < pc["console_prob"], n, err, label)

    def _ci(self) -> None:
        rng, cfg = self.rng, self.cfg["personas"]["ci"]
        p = self.w.by_persona("ci")[0]
        ua = p.uas["terraform"][0]
        for day in range(self.days):
            date = self.start + timedelta(days=day)
            wd = date.weekday() < 5
            for _ in range(rng.randint(*(cfg["deploys_per_weekday"] if wd else cfg["deploys_per_weekend"]))):
                t0 = date + timedelta(hours=rng.uniform(13, 23))
                session = p.new_session(rng, session_name=f"ci-runner-{hexid(rng, 6)}")
                n = max(3, int(rng.lognormvariate(cfg["events_per_deploy"]["mu"], cfg["events_per_deploy"]["sigma"]) * self.scale))
                self._api_run(p, session, t0, n, rng.choice(p.service_ips), ua, cfg["api_mix"], 1.5, cfg["error_rate"], region="us-east-1")
            # poller: one DescribeStacks every ~5 minutes around the clock
            session = p.new_session(rng, session_name="ci-poller")
            t = date
            while t < date + timedelta(days=1):
                t += timedelta(seconds=cfg["poll_every_s"] * rng.uniform(0.9, 1.1))
                self._emit(build_record(rng, t, p, session, p.service_ips[0], ua, "us-east-1", "DescribeStacks"))

    def _lambdas(self) -> None:
        rng, cfg = self.rng, self.cfg["personas"]["lambdas"]
        for p in self.w.by_persona("lambdas"):
            rate = p.rate_per_hour * self.scale                              # events/hour at peak (fixed per world)
            gap = 3600.0 / max(rate, 1e-6)
            ua, ip = p.uas["lambda"][0], p.service_ips[0]
            names, weights = list(cfg["api_mix"]), list(cfg["api_mix"].values())
            end = self.start + timedelta(days=self.days)
            t = self.start
            session, sess_until = None, self.start
            while True:
                t += timedelta(seconds=rng.expovariate(1 / gap))
                if t >= end:
                    break
                if rng.random() > (1.0 if 12 <= t.hour < 24 else 0.5):   # diurnal thinning
                    continue
                if session is None or t >= sess_until:
                    session = p.new_session(rng, session_name=p.name.removeprefix("lambda-"))
                    sess_until = t + timedelta(hours=6)
                name = _pick_name(rng, names, weights)
                error = _err(rng, name) if rng.random() < cfg["error_rate"] else None
                self._emit(build_record(rng, t, p, session, ip, ua, p.region, name, error=error, ctx=self._ctx(p)))

    # ------------------------------------------------------------------ noise
    def _on_call(self) -> None:
        rng, nz = self.rng, self.cfg["noise"]
        devs = [p for p in self.w.by_persona("developers") if p.start_day == 0][:nz["on_call_engineers"]]
        mix = {"GetLogEvents": 10, "FilterLogEvents": 8, "DescribeLogStreams": 5, "DescribeInstances": 5, "StopInstances": 0.5,
               "StartInstances": 0.8, "DescribeAlarms": 4, "GetCallerIdentity": 1}
        for p in devs:
            for day in rng.sample(range(self.days), min(nz["on_call_nights"], self.days)):
                local = rng.uniform(1.0, 4.0)
                t0 = self.start + timedelta(days=day, hours=local - p.tz)
                self._human_session(p, t0, rng.choice(p.home_ips), False, max(5, int(rng.randint(20, 60) * self.scale)),
                                    0.02, _noise_label("oncall"), mix)

    def _traveler(self) -> Optional[dict]:
        if not self.cfg["noise"].get("traveling_devs"):
            return None
        p = [x for x in self.w.by_persona("developers") if x.start_day == 0][2]
        hotel = geo.random_ip(self.rng, "US", "residential")
        while hotel in p.home_ips:
            hotel = geo.random_ip(self.rng, "US", "residential")
        return {"name": p.name, "ip": hotel, "days": (min(2, self.days - 1), min(3, self.days - 1))}

    def _onboarding_and_maintenance(self, newhires: list[Principal]) -> None:
        rng, nz = self.rng, self.cfg["noise"]
        admins = self.w.by_persona("admins")
        for p in newhires:
            admin = admins[0]
            t = self.start + timedelta(days=p.start_day, hours=14.2)
            session = admin.new_session(rng, console=True)
            ua, ip = admin.uas["console"][0], admin.office_ip
            for name, ctx in (("CreateUser", {"target_user": p.name}), ("AttachUserPolicy", {"target_user": p.name, "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}),
                              ("CreateAccessKey", {"target_user": p.name}), ("CreateLoginProfile", {"target_user": p.name})):
                t += timedelta(seconds=rng.uniform(5, 40))
                self._emit(build_record(rng, t, admin, session, ip, ua, "us-east-1", name, ctx=ctx), _noise_label("onboarding"))
        if nz.get("admin_maintenance"):
            for day in range(self.days):
                date = self.start + timedelta(days=day)
                if date.weekday() == 5:
                    a = admins[-1]
                    t = date + timedelta(hours=3 - a.tz)
                    session = a.new_session(rng)
                    ua = a.uas.get("cli", a.uas.get("sdk"))[0]
                    for name, ctx in (("ListAccessKeys", {"target_user": "svc-backup"}), ("CreateAccessKey", {"target_user": "svc-backup"}),
                                      ("DeleteAccessKey", {"target_user": "svc-backup"}), ("ListAccessKeys", {"target_user": "svc-backup"})):
                        t += timedelta(seconds=rng.uniform(3, 30))
                        self._emit(build_record(rng, t, a, session, a.home_ips[0], ua, "us-east-1", name, ctx=ctx), _noise_label("maintenance"))

    def _root(self) -> None:
        n = self.cfg["personas"]["root"]["events_per_week"]
        p = self.w.by_persona("root")[0]
        for _ in range(int(n * self.days / 7)):
            t = self.start + timedelta(seconds=self.rng.uniform(0, self.days * 86400))
            self._emit(console_login(self.rng, t, p, p.home_ips[0], p.uas["console"][0], self.signin_region, mfa=True), _noise_label("breakglass"))

    # ------------------------------------------------------------------ main
    def generate(self) -> list[Event]:
        travel = self._traveler()
        newhires = [p for p in self.w.by_persona("developers") if p.start_day > 0]
        self._humans(travel, {p.name for p in newhires})
        self._ci()
        self._lambdas()
        if self.cfg["noise"].get("on_call_engineers"):
            self._on_call()
        self._onboarding_and_maintenance(newhires)
        self._root()
        self.events.sort(key=lambda e: e[0]["eventTime"])
        return self.events
