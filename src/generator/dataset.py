"""Compose benign baseline + scheduled attack injections into one dataset."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .attacks import SCEN, AttackRunner
from .benign import BenignGenerator
from .world import World, build_world, load_yaml


@dataclass
class Dataset:
    world: World
    events: list = field(default_factory=list)       # (record, label|None), sorted by eventTime
    injections: list = field(default_factory=list)


def generate_dataset(seed: int = 42, days: int | None = None, start: str | None = None, scale: float | None = None,
                     attacks: list[str] | None = None, count: int = 1, stealth: float = 0.0) -> Dataset:
    cfg = load_yaml("org.yaml")
    days = days or cfg["org"]["default_days"]
    start_dt = datetime.strptime(start or cfg["org"]["default_start"], "%Y-%m-%d")
    world = build_world(cfg, seed)
    events = BenignGenerator(world, seed, start_dt, days, scale).generate()
    injections: list[dict] = []
    if attacks:
        runner = AttackRunner(world, seed)
        rng = random.Random(f"schedule-{seed}")
        for spec in attacks:
            first = spec.split("+")[0]
            off_hours = SCEN["scenarios"][first].get("off_hours", False)
            for _ in range(count):
                # keep day 0 attack-free when possible so baselines have clean history to learn from
                lo_day = 1 if days > 1 else 0
                day = rng.randint(lo_day, days - 1)
                hour = rng.uniform(2, 10) if off_hours else rng.uniform(0, 24)
                t0 = start_dt + timedelta(days=day, hours=hour)
                evs, rows = runner.run(spec, t0, stealth=stealth)
                events.extend(evs)
                injections.extend(rows)
        events.sort(key=lambda e: e[0]["eventTime"])
    return Dataset(world, events, injections)
