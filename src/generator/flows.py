"""Synthetic VPC Flow Logs correlated with the CloudTrail events already in a dataset (stretch goal).

Flow logs are generated AFTER the CloudTrail dataset, from its events (and, because this is the generation side, from the labels that say which
instances the simulated attacker launched). Records follow the VPC Flow Logs v2 format with a few custom fields (vpc-id, instance-id, region,
flow-direction, flow-log-id), aggregated into 10-minute windows per instance.

What exists:
  * a small long-lived fleet per home region (web: inbound 443 from the internet; app: east-west to the database and outbound 443; db: 5432 from app)
    plus background internet noise on port 22 that the security group REJECTs;
  * every instance launched by a successful RunInstances event (CloudTrail instanceId), with benign chatter, or, when the launch is a labeled S7
    (crypto-mining) event, sustained outbound connections to mining-pool (stratum) ports;
  * after an S7 AuthorizeSecurityGroupIngress that opens SSH to the world, internet scanners reach the instances in that region (ACCEPT on port 22);
  * after a DeleteFlowLogs event, the flow log it deleted produces NO further records (so the silence can be detected).
Assumption stated loudly: the organisation runs a VPC flow log in EVERY region (an org policy). Without that, mining in an unmonitored region
would leave no flow evidence at all.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

import pandas as pd

from .catalog import flow_log_id_for, vpc_id_for

MINING_PORTS = (3333, 4444, 5555, 7777, 14444, 14433)
WINDOW = timedelta(minutes=10)
MINING_PRIVATE = "10."


@dataclass
class Inst:
    instance_id: str
    region: str
    private_ip: str
    role: str                       # web | app | db | worker | miner
    launched: datetime
    eni: str = ""
    flow_log_id: str = ""


def _public_ip(rng: random.Random) -> str:
    # avoid the synthetic office/CI/AWS ranges used elsewhere so flow sources look like arbitrary internet hosts
    return f"{rng.choice([23, 34, 50, 64, 91, 104, 141, 162, 178, 203])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _eni(rng: random.Random) -> str:
    return "eni-0" + "".join(rng.choices("0123456789abcdef", k=16))


def fleet(account: str, regions: list[str], t0: datetime, rng: random.Random) -> list[Inst]:
    out = []
    for ri, region in enumerate(regions):
        for k, role in enumerate(("web", "app", "db")):
            iid = "i-0" + "".join(rng.choices("0123456789abcdef", k=16))
            out.append(Inst(iid, region, f"10.{ri + 1}.0.{10 + k}", role, t0 - timedelta(days=30), _eni(rng)))
    return out


def _flow(rng: random.Random, inst: Inst, w: datetime, account: str, *, src: str, dst: str, sport: int, dport: int, direction: str, action: str = "ACCEPT",
          packets: tuple[int, int] = (5, 60), bytes_per_packet: tuple[int, int] = (60, 900)) -> dict:
    s = w + timedelta(seconds=rng.randint(0, 540))
    pk = rng.randint(*packets)
    return {"start_time": s, "end_time": s + timedelta(seconds=rng.randint(10, 59)), "account_id": account, "interface_id": inst.eni, "instance_id": inst.instance_id,
            "vpc_id": vpc_id_for(account, inst.region), "region": inst.region, "srcaddr": src, "dstaddr": dst, "srcport": sport, "dstport": dport, "protocol": 6,
            "packets": pk, "bytes": pk * rng.randint(*bytes_per_packet), "action": action, "flow_direction": direction,
            "flow_log_id": inst.flow_log_id or flow_log_id_for(account, inst.region), "log_status": "OK"}


def _benign(rng: random.Random, inst: Inst, w: datetime, account: str, fl: list[dict]) -> None:
    eph = lambda: rng.randint(32768, 60999)
    if inst.role == "web":
        for _ in range(max(1, int(rng.gauss(6, 2)))):
            src = _public_ip(rng)
            fl.append(_flow(rng, inst, w, account, src=src, dst=inst.private_ip, sport=eph(), dport=443, direction="ingress"))
            fl.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=src, sport=443, dport=eph(), direction="egress", bytes_per_packet=(400, 1400)))
    elif inst.role == "app":
        for _ in range(max(1, int(rng.gauss(4, 1.5)))):
            fl.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=inst.private_ip.rsplit(".", 1)[0] + ".12", sport=eph(), dport=5432, direction="egress"))
        fl.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=_public_ip(rng), sport=eph(), dport=443, direction="egress"))
    elif inst.role == "db":
        for _ in range(max(1, int(rng.gauss(4, 1.5)))):
            fl.append(_flow(rng, inst, w, account, src=inst.private_ip.rsplit(".", 1)[0] + ".11", dst=inst.private_ip, sport=eph(), dport=5432, direction="ingress"))
    else:                                                    # a freshly launched worker: package updates and a little internal traffic
        fl.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=_public_ip(rng), sport=eph(), dport=443, direction="egress"))
    if inst.role in ("web", "app") and rng.random() < 0.5:   # background internet SSH noise that the security group rejects
        fl.append(_flow(rng, inst, w, account, src=_public_ip(rng), dst=inst.private_ip, sport=eph(), dport=22, direction="ingress", action="REJECT", packets=(1, 3)))


def generate_flows(con, cfg: dict, seed: int = 0) -> pd.DataFrame:
    """Build the `flows` table for the dataset in `con` (needs events; labels are optional and only used to mark simulated mining)."""
    rng = random.Random(f"flows-{seed}")
    account = cfg["org"]["account_id"]
    regions = list(cfg["org"]["home_regions"])
    lo, hi = con.execute("SELECT min(event_time), max(event_time) FROM events").fetchone()
    t0, t1 = pd.Timestamp(lo).floor("10min").to_pydatetime(), pd.Timestamp(hi).to_pydatetime()
    insts = fleet(account, regions, t0, rng)
    has_labels = con.execute("SELECT count(*) FROM labels").fetchone()[0] > 0
    q = ("SELECT e.event_time, e.aws_region, e.raw, COALESCE(l.is_malicious AND l.scenario_id = 'S7', FALSE) FROM events e LEFT JOIN labels l USING (event_id) "
         "WHERE e.event_name = 'RunInstances' AND e.error_code IS NULL ORDER BY e.event_time") if has_labels else \
        ("SELECT e.event_time, e.aws_region, e.raw, FALSE FROM events e WHERE e.event_name = 'RunInstances' AND e.error_code IS NULL ORDER BY e.event_time")
    for t, region, raw, mining in con.execute(q).fetchall():
        rec = json.loads(raw)
        for it in ((rec.get("responseElements") or {}).get("instancesSet") or {}).get("items", []):
            insts.append(Inst(it["instanceId"], region, f"10.{200 + len(insts) % 50}.{rng.randint(0, 255)}.{rng.randint(4, 250)}", "miner" if mining else "worker",
                              pd.Timestamp(t).to_pydatetime(), _eni(rng)))
    deleted, region_log = {}, {}
    for t, region, raw in con.execute("SELECT event_time, aws_region, raw FROM events WHERE event_name = 'DeleteFlowLogs' AND error_code IS NULL ORDER BY event_time").fetchall():
        fid = (((json.loads(raw).get("requestParameters") or {}).get("DeleteFlowLogsRequest") or {}).get("FlowLogId") or {}).get("content")
        if fid:
            if fid not in deleted:
                deleted[fid] = pd.Timestamp(t).to_pydatetime()
            # datasets generated before flow-log ids were deterministic carry arbitrary ids: adopt the first deleted id of a region as that region's flow log
            region_log.setdefault(region, fid)
    for inst in insts:
        inst.flow_log_id = region_log.get(inst.region, flow_log_id_for(account, inst.region))
    exposure = {}
    if has_labels:
        for t, region in con.execute("SELECT e.event_time, e.aws_region FROM events e JOIN labels l USING (event_id) "
                                     "WHERE e.event_name = 'AuthorizeSecurityGroupIngress' AND l.is_malicious AND l.scenario_id = 'S7'").fetchall():
            exposure.setdefault(region, []).append(pd.Timestamp(t).to_pydatetime())
    pools = [(f"{p}.{rng.randint(1, 250)}.{rng.randint(1, 250)}.{rng.randint(1, 250)}", rng.choice(MINING_PORTS)) for p in (45, 94, 148, 185)]
    flows: list[dict] = []
    w = t0
    while w <= t1:
        for inst in insts:
            if inst.launched > w + WINDOW:
                continue
            gone = deleted.get(inst.flow_log_id)
            if gone is not None and w >= gone:                # the flow log was deleted: nothing is recorded any more
                continue
            if inst.role != "miner":
                _benign(rng, inst, w, account, flows)
            if inst.role == "miner" and w >= inst.launched + timedelta(minutes=2) and w <= inst.launched + timedelta(hours=6):
                pool_ip, port = pools[int(inst.instance_id[-4:], 16) % len(pools)]          # stable across runs (str hash() is randomised per process)
                for _ in range(rng.randint(2, 4)):
                    flows.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=pool_ip, sport=rng.randint(32768, 60999), dport=port, direction="egress",
                                       packets=(30, 220), bytes_per_packet=(60, 200)))
            elif inst.role == "miner":
                flows.append(_flow(rng, inst, w, account, src=inst.private_ip, dst=_public_ip(rng), sport=rng.randint(32768, 60999), dport=443, direction="egress"))
            for ts in exposure.get(inst.region, []):
                if inst.role in ("miner", "web") and ts <= w <= ts + timedelta(hours=3):
                    for _ in range(rng.randint(2, 4)):
                        flows.append(_flow(rng, inst, w, account, src=_public_ip(rng), dst=inst.private_ip, sport=rng.randint(32768, 60999), dport=22, direction="ingress",
                                           packets=(5, 40)))
        w += WINDOW
    df = pd.DataFrame(flows)
    if len(df) and deleted:     # records are placed randomly inside each 10-minute window: drop any that fall after the flow log was deleted
        cut = df["flow_log_id"].map(lambda f: deleted.get(f))
        df = df[~(cut.notna() & (df["start_time"] >= cut))]
    return df.sort_values("start_time").reset_index(drop=True) if len(df) else df
