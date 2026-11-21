"""Live pipeline: Streamer thread -> bounded queue -> Detector thread -> DuckDB (events, alerts, incidents, ttd).

* The streamer replays a generated benign stream against a simulated clock (speed = sim-seconds per wall-second, 0 = as fast as
  possible) and merges in attacks injected at any time (`LiveEngine.inject`).
* The detector is event-time driven (it never looks at the wall clock), so results are identical at any replay speed.
* Ground truth (labels, injections, time-to-detect) lives in `GroundTruth`, owned by the harness. The detector only ever receives
  CloudTrail records.
DuckDB allows one writing process, so the dashboard runs in the same process and reads through `LiveEngine.cursor()`.
"""
from __future__ import annotations

import heapq
import itertools
import queue
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

import numpy as np
import pandas as pd

from src.detection import features as F
from src.detection.explain import explain
from src.detection.features import Baseline, compute_windows
from src.detection.iforest import AnomalyModel, windows_to_alerts
from src.detection.incidents import group_alerts
from src.detection.ip_analysis import IpAnalyzer
from src.detection.rules_engine import Alert, RulesEngine
from src.detection.scoring import load_config, score_alert, score_alerts
from src.detection.triage import SuppressionList
from src.generator.attacks import AttackRunner
from src.generator.benign import BenignGenerator
from src.generator.world import build_world, load_yaml
from src.pipeline import storage
from src.pipeline.batch import org_context

STEP = pd.Timedelta(minutes=F.STEP_MIN)
WIN = pd.Timedelta(minutes=F.WINDOW_MIN)


def _epoch(rec: dict) -> float:
    return datetime.strptime(rec["eventTime"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def _dt(ep: float) -> datetime:
    return datetime.fromtimestamp(ep, tz=timezone.utc).replace(tzinfo=None)


# ====================================================================================================== ground truth (harness only)
class GroundTruth:
    """Labels, injections and time-to-detect. Owned by the harness; nothing in src/detection imports this."""

    def __init__(self, con, lock: threading.RLock):
        self.con, self.lock = con, lock
        self.labels: dict[str, dict] = {}
        self.event_inj: dict[str, str] = {}
        self.inj: dict[str, dict] = {}
        self.emit_wall: dict[str, float] = {}
        self.done: set[str] = set()
        self._pending_labels: list[dict] = []

    def register_events(self, events: list[tuple[dict, Optional[dict]]]) -> None:
        for rec, lab in events:
            if lab:
                self.labels[rec["eventID"]] = lab
                if lab["is_malicious"] and lab.get("injection_id"):
                    self.event_inj[rec["eventID"]] = lab["injection_id"]

    def register_injections(self, rows: list[dict], wall: float, sim_now: datetime) -> None:
        for r in rows:
            self.inj[r["injection_id"]] = {**r, "injected_wall": wall, "injected_sim": sim_now}
        with self.lock:
            storage.insert_injections(self.con, rows)

    def on_emit(self, rec: dict, wall: float) -> None:
        eid = rec["eventID"]
        if eid in self.event_inj:
            self.emit_wall[eid] = wall
        if eid in self.labels:
            self._pending_labels.append({"event_id": eid, **self.labels[eid]})

    def flush_labels(self) -> None:
        if self._pending_labels:
            rows, self._pending_labels = self._pending_labels, []
            with self.lock:
                storage.insert_labels(self.con, rows)

    def on_alerts(self, alerts: list[Alert], wall_now: float, extended: Optional[set] = None, sim_now: Optional[pd.Timestamp] = None) -> list[dict]:
        """An alert that was opened earlier and merely extended to cover this injection counts as detected at `sim_now`, not at its opening."""
        out = []
        extended = extended or set()
        for a in alerts:
            ids = set(a.matched_event_ids) | {a.event_id}
            hits = {self.event_inj[e] for e in ids if e in self.event_inj}
            for inj_id in hits:
                if inj_id in self.done:
                    continue
                self.done.add(inj_id)
                info = self.inj[inj_id]
                first_emit = min((self.emit_wall[e] for e in ids if self.event_inj.get(e) == inj_id and e in self.emit_wall), default=wall_now)
                det_sim = pd.Timestamp(a.detected_at.rstrip("Z"))
                if a.alert_id in extended and sim_now is not None:
                    det_sim = max(det_sim, sim_now)
                start = pd.Timestamp(info["start_time"])
                out.append({"injection_id": inj_id, "scenario_id": info["scenario_id"], "chain_id": info.get("chain_id"),
                            "injected_sim": info["injected_sim"], "injected_wall": datetime.fromtimestamp(info["injected_wall"]),
                            "first_alert_id": a.alert_id, "detected_by": a.rule_id, "first_alert_sim": det_sim.to_pydatetime(),
                            "ttd_sim_s": max(0.0, (det_sim - start).total_seconds()),
                            "ttd_wall_s": max(0.0, wall_now - info["injected_wall"]),
                            "pipeline_latency_ms": max(0.0, (wall_now - first_emit) * 1000.0)})
        if out:
            with self.lock:
                df = pd.DataFrame(out)
                self.con.register("_ttd", df)
                self.con.execute("INSERT OR REPLACE INTO ttd SELECT * FROM _ttd")
                self.con.unregister("_ttd")
        return out


# ====================================================================================================== streamer
class Streamer(threading.Thread):
    def __init__(self, base: list[tuple[dict, Optional[dict]]], q: queue.Queue, truth: GroundTruth, sim_start: datetime, speed: float,
                 until: Optional[datetime] = None):
        super().__init__(daemon=True, name="streamer")
        start_ep = sim_start.replace(tzinfo=timezone.utc).timestamp()
        self.base = [(_epoch(r), r) for r, _ in base if _epoch(r) >= start_ep]
        self.q, self.truth = q, truth
        self.speed = speed
        self.until = until.replace(tzinfo=timezone.utc).timestamp() if until else None
        self._anchor_sim, self._anchor_wall = start_ep, time.time()
        self._last_emitted = start_ep
        self._i = 0
        self._extra: list = []
        self._seq = itertools.count()
        self._lock = threading.Lock()
        self.stop_flag = threading.Event()
        self.paused = threading.Event()
        self.finished = threading.Event()
        self.emitted = 0

    # --- clock
    def sim_now_ep(self) -> float:
        if self.speed <= 0:
            return self._last_emitted
        return self._anchor_sim + (time.time() - self._anchor_wall) * self.speed

    def sim_now(self) -> datetime:
        return _dt(self.sim_now_ep())

    def set_speed(self, speed: float) -> None:
        with self._lock:
            now = self.sim_now_ep()
            self._anchor_sim, self._anchor_wall, self.speed = now, time.time(), speed

    # --- injection
    def add_events(self, events: list[tuple[dict, dict]]) -> None:
        with self._lock:
            for rec, lab in events:
                heapq.heappush(self._extra, (_epoch(rec), next(self._seq), rec))

    def _next(self):
        with self._lock:
            b = self.base[self._i] if self._i < len(self.base) else None
            e = self._extra[0] if self._extra else None
            if b is None and e is None:
                return None
            if e is None or (b is not None and b[0] <= e[0]):
                return b[0], b[1], "base"
            return e[0], e[2], "extra"

    def _pop(self, kind: str) -> None:
        with self._lock:
            if kind == "base":
                self._i += 1
            else:
                heapq.heappop(self._extra)

    def run(self) -> None:
        while not self.stop_flag.is_set():
            if self.paused.is_set():
                time.sleep(0.05)
                continue
            nxt = self._next()
            if nxt is None:
                break
            ts, rec, kind = nxt
            if self.until is not None and ts > self.until:
                break
            if self.speed > 0 and ts > self.sim_now_ep():
                time.sleep(min(0.02, max(0.0, (ts - self.sim_now_ep()) / self.speed)))
                continue
            self._pop(kind)
            self._last_emitted = max(self._last_emitted, ts)
            self.truth.on_emit(rec, time.time())
            while not self.stop_flag.is_set():
                try:
                    self.q.put(rec, timeout=0.2)
                    break
                except queue.Full:
                    continue
            self.emitted += 1
        self.finished.set()
        try:
            self.q.put(None, timeout=5)
        except queue.Full:
            pass


# ====================================================================================================== detector
class Detector(threading.Thread):
    """Consumes records (only records), runs rules + IP layer per event, windows -> IsolationForest every 5 sim-minutes,
    scores, suppresses, groups into incidents and persists."""

    def __init__(self, engine: "LiveEngine"):
        super().__init__(daemon=True, name="detector")
        self.e = engine
        cfg = engine.cfg
        self.rules = RulesEngine(context=org_context(), disabled=engine.disabled_rules)
        self.ip = IpAnalyzer(cfg["ip"], engine.baseline)
        self.buffer: deque = deque()
        self.next_boundary: Optional[pd.Timestamp] = None
        self.alerts: dict[str, Alert] = {}
        self.open_anom: dict[str, tuple[Alert, pd.Timestamp]] = {}
        self.written_incident: dict[str, str] = {}
        self.written_sig: dict[str, tuple] = {}
        self.stats = {"events": 0, "alerts": 0, "suppressed": 0, "anomaly_steps": 0, "last_step_ms": 0.0, "last_event_time": None}
        self.idle = threading.Event()
        self.done = threading.Event()
        self.error: Optional[BaseException] = None

    def run(self) -> None:
        try:
            self._loop()
        except BaseException as ex:      # noqa: BLE001 - surface worker failures to the engine
            self.error = ex
            raise
        finally:
            self.done.set()

    def _loop(self) -> None:
        q = self.e.queue
        while True:
            try:
                first = q.get(timeout=0.2)
            except queue.Empty:
                self.idle.set()
                if self.e.stop_flag.is_set():
                    return
                continue
            self.idle.clear()
            batch = [first]
            while len(batch) < 3000:
                try:
                    batch.append(q.get_nowait())
                except queue.Empty:
                    break
            end = batch[-1] is None
            recs = [r for r in batch if r is not None]
            if recs:
                self._process(recs)
            if end:
                return

    # ------------------------------------------------------------------ batch processing
    def _process(self, recs: list[dict]) -> None:
        new: list[Alert] = []
        touched: list[Alert] = []
        rows = []
        for rec in recs:
            row = storage.flatten(rec)
            t = pd.Timestamp(row["event_time"])
            if self.next_boundary is None:
                self.next_boundary = t.floor(STEP) + STEP
            while self.e.model is not None and t >= self.next_boundary:
                n, tt = self._anomaly_step(self.next_boundary)
                new += n
                touched += tt
                self.next_boundary += STEP
            new += self.rules.evaluate(rec)
            light = {k: row[k] for k in F._PUBLIC_COLS}
            new += self.ip.evaluate({"event_id": row["event_id"], "event_time": t, "identity": row["identity"], "identity_type": row["identity_type"],
                                     "source_ip": row["source_ip"], "event_name": row["event_name"]})
            self.buffer.append(light)
            rows.append(row)
        last_t = pd.Timestamp(rows[-1]["event_time"])
        while self.buffer and pd.Timestamp(self.buffer[0]["event_time"]) < last_t - pd.Timedelta(minutes=self.e.retain_min):
            self.buffer.popleft()
        with self.e.lock:
            storage.insert_flat(self.e.con, rows)
        self.e.on_batch_persisted()
        self.stats["events"] += len(rows)
        self.stats["last_event_time"] = last_t
        self._ingest(new, touched, last_t)

    def _anomaly_step(self, boundary: pd.Timestamp) -> tuple[list[Alert], list[Alert]]:
        t0 = time.time()
        buf = pd.DataFrame(list(self.buffer))
        if buf.empty:
            return [], []
        buf["event_time"] = pd.to_datetime(buf["event_time"])
        ws = boundary - WIN
        feats = compute_windows(buf, self.e.baseline, min_start=ws)
        feats = feats[feats["wstart"] == ws].reset_index(drop=True)
        self.stats["anomaly_steps"] += 1
        if feats.empty:
            return [], []
        model = self.e.model
        scores = model.score(feats)
        flagged = model.flag(feats, scores)
        fresh: list[Alert] = []
        touched: list[Alert] = []
        if flagged.any():
            idx = np.where(flagged)[0]
            rs = explain(model, feats.iloc[idx], 5)
            reasons = {(feats.at[i, "identity"], feats.at[i, "wstart"]): r for i, r in zip(idx, rs)}
            for a in windows_to_alerts(feats, scores, flagged, buf, reasons, model.threshold_for(feats)):
                prev = self.open_anom.get(a.identity)
                if prev and ws <= prev[1] + WIN:          # contiguous with an open run: extend it
                    pa = prev[0]
                    seen = set(pa.matched_event_ids)
                    pa.matched_event_ids += [e for e in a.matched_event_ids if e not in seen]
                    if a.score > pa.score:
                        pa.score, pa.reasons = a.score, a.reasons
                    pa.margin = max(pa.margin, a.margin)
                    pa.detail = f"run extended to {boundary}; max score {pa.score:.3f}"
                    self.open_anom[a.identity] = (pa, ws)
                    touched.append(pa)
                else:
                    self.open_anom[a.identity] = (a, ws)
                    fresh.append(a)
        self.stats["last_step_ms"] = round((time.time() - t0) * 1000, 1)
        return fresh, touched

    def _ingest(self, new: list[Alert], touched: list[Alert], now: pd.Timestamp) -> None:
        if not new and not touched:
            return
        cfg = self.e.cfg
        sc = cfg["scoring"]
        scored = [score_alert(a, sc) for a in new]
        if self.e.suppressions is not None:
            scored, dropped = self.e.suppressions.apply(scored)
            self.stats["suppressed"] += len(dropped)
        for a in touched:
            score_alert(a, sc)
        changed: dict[str, Alert] = {}
        for a in scored:
            if a.alert_id not in self.alerts:
                self.stats["alerts"] += 1
            self.alerts[a.alert_id] = a
            changed[a.alert_id] = a
        for a in touched:
            if a.alert_id in self.alerts:
                changed[a.alert_id] = a
        # prune alerts older than 24h of sim time
        cutoff = now - pd.Timedelta(hours=24)
        for k in [k for k, a in self.alerts.items() if pd.Timestamp(a.detected_at.rstrip("Z")) < cutoff]:
            del self.alerts[k]
        incidents = group_alerts(list(self.alerts.values()), cfg, self.e.org_known_ips)
        incident_of = {aid: i.incident_id for i in incidents for aid in i.alert_ids}
        for aid, iid in incident_of.items():                      # alerts whose incident changed (merges) must be rewritten
            if self.written_incident.get(aid) != iid and aid in self.alerts:
                changed[aid] = self.alerts[aid]
        status_of = self.e.alert_status
        wall_iso = datetime.now().isoformat(timespec="seconds")
        with self.e.lock:
            storage.upsert_alerts(self.e.con, list(changed.values()), incident_of, wall_iso, status_of)
            sig_changed = [i for i in incidents if self.written_sig.get(i.incident_id) != (i.n_alerts, i.severity, i.last_seen, tuple(i.tactics))]
            storage.upsert_incidents(self.e.con, sig_changed)
        for aid in changed:
            self.written_incident[aid] = incident_of.get(aid)
        for i in sig_changed:
            self.written_sig[i.incident_id] = (i.n_alerts, i.severity, i.last_seen, tuple(i.tactics))
        self.e.on_alerts_persisted(list(changed.values()), {a.alert_id for a in touched}, now)
        for a in scored:
            for cb in self.e.callbacks:
                try:
                    cb(a)
                except Exception:        # noqa: BLE001 - a bad callback must not kill the pipeline
                    pass


# ====================================================================================================== engine
class LiveEngine:
    def __init__(self, db_path: str | Path, baseline: Optional[Baseline] = None, model: Optional[AnomalyModel] = None, *, speed: float = 60.0,
                 scale: float = 0.3, seed: int = 777, world_seed: int = 42, start: str = "2025-01-13", start_hour: float = 9.0, days: int = 2,
                 until: Optional[datetime] = None, retain_min: int = 120, suppressions: Optional[SuppressionList] = None,
                 disabled_rules: Optional[set] = None, queue_size: int = 20000, fresh: bool = True, cfg: Optional[dict] = None):
        import duckdb
        self.cfg = cfg or load_config()
        self.baseline, self.model = baseline, model
        if baseline is None:
            raise ValueError("a Baseline is required (it drives the IP layer and anomaly features)")
        self.org_known_ips = set(baseline.org_sets["ip"]["value"])
        self.retain_min = retain_min
        self.suppressions, self.disabled_rules = suppressions, disabled_rules
        self.callbacks: list[Callable[[Alert], None]] = []
        self.alert_status: dict[str, str] = {}
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if fresh and path.exists():
            path.unlink()
        self.con = storage.connect(path)
        self.lock = threading.RLock()
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.stop_flag = threading.Event()
        self.truth = GroundTruth(self.con, self.lock)
        org = load_yaml("org.yaml")
        self.world = build_world(org, world_seed)
        start_dt = datetime.strptime(start, "%Y-%m-%d")
        base = BenignGenerator(self.world, seed, start_dt, days, scale).generate()
        self.truth.register_events(base)
        self.runner = AttackRunner(self.world, seed)
        self.streamer = Streamer(base, self.queue, self.truth, start_dt + timedelta(hours=start_hour), speed, until)
        self.detector = Detector(self)
        self.started_wall: Optional[float] = None

    # --- lifecycle
    def start(self) -> "LiveEngine":
        self.started_wall = time.time()
        self.detector.start()
        self.streamer.start()
        return self

    def stop(self) -> None:
        self.stop_flag.set()
        self.streamer.stop_flag.set()
        self.detector.join(timeout=10)

    def wait(self, timeout: Optional[float] = None) -> bool:
        """Block until the stream ended and the detector drained the queue."""
        return self.detector.done.wait(timeout)

    def cursor(self):
        return self.con.cursor()

    # --- harness hooks (the detector calls these; only the harness touches ground truth)
    def on_batch_persisted(self) -> None:
        self.truth.flush_labels()

    def on_alerts_persisted(self, alerts: list[Alert], extended_ids: set, sim_now: pd.Timestamp) -> None:
        self.truth.on_alerts(alerts, time.time(), extended_ids, sim_now)

    # --- controls
    def set_speed(self, speed: float) -> None:
        self.streamer.set_speed(speed)

    def inject(self, spec: str, victim: Optional[str] = None, stealth: float = 0.0, speed: float = 1.0, at: Optional[datetime] = None) -> list[str]:
        """Inject an attack/kill chain (e.g. 'S1+S3+S4') starting at the current simulated time (or `at`). Returns injection ids."""
        t0 = at or (self.streamer.sim_now() + timedelta(seconds=2))
        events, rows = self.runner.run(spec, t0, victim=victim, stealth=stealth, speed=speed)
        self.truth.register_events(events)
        self.truth.register_injections(rows, time.time(), self.streamer.sim_now())
        self.streamer.add_events(events)
        return [r["injection_id"] for r in rows]

    def mark_alert(self, alert_id: str, status: str, scope: str = "identity", note: str = "") -> None:
        """Analyst triage: update an alert's status; 'False Positive' also adds a suppression entry."""
        self.alert_status[alert_id] = status
        with self.lock:
            self.con.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", [status, alert_id])
        a = self.detector.alerts.get(alert_id)
        if status == "False Positive" and a is not None and self.suppressions is not None:
            self.suppressions.add_from_alert(a, scope, note)

    def set_incident_status(self, incident_id: str, status: str, notes: Optional[str] = None) -> None:
        with self.lock:
            self.con.execute("UPDATE incidents SET status = ? WHERE incident_id = ?", [status, incident_id])
            if notes is not None:
                self.con.execute("UPDATE incidents SET notes = ? WHERE incident_id = ?", [notes, incident_id])

    def stats(self) -> dict:
        s = dict(self.detector.stats)
        s.update({"emitted": self.streamer.emitted, "backlog": self.queue.qsize(), "sim_now": self.streamer.sim_now(),
                  "speed": self.streamer.speed, "wall_elapsed_s": round(time.time() - (self.started_wall or time.time()), 1),
                  "finished": self.streamer.finished.is_set(), "injections": len(self.truth.inj), "detected_injections": len(self.truth.done)})
        return s
