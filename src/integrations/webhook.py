"""Optional alert delivery to a Discord or Slack incoming webhook (both free), or any URL that accepts a JSON POST.

Off unless a URL is configured. A failing or slow endpoint can never stall or crash the detection pipeline: alerts are queued and sent
from a background thread, with a per-minute cap and a bounded queue. The payload contains the alert title, severity, identity, IP and
MITRE tactic: with a real webhook this leaves your machine, so point it only at a channel you control.
"""
from __future__ import annotations

import ipaddress
import json
import os
import queue
import socket
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable, Optional
from urllib.parse import urlparse

from src.detection.rules_engine import SEVERITY_ORDER, Alert

COLORS = {"LOW": 0x9A99A6, "MEDIUM": 0xFAB219, "HIGH": 0xEC835A, "CRITICAL": 0xD03B3B}
SYMBOL = {"LOW": "○", "MEDIUM": "●", "HIGH": "▲", "CRITICAL": "◆"}


def valid_url(url: str) -> bool:
    try:
        u = urlparse(url)
    except ValueError:
        return False
    return u.scheme in ("http", "https") and bool(u.netloc)


def detect_kind(url: str) -> str:
    host = urlparse(url).netloc.lower()
    if "discord.com" in host or "discordapp.com" in host:
        return "discord"
    if "slack.com" in host:
        return "slack"
    return "generic"


def build_payload(a: Alert, kind: str) -> dict:
    head = f"{SYMBOL.get(a.severity, '')} {a.severity}: {a.title}"
    facts = {"Identity": a.identity, "Source IP": a.source_ip or "n/a", "Layer": a.source, "Rule": a.rule_id, "MITRE": " / ".join(x for x in (a.mitre_tactic, a.mitre_technique) if x) or "n/a",
             "Risk": f"{a.risk:.0f}/100", "Detected (sim UTC)": a.detected_at}
    if kind == "discord":
        return {"username": "cloud-threat-detection",
                "embeds": [{"title": head[:250], "description": (a.detail or a.description)[:1000], "color": COLORS.get(a.severity, 0x888888),
                            "fields": [{"name": k, "value": str(v)[:200], "inline": True} for k, v in facts.items()]}]}
    text = head + "\n" + "\n".join(f"• {k}: {v}" for k, v in facts.items())
    if kind == "slack":
        return {"text": text}
    return {"severity": a.severity, "title": a.title, "alert_id": a.alert_id, "text": text, **{k.lower().replace(" ", "_"): v for k, v in facts.items()}}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A webhook endpoint must answer directly: following a redirect would let it bounce the request to an internal address."""

    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def destination_error(url: str, strict: Optional[bool] = None) -> Optional[str]:
    """Why this URL must not be contacted, or None if it is fine. Always blocks link-local/metadata (169.254.0.0/16, fe80::/10), unspecified,
    multicast and reserved addresses (the cloud-metadata SSRF targets). With CTD_WEBHOOK_STRICT=1 (or strict=True) loopback and private
    ranges are blocked too, for deployments where the dashboard is reachable by people who must not be able to probe the internal network."""
    strict = os.environ.get("CTD_WEBHOOK_STRICT") == "1" if strict is None else strict
    host = urlparse(url).hostname
    if not host:
        return "no host in URL"
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError as ex:
        return f"could not resolve {host}: {ex}"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved:
            return f"destination {ip} is blocked (link-local / metadata / reserved range)"
        if strict and (ip.is_loopback or ip.is_private):
            return f"destination {ip} is blocked in strict mode (loopback / private range)"
    return None


def _http_post(url: str, payload: dict, timeout: float) -> int:
    err = destination_error(url)
    if err:
        raise ValueError(err)
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json", "User-Agent": "cloud-threat-detection/0.1"}, method="POST")
    with _OPENER.open(req, timeout=timeout) as r:       # noqa: S310 - scheme validated in valid_url, destination in destination_error, redirects disabled
        return r.status


class WebhookNotifier:
    """Callable usable as a LiveEngine alert callback: `engine.callbacks.append(WebhookNotifier(url))`."""

    def __init__(self, url: str, min_severity: str = "HIGH", kind: str = "auto", max_per_minute: int = 20, timeout: float = 5.0,
                 post: Optional[Callable[[str, dict, float], int]] = None, queue_size: int = 200):
        if not valid_url(url):
            raise ValueError("webhook URL must be http(s)")
        if min_severity not in SEVERITY_ORDER:
            raise ValueError(f"unknown severity {min_severity}")
        self.url, self.min_rank = url, SEVERITY_ORDER[min_severity]
        self.min_severity = min_severity
        self.kind = detect_kind(url) if kind == "auto" else kind
        self.max_per_minute, self.timeout = max_per_minute, timeout
        self._post = post or _http_post
        self._q: queue.Queue = queue.Queue(maxsize=queue_size)
        self._sent_times: deque = deque()
        self.stats = {"sent": 0, "failed": 0, "skipped_below_threshold": 0, "dropped_rate_limit": 0, "dropped_queue_full": 0, "last_error": None}
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True, name="webhook")
        self._t.start()

    def __call__(self, alert: Alert) -> None:
        if SEVERITY_ORDER.get(alert.severity, 0) < self.min_rank:
            self.stats["skipped_below_threshold"] += 1
            return
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self.stats["dropped_queue_full"] += 1

    def send_test(self) -> tuple[bool, str]:
        """Synchronous test message; returns (ok, detail)."""
        a = Alert("TEST", "Test notification from cloud-threat-detection", "LOW", "", "", "test", "1970-01-01T00:00:00Z", "test-identity", "", "This is a test message.")
        try:
            return 200 <= self._post(self.url, build_payload(a, self.kind), self.timeout) < 300, "sent"
        except Exception as ex:      # noqa: BLE001 - report any failure to the UI instead of raising
            return False, f"{type(ex).__name__}: {ex}"

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                a = self._q.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                self._deliver(a)
            finally:
                self._q.task_done()                  # lets drain() know the send really finished

    def _deliver(self, a: Alert) -> None:
        now = time.time()
        while self._sent_times and now - self._sent_times[0] > 60:
            self._sent_times.popleft()
        if len(self._sent_times) >= self.max_per_minute:
            self.stats["dropped_rate_limit"] += 1
            return
        self._sent_times.append(now)
        try:
            ok = 200 <= self._post(self.url, build_payload(a, self.kind), self.timeout) < 300
            self.stats["sent" if ok else "failed"] += 1
        except Exception as ex:   # noqa: BLE001 - a dead endpoint must never affect detection
            self.stats["failed"] += 1
            self.stats["last_error"] = f"{type(ex).__name__}: {ex}"

    def drain(self, timeout: float = 5.0) -> None:
        """Wait until every queued alert has been fully processed (used by tests)."""
        t0 = time.time()
        while self._q.unfinished_tasks and time.time() - t0 < timeout:
            time.sleep(0.02)

    def close(self) -> None:
        self._stop.set()
