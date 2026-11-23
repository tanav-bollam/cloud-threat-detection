"""User-adjustable runtime settings (saved to data/settings.json, applied to the running engine)."""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from src.integrations.webhook import WebhookNotifier, valid_url


@dataclass
class Settings:
    disabled_rules: list[str] = field(default_factory=list)
    dedupe_s: float = 300.0                  # single-event rules: repeats within this window fold into one alert (0 = off)
    anomaly_sensitivity: float = 0.0         # added to every anomaly threshold: negative = more sensitive (more alerts), positive = fewer
    webhook_url: str = ""
    webhook_min_severity: str = "HIGH"

    def validate(self) -> list[str]:
        errs = []
        if self.dedupe_s < 0 or self.dedupe_s > 86400:
            errs.append("Deduplication window must be between 0 and 86400 seconds.")
        if not -0.3 <= self.anomaly_sensitivity <= 0.3:
            errs.append("Anomaly sensitivity must be between -0.3 and 0.3.")
        if self.webhook_url and not valid_url(self.webhook_url):
            errs.append("Webhook URL must start with http:// or https://.")
        if self.webhook_min_severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            errs.append("Unknown webhook severity.")
        return errs


def settings_path() -> Path:
    return Path(os.environ.get("CTD_SETTINGS", "data/settings.json"))


def load(path: Optional[Path] = None) -> Settings:
    p = path or settings_path()
    s = Settings()
    if p.exists():
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            for k, v in raw.items():
                if hasattr(s, k):
                    setattr(s, k, v)
        except (ValueError, OSError):
            pass                                   # a corrupt settings file falls back to defaults
    env_url = os.environ.get("CTD_WEBHOOK_URL")
    if env_url:
        s.webhook_url = env_url                    # the environment wins, so deployments never have to store the URL in a file
    return s


def save(s: Settings, path: Optional[Path] = None) -> None:
    p = path or settings_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    data = asdict(s)
    if os.environ.get("CTD_WEBHOOK_URL"):
        data["webhook_url"] = ""                   # do not write an env-provided secret to disk
    p.write_text(json.dumps(data, indent=1), encoding="utf-8")


def apply(engine, s: Settings) -> list[str]:
    """Apply settings to a running LiveEngine. Returns warnings (e.g. an unusable webhook)."""
    warnings: list[str] = []
    det = engine.detector
    det.rules.disabled = set(s.disabled_rules)
    det.rules.dedupe_s = s.dedupe_s
    if engine.model is not None:
        for u in engine.model.units.values():
            if not hasattr(u, "_base_threshold"):
                u._base_threshold = u.threshold                   # remember the calibrated value; sensitivity is an offset from it
            u.threshold = u._base_threshold + s.anomaly_sensitivity
    old = getattr(engine, "_webhook", None)
    if old is not None:
        old.close()
        if old in engine.callbacks:
            engine.callbacks.remove(old)
        engine._webhook = None
    if s.webhook_url:
        try:
            n = WebhookNotifier(s.webhook_url, s.webhook_min_severity)
            engine.callbacks.append(n)
            engine._webhook = n
        except ValueError as ex:
            warnings.append(str(ex))
    return warnings
