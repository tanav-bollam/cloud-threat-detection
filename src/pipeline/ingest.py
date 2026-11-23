"""Lenient CloudTrail file ingestion: any real export -> the same DuckDB `events` table the detectors use. No AWS SDK, no credentials.

Accepts files or folders of: .json ({"Records": [...]}, a bare list, or a single record), .json.gz / .gz, JSON-lines, and .tar / .tar.gz / .tgz
archives of those. Real CloudTrail varies a lot (older schema versions, missing fields, identity types such as AWSAccount, IPv6 sources,
anonymized values), so flattening here never assumes a field exists; records without an eventID/eventTime/eventName are counted and skipped.
"""
from __future__ import annotations

import io
import json
import re
import tarfile
import zlib
from pathlib import Path
from typing import Iterable, Iterator, Optional

import pandas as pd

from . import storage

_LOG_SUFFIXES = (".json", ".json.gz", ".gz", ".jsonl", ".ndjson", ".tar", ".tar.gz", ".tgz")
_READ_PREFIX = ("Get", "List", "Describe", "Head", "Lookup", "Search", "Select", "Batch Get")
_ROLE_RE = re.compile(r":assumed-role/([^/]+)/")


def _records_from_obj(obj) -> Iterator[dict]:
    if isinstance(obj, dict):
        if isinstance(obj.get("Records"), list):
            for r in obj["Records"]:
                if isinstance(r, dict):
                    yield r
        elif "eventName" in obj and "eventTime" in obj:
            yield obj
    elif isinstance(obj, list):
        for r in obj:
            if isinstance(r, dict):
                yield r


def _parse_text(text: str) -> Iterator[dict]:
    text = text.strip()
    if not text:
        return
    try:
        yield from _records_from_obj(json.loads(text))
        return
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():                      # JSON lines
        line = line.strip()
        if line:
            try:
                yield from _records_from_obj(json.loads(line))
            except json.JSONDecodeError:
                continue


MAX_DECOMPRESSED_BYTES = 1 << 30          # 1 GiB: a gzip member that expands beyond this is treated as a decompression bomb


def _gunzip(data: bytes) -> bytes:
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
    if len(out) > MAX_DECOMPRESSED_BYTES or d.unconsumed_tail:
        raise ValueError(f"decompressed size exceeds {MAX_DECOMPRESSED_BYTES:,} bytes (possible decompression bomb)")
    return out


def _read_bytes(name: str, data: bytes) -> Iterator[dict]:
    low = name.lower()
    if low.endswith((".tar", ".tar.gz", ".tgz")):
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            for m in t:
                if m.isfile():
                    f = t.extractfile(m)
                    if f is not None:
                        yield from _read_bytes(m.name, f.read())
        return
    if low.endswith(".gz"):
        data = _gunzip(data)
        name = name[:-3]
    yield from _parse_text(data.decode("utf-8", errors="replace"))


def iter_records(paths: Iterable[str | Path], errors: Optional[list] = None) -> Iterator[dict]:
    """Yield CloudTrail records. A file that cannot be read (corrupt gzip, decompression bomb, bad tar) is skipped and appended to `errors`
    so one bad file never aborts a large ingest."""
    for p in paths:
        p = Path(p)
        # a directory is walked for log-like files only (so an output .duckdb or README next to the exports is never read);
        # a file named explicitly is always attempted
        files = sorted(x for x in p.rglob("*") if x.is_file() and x.name.lower().endswith(_LOG_SUFFIXES) and not x.name.startswith(".")) if p.is_dir() else [p]
        for f in files:
            if f.suffix.lower() == ".tar":                   # stream big tars member by member instead of reading them whole
                try:
                    with tarfile.open(f) as t:
                        for m in t:
                            if m.isfile():
                                fh = t.extractfile(m)
                                if fh is not None:
                                    try:
                                        yield from _read_bytes(m.name, fh.read())
                                    except (ValueError, OSError, EOFError, zlib.error) as ex:
                                        if errors is not None:
                                            errors.append(f"{f.name}:{m.name}: {ex}")
                except (tarfile.TarError, OSError) as ex:
                    if errors is not None:
                        errors.append(f"{f.name}: {ex}")
                continue
            try:
                yield from _read_bytes(f.name, f.read_bytes())
            except (ValueError, OSError, EOFError, zlib.error) as ex:
                if errors is not None:
                    errors.append(f"{f.name}: {ex}")


def _identity_name(ui: dict) -> str:
    t = ui.get("type") or "Unknown"
    sc = ui.get("sessionContext") or {}
    issuer = (sc.get("sessionIssuer") or {}) if isinstance(sc, dict) else {}
    arn = ui.get("arn") or ""
    if t == "IAMUser":
        return ui.get("userName") or arn or ui.get("principalId") or "unknown"
    if t == "AssumedRole":
        m = _ROLE_RE.search(arn)
        return issuer.get("userName") or (m.group(1) if m else None) or arn or "unknown"
    if t == "Root":
        return "root"
    if t == "AWSService":
        return ui.get("invokedBy") or "aws-service"
    return ui.get("userName") or arn or ui.get("principalId") or ui.get("accountId") or ui.get("invokedBy") or "unknown"


def flatten_lenient(rec: dict) -> Optional[dict]:
    eid, et, name = rec.get("eventID"), rec.get("eventTime"), rec.get("eventName")
    if not (eid and et and name):
        return None
    ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    sc = ui.get("sessionContext") if isinstance(ui.get("sessionContext"), dict) else {}
    attrs = sc.get("attributes") if isinstance(sc.get("attributes"), dict) else {}
    mfa = attrs.get("mfaAuthenticated")
    add = rec.get("additionalEventData") if isinstance(rec.get("additionalEventData"), dict) else {}
    resp = rec.get("responseElements") if isinstance(rec.get("responseElements"), dict) else {}
    ro = rec.get("readOnly")
    if ro is None:
        ro = name.startswith(_READ_PREFIX)
    mg = rec.get("managementEvent")
    if mg is None:
        mg = rec.get("eventCategory", "Management") != "Data"
    bytes_out = add.get("bytesTransferredOut")
    try:
        bytes_out = int(bytes_out) if bytes_out is not None else None
    except (TypeError, ValueError):
        bytes_out = None
    return {
        "event_id": str(eid), "event_time": str(et).replace("T", " ").rstrip("Z")[:19], "event_source": str(rec.get("eventSource") or ""), "event_name": str(name),
        "aws_region": str(rec.get("awsRegion") or ""), "source_ip": str(rec.get("sourceIPAddress") or ""), "user_agent": str(rec.get("userAgent") or ""),
        "identity_type": str(ui.get("type") or "Unknown"), "identity": _identity_name(ui), "principal_id": ui.get("principalId"), "identity_arn": ui.get("arn"),
        "access_key_id": ui.get("accessKeyId") or None, "account_id": ui.get("accountId") or rec.get("recipientAccountId"),
        "mfa_authenticated": None if mfa is None else str(mfa).lower() == "true", "error_code": rec.get("errorCode"), "read_only": bool(ro),
        "management_event": bool(mg), "event_type": str(rec.get("eventType") or "AwsApiCall"), "bytes_out": bytes_out,
        "console_login": resp.get("ConsoleLogin") if name == "ConsoleLogin" else None, "raw": json.dumps(rec, separators=(",", ":")),
    }


def _insert_ignore(con, rows: list[dict]) -> int:
    ev = pd.DataFrame(rows, columns=storage.EVENT_COLS).drop_duplicates("event_id")
    ev["event_time"] = pd.to_datetime(ev["event_time"], errors="coerce")
    ev = ev.dropna(subset=["event_time"])
    con.register("_ing", ev)
    n0 = con.execute("SELECT count(*) FROM events").fetchall()[0][0]
    con.execute("INSERT OR IGNORE INTO events SELECT * FROM _ing").fetchall()
    con.unregister("_ing")
    return con.execute("SELECT count(*) FROM events").fetchall()[0][0] - n0


def ingest(con, paths: Iterable[str | Path], chunk: int = 50_000, progress=None) -> dict:
    """Stream records into `events` (duplicates by eventID ignored). Returns counts."""
    seen = inserted = skipped = 0
    buf: list[dict] = []
    errors: list[str] = []
    for rec in iter_records(paths, errors):
        seen += 1
        row = flatten_lenient(rec)
        if row is None:
            skipped += 1
            continue
        buf.append(row)
        if len(buf) >= chunk:
            inserted += _insert_ignore(con, buf)
            buf = []
            if progress:
                progress(seen, inserted)
    if buf:
        inserted += _insert_ignore(con, buf)
    return {"records_seen": seen, "inserted": inserted, "skipped_invalid": skipped, "duplicates": seen - skipped - inserted, "unreadable_files": errors[:20]}
