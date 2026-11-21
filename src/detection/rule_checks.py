"""Python predicates referenced by name from rule YAML (for things YAML can't express: parsing embedded policy JSON)."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
_BIG_INSTANCE = re.compile(r"^(p\d|g\d|inf\d|trn\d|dl\d)[a-z]*\.|\.(16|18|24|32|48)xlarge$|\.metal$", re.I)


def _doc(v: Any) -> dict:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            return json.loads(v)
        except ValueError:
            return {}
    return {}


def _statements(doc: dict) -> list[dict]:
    st = doc.get("Statement", [])
    return [st] if isinstance(st, dict) else [s for s in st if isinstance(s, dict)]


def _aslist(x: Any) -> list:
    return x if isinstance(x, list) else [x]


def _principals(stmt: dict) -> list[str]:
    p = stmt.get("Principal")
    if p == "*":
        return ["*"]
    if isinstance(p, dict):
        return [v for vals in p.values() for v in _aslist(vals)]
    return []


def public_bucket_policy(rec: dict, ctx: dict) -> bool:
    pol = _doc((rec.get("requestParameters") or {}).get("policy"))
    for s in _statements(pol):
        if s.get("Effect") == "Allow" and "*" in _principals(s) and not s.get("Condition"):
            return True
    return False


def public_acl(rec: dict, ctx: dict) -> bool:
    rp = rec.get("requestParameters") or {}
    acl = rp.get("acl")
    if isinstance(acl, list) and any(a in _PUBLIC_ACLS for a in acl):
        return True
    return "AllUsers" in json.dumps(rp.get("AccessControlPolicy", ""))


def admin_policy_document(rec: dict, ctx: dict) -> bool:
    doc = _doc((rec.get("requestParameters") or {}).get("policyDocument"))
    for s in _statements(doc):
        if s.get("Effect") == "Allow" and "*" in _aslist(s.get("Action", [])) and "*" in _aslist(s.get("Resource", [])):
            return True
    return False


def external_trust_policy(rec: dict, ctx: dict) -> bool:
    doc = _doc((rec.get("requestParameters") or {}).get("policyDocument"))
    for s in _statements(doc):
        for pr in _principals(s):
            if pr == "*":
                return True
            m = re.search(r"arn:aws:iam::(\d{12}):", pr)
            if m and m.group(1) != ctx["account_id"]:
                return True
            if re.fullmatch(r"\d{12}", pr) and pr != ctx["account_id"]:
                return True
    return False


def snapshot_shared_external(rec: dict, ctx: dict) -> bool:
    perm = (rec.get("requestParameters") or {}).get("createVolumePermission") or {}
    for item in (perm.get("add") or {}).get("items", []):
        if item.get("group") == "all" or (item.get("userId") and item["userId"] != ctx["account_id"]):
            return True
    return False


def big_instance(rec: dict, ctx: dict) -> bool:
    rp = rec.get("requestParameters") or {}
    t = rp.get("instanceType") or (rp.get("launchSpecification") or {}).get("instanceType") or ""
    return bool(_BIG_INSTANCE.search(t))


def non_home_region(rec: dict, ctx: dict) -> bool:
    return rec["awsRegion"] not in ctx["home_regions"]


def key_for_other_user(rec: dict, ctx: dict) -> bool:
    target = (rec.get("requestParameters") or {}).get("userName")
    me = rec["userIdentity"].get("userName")
    return bool(target) and target != me


def open_to_world(rec: dict, ctx: dict) -> bool:
    perms = ((rec.get("requestParameters") or {}).get("ipPermissions") or {}).get("items", [])
    return any(r.get("cidrIp") == "0.0.0.0/0" for p in perms for r in (p.get("ipRanges") or {}).get("items", []))


def console_login_success(rec: dict, ctx: dict) -> bool:
    return (rec.get("responseElements") or {}).get("ConsoleLogin") == "Success"


def console_login_failure(rec: dict, ctx: dict) -> bool:
    return (rec.get("responseElements") or {}).get("ConsoleLogin") == "Failure"


def no_mfa_login(rec: dict, ctx: dict) -> bool:
    return console_login_success(rec, ctx) and (rec.get("additionalEventData") or {}).get("MFAUsed") == "No"


def is_error(rec: dict, ctx: dict) -> bool:
    return bool(rec.get("errorCode")) and rec["errorCode"] in ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation")


def detector_disabled(rec: dict, ctx: dict) -> bool:
    if rec["eventName"] == "DeleteDetector":
        return True
    return rec["eventName"] == "UpdateDetector" and (rec.get("requestParameters") or {}).get("enable") is False


CHECKS: dict[str, Callable[[dict, dict], bool]] = {
    "public_bucket_policy": public_bucket_policy, "public_acl": public_acl, "admin_policy_document": admin_policy_document,
    "external_trust_policy": external_trust_policy, "snapshot_shared_external": snapshot_shared_external, "big_instance": big_instance,
    "non_home_region": non_home_region, "key_for_other_user": key_for_other_user, "open_to_world": open_to_world,
    "console_login_failure": console_login_failure, "console_login_success": console_login_success, "no_mfa_login": no_mfa_login,
    "is_error": is_error, "detector_disabled": detector_disabled,
}
