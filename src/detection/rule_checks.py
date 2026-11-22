"""Python predicates referenced by name from rule YAML (for things YAML can't express: parsing embedded policy JSON)."""
from __future__ import annotations

import json
import re
from typing import Any, Callable

_PUBLIC_ACLS = {"public-read", "public-read-write", "authenticated-read"}
_BIG_INSTANCE = re.compile(r"^(p\d|g\d|inf\d|trn\d|dl\d)[a-z]*\.|\.(16|18|24|32|48)xlarge$|\.metal$", re.I)


def _rp(rec: dict) -> dict:
    v = rec.get("requestParameters")
    return v if isinstance(v, dict) else {}


def _re(rec: dict) -> dict:
    v = rec.get("responseElements")
    return v if isinstance(v, dict) else {}


def _d(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _items(v: Any) -> list[dict]:
    """The `{"items": [...]}` wrapper AWS uses for lists, tolerating any other shape."""
    lst = _d(v).get("items")
    return [x for x in lst if isinstance(x, dict)] if isinstance(lst, list) else []


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
    pol = _doc(_rp(rec).get("policy"))
    for s in _statements(pol):
        if s.get("Effect") == "Allow" and "*" in _principals(s) and not s.get("Condition"):
            return True
    return False


def public_acl(rec: dict, ctx: dict) -> bool:
    rp = _rp(rec)
    acl = rp.get("acl")
    if isinstance(acl, list) and any(a in _PUBLIC_ACLS for a in acl):
        return True
    return "AllUsers" in json.dumps(rp.get("AccessControlPolicy", ""))


def admin_policy_document(rec: dict, ctx: dict) -> bool:
    doc = _doc(_rp(rec).get("policyDocument"))
    for s in _statements(doc):
        if s.get("Effect") == "Allow" and "*" in _aslist(s.get("Action", [])) and "*" in _aslist(s.get("Resource", [])):
            return True
    return False


def external_trust_policy(rec: dict, ctx: dict) -> bool:
    rp = _rp(rec)
    doc = _doc(rp.get("policyDocument") or rp.get("assumeRolePolicyDocument"))      # UpdateAssumeRolePolicy / CreateRole
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
    perm = _d(_rp(rec).get("createVolumePermission"))
    return any(it.get("group") == "all" or (it.get("userId") and it["userId"] != ctx["account_id"]) for it in _items(perm.get("add")))


def big_instance(rec: dict, ctx: dict) -> bool:
    rp = _rp(rec)
    t = rp.get("instanceType") or (rp.get("launchSpecification") or {}).get("instanceType") or ""
    return bool(_BIG_INSTANCE.search(t))


def non_home_region(rec: dict, ctx: dict) -> bool:
    return rec.get("awsRegion") not in ctx["home_regions"]


def key_for_other_user(rec: dict, ctx: dict) -> bool:
    target = _rp(rec).get("userName")
    me = (rec.get("userIdentity") or {}).get("userName") if isinstance(rec.get("userIdentity"), dict) else None
    return bool(target) and target != me


def _is_world_cidr(c: Any) -> bool:
    if not isinstance(c, str):
        return False
    return c in ("0.0.0.0/0", "::/0") or c.endswith("/0")        # any /0 mask is the whole internet, whatever the address part says


def open_to_world(rec: dict, ctx: dict) -> bool:
    """AuthorizeSecurityGroupIngress in any of its real shapes: ipPermissions.items[].ipRanges/ipv6Ranges, top-level cidrIp,
    or the cidrIpv4/cidrIpv6 of the response's securityGroupRuleSet."""
    rp, resp = _rp(rec), _re(rec)
    if _is_world_cidr(rp.get("cidrIp")):
        return True
    for p in _items(rp.get("ipPermissions")):
        if any(_is_world_cidr(r.get("cidrIp")) for r in _items(p.get("ipRanges"))):
            return True
        if any(_is_world_cidr(r.get("cidrIpv6")) for r in _items(p.get("ipv6Ranges"))):
            return True
    return any(_is_world_cidr(r.get("cidrIpv4")) or _is_world_cidr(r.get("cidrIpv6")) for r in _items(resp.get("securityGroupRuleSet")))


def console_login_success(rec: dict, ctx: dict) -> bool:
    return _re(rec).get("ConsoleLogin") == "Success"


def console_login_failure(rec: dict, ctx: dict) -> bool:
    return _re(rec).get("ConsoleLogin") == "Failure"


def no_mfa_login(rec: dict, ctx: dict) -> bool:
    return console_login_success(rec, ctx) and (rec.get("additionalEventData") if isinstance(rec.get("additionalEventData"), dict) else {}).get("MFAUsed") == "No"


def is_error(rec: dict, ctx: dict) -> bool:
    return bool(rec.get("errorCode")) and rec["errorCode"] in ("AccessDenied", "Client.UnauthorizedOperation", "UnauthorizedOperation")


def detector_disabled(rec: dict, ctx: dict) -> bool:
    if rec["eventName"] == "DeleteDetector":
        return True
    return rec["eventName"] == "UpdateDetector" and _rp(rec).get("enable") is False


def image_shared_external(rec: dict, ctx: dict) -> bool:
    """ModifyImageAttribute adding a launch permission for another account or for everyone (group=all)."""
    lp = _d(_rp(rec).get("launchPermission"))
    return any(it.get("group") == "all" or (it.get("userId") and it["userId"] != ctx["account_id"]) for it in _items(lp.get("add")))


def rds_snapshot_shared_external(rec: dict, ctx: dict) -> bool:
    """ModifyDBSnapshotAttribute / ModifyDBClusterSnapshotAttribute adding restore permission for another account or 'all'."""
    rp = _rp(rec)
    if rp.get("attributeName") != "restore":
        return False
    vals = rp.get("valuesToAdd")
    return any(v == "all" or (isinstance(v, str) and v != ctx["account_id"]) for v in (vals if isinstance(vals, list) else []))


def public_lambda_permission(rec: dict, ctx: dict) -> bool:
    """Lambda AddPermission granting invoke to Principal '*' (anyone)."""
    rp = _rp(rec)
    return rp.get("principal") == "*" and "Condition" not in json.dumps(rp) and not rp.get("sourceArn") and not rp.get("principalOrgID")


def bulk_parameter_read(rec: dict, ctx: dict) -> bool:
    """GetParameters naming ten or more parameters in one call (SecureString harvesting)."""
    names = _rp(rec).get("names")
    return isinstance(names, list) and len(names) >= 10


def user_data_attribute(rec: dict, ctx: dict) -> bool:
    rp = _rp(rec)
    return rp.get("attribute") == "userData" or "userData" in rp


def not_by_this_account_service(rec: dict, ctx: dict) -> bool:
    ui = rec.get("userIdentity") if isinstance(rec.get("userIdentity"), dict) else {}
    return ui.get("type") not in ("AWSService",)


CHECKS: dict[str, Callable[[dict, dict], bool]] = {
    "image_shared_external": image_shared_external, "rds_snapshot_shared_external": rds_snapshot_shared_external,
    "public_lambda_permission": public_lambda_permission, "bulk_parameter_read": bulk_parameter_read,
    "user_data_attribute": user_data_attribute, "not_aws_service": not_by_this_account_service,
    "public_bucket_policy": public_bucket_policy, "public_acl": public_acl, "admin_policy_document": admin_policy_document,
    "external_trust_policy": external_trust_policy, "snapshot_shared_external": snapshot_shared_external, "big_instance": big_instance,
    "non_home_region": non_home_region, "key_for_other_user": key_for_other_user, "open_to_world": open_to_world,
    "console_login_failure": console_login_failure, "console_login_success": console_login_success, "no_mfa_login": no_mfa_login,
    "is_error": is_error, "detector_disabled": detector_disabled,
}
