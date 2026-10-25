from __future__ import annotations

import fnmatch
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from core.menu import MenuItem
from core.output import print_header, print_json


ROLE_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):role\/(?:.+\/)?([^\/]+)$")


def _store_into_last_result(ctx, key: str, value: Dict[str, Any]) -> None:
    if isinstance(getattr(ctx, "last_result", None), dict):
        ctx.last_result[key] = value
    else:
        ctx.last_result = {key: value}


def _ensure_list(x: Any) -> List[Any]:
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def _collect_statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def _caller_policy_documents(last: Dict[str, Any]) -> List[Dict[str, Any]]:
    attached = last.get("attached_policies", [])
    inline = last.get("inline_policies", [])
    group_policies = last.get("group_policies", [])
    all_policies: List[Dict[str, Any]] = []
    if isinstance(attached, list):
        all_policies.extend([p for p in attached if isinstance(p, dict)])
    if isinstance(inline, list):
        all_policies.extend([p for p in inline if isinstance(p, dict)])
    if isinstance(group_policies, list):
        all_policies.extend([p for p in group_policies if isinstance(p, dict)])
    return all_policies


def _parse_role_arn(role_arn: str) -> Tuple[Optional[str], Optional[str]]:
    m = ROLE_ARN_RE.match(role_arn or "")
    if not m:
        return None, None
    return m.group(1), m.group(2)


def _collect_role_arns_from_resources_block(last: Dict[str, Any]) -> Set[str]:
    role_arns: Set[str] = set()

    resources = last.get("resources")
    if not isinstance(resources, dict):
        return role_arns

    iam_block = resources.get("iam")
    if not isinstance(iam_block, dict):
        return role_arns

    roles = iam_block.get("roles")
    if not isinstance(roles, list):
        return role_arns

    for item in roles:
        if isinstance(item, dict):
            arn = item.get("arn") or item.get("role_arn")
            if isinstance(arn, str) and arn.startswith("arn:aws:iam::") and ":role/" in arn:
                role_arns.add(arn)
        elif isinstance(item, str) and item.startswith("arn:aws:iam::") and ":role/" in item:
            role_arns.add(item)

    return role_arns

def _is_service_linked_role_name(role_name: Optional[str]) -> bool:
    return isinstance(role_name, str) and role_name.startswith("AWSServiceRoleFor")


def _collect_role_arns_from_resource_targets(last: Dict[str, Any], account_id: str) -> Set[str]:
    role_arns: Set[str] = set()

    targets = last.get("resource_targets", [])
    if not isinstance(targets, list):
        return role_arns

    for t in targets:
        if not isinstance(t, str):
            continue

        if t.startswith("arn:aws:iam::") and ":role/" in t:
            role_arns.add(t)
            continue

        if t.startswith("iam:role/") and account_id:
            role_name = t.split("iam:role/", 1)[1].strip()
            if role_name:
                role_arns.add(f"arn:aws:iam::{account_id}:role/{role_name}")

    return role_arns


def _action_matches(pattern: str, action: str) -> bool:
    p = (pattern or "").strip()
    a = (action or "").strip()

    if not p or not a:
        return False

    p_low = p.lower()
    a_low = a.lower()

    if p_low in {"*", "*:*"}:
        return True

    return fnmatch.fnmatchcase(a_low, p_low)


def _resource_matches(pattern: str, resource_arn: str) -> bool:
    p = (pattern or "").strip()
    r = (resource_arn or "").strip()

    if not p or not r:
        return False

    if p == "*":
        return True

    return fnmatch.fnmatchcase(r, p)


def _statement_allows_action_on_resource(stmt: Dict[str, Any], action: str, resource_arn: str) -> bool:
    if stmt.get("Effect") != "Allow":
        return False

    actions = [x for x in _ensure_list(stmt.get("Action")) if isinstance(x, str)]
    resources = [x for x in _ensure_list(stmt.get("Resource")) if isinstance(x, str)]

    if not actions:
        return False

    if not any(_action_matches(a, action) for a in actions):
        return False

    if not resources:
        return False

    return any(_resource_matches(r, resource_arn) for r in resources)


def _statement_denies_action_on_resource(stmt: Dict[str, Any], action: str, resource_arn: str) -> bool:
    if stmt.get("Effect") != "Deny":
        return False

    actions = [x for x in _ensure_list(stmt.get("Action")) if isinstance(x, str)]
    resources = [x for x in _ensure_list(stmt.get("Resource")) if isinstance(x, str)]

    if not actions:
        return False

    if not any(_action_matches(a, action) for a in actions):
        return False

    if not resources:
        return False

    return any(_resource_matches(r, resource_arn) for r in resources)


def _collect_role_arns_from_caller_policies(last: Dict[str, Any]) -> Set[str]:
    role_arns: Set[str] = set()

    all_policies = _caller_policy_documents(last)

    for pol in all_policies:
        if not isinstance(pol, dict):
            continue
        doc = pol.get("document")
        if not isinstance(doc, dict):
            continue

        for stmt in _collect_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue

            actions = [x for x in _ensure_list(stmt.get("Action")) if isinstance(x, str)]
            if not any(_action_matches(a, "sts:AssumeRole") for a in actions):
                continue

            for r in _ensure_list(stmt.get("Resource")):
                if isinstance(r, str) and r.startswith("arn:aws:iam::") and ":role/" in r:
                    role_arns.add(r)

    return role_arns


def _try_list_roles(iam) -> Set[str]:
    arns: Set[str] = set()
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page.get("Roles", []):
            arn = r.get("Arn")
            if isinstance(arn, str) and arn.startswith("arn:aws:iam::") and ":role/" in arn:
                arns.add(arn)
    return arns


def _caller_policy_assume_analysis(last: Dict[str, Any], target_role_arn: str) -> Dict[str, Any]:
    all_policies = _caller_policy_documents(last)

    explicit_deny = False
    explicit_allow = False

    for pol in all_policies:
        if not isinstance(pol, dict):
            continue
        doc = pol.get("document")
        if not isinstance(doc, dict):
            continue

        for stmt in _collect_statements(doc):
            if _statement_denies_action_on_resource(stmt, "sts:AssumeRole", target_role_arn):
                explicit_deny = True
                break
        if explicit_deny:
            break

    for pol in all_policies:
        if not isinstance(pol, dict):
            continue
        doc = pol.get("document")
        if not isinstance(doc, dict):
            continue

        for stmt in _collect_statements(doc):
            if _statement_allows_action_on_resource(stmt, "sts:AssumeRole", target_role_arn):
                explicit_allow = True
                break
        if explicit_allow:
            break

    return {
        "explicit_allow": explicit_allow,
        "explicit_deny": explicit_deny,
    }
    
def _assume_path_confidence(entry: Dict[str, Any]) -> str:
    role_name = entry.get("role_name")
    if _is_service_linked_role_name(role_name):
        return "INFO"

    if entry.get("caller_policy_explicit_deny_assume"):
        return "BLOCKED"

    if entry.get("assumable_by_explicit_allow"):
        return "CONFIRMED"

    if entry.get("assumable_via_same_account_direct_trust"):
        return "HIGH"

    trust = entry.get("trust", {}) or {}
    same_account_role = bool(entry.get("same_account_role"))

    if same_account_role and trust.get("allows_caller_arn"):
        return "HIGH"

    if trust.get("allows_wildcard"):
        return "HIGH"

    if same_account_role and trust.get("allows_account_root"):
        return "MEDIUM"

    if trust.get("allows_external_account"):
        return "MEDIUM"

    return "LOW"


def _extract_principal_values(principal: Any, key: str) -> List[str]:
    if not isinstance(principal, dict):
        return []
    value = principal.get(key)
    values = _ensure_list(value)
    return [v for v in values if isinstance(v, str)]


def _trust_analysis(trust_doc: Any, caller_arn: str, account_id: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "trust_allows_caller": False,
        "allows_wildcard": False,
        "allows_account_root": False,
        "allows_caller_arn": False,
        "allows_external_account": False,
        "aws_principals": [],
        "service_principals": [],
        "federated_principals": [],
    }

    if not isinstance(trust_doc, dict):
        return out

    caller_acct = account_id or ""
    stmts = trust_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    if not isinstance(stmts, list):
        return out

    aws_seen: Set[str] = set()
    svc_seen: Set[str] = set()
    fed_seen: Set[str] = set()

    trust_allows_caller = False
    allows_wildcard = False
    allows_account_root = False
    allows_caller_arn = False
    allows_external_account = False

    for stmt in stmts:
        if not isinstance(stmt, dict):
            continue
        if stmt.get("Effect") != "Allow":
            continue

        actions = [x for x in _ensure_list(stmt.get("Action")) if isinstance(x, str)]
        if not any(_action_matches(a, "sts:AssumeRole") for a in actions):
            continue

        principal = stmt.get("Principal")

        if principal == "*":
            allows_wildcard = True
            trust_allows_caller = True
            continue

        if not isinstance(principal, dict):
            continue

        aws_principals = _extract_principal_values(principal, "AWS")
        service_principals = _extract_principal_values(principal, "Service")
        federated_principals = _extract_principal_values(principal, "Federated")

        for p in aws_principals:
            aws_seen.add(p)

            if p == "*":
                allows_wildcard = True
                trust_allows_caller = True

            if caller_arn and p == caller_arn:
                allows_caller_arn = True
                trust_allows_caller = True

            if caller_acct and p == f"arn:aws:iam::{caller_acct}:root":
                allows_account_root = True
                trust_allows_caller = True

            if p.startswith("arn:aws:iam::") and ":root" in p:
                parts = p.split(":")
                if len(parts) >= 5:
                    principal_acct = parts[4]
                    if caller_acct and principal_acct and principal_acct != caller_acct:
                        allows_external_account = True

        for p in service_principals:
            svc_seen.add(p)

        for p in federated_principals:
            fed_seen.add(p)

    out["trust_allows_caller"] = trust_allows_caller
    out["allows_wildcard"] = allows_wildcard
    out["allows_account_root"] = allows_account_root
    out["allows_caller_arn"] = allows_caller_arn
    out["allows_external_account"] = allows_external_account
    out["aws_principals"] = sorted(aws_seen)
    out["service_principals"] = sorted(svc_seen)
    out["federated_principals"] = sorted(fed_seen)

    return out


def _count_role_policies(iam, role_name: str) -> Dict[str, Any]:
    out = {
        "attached_policy_count": None,
        "inline_policy_count": None,
        "warnings": [],
    }

    try:
        paginator = iam.get_paginator("list_attached_role_policies")
        count = 0
        for page in paginator.paginate(RoleName=role_name):
            count += len(page.get("AttachedPolicies", []))
        out["attached_policy_count"] = count
    except ClientError as e:
        out["warnings"].append(f"list_attached_role_policies failed: {e}")

    try:
        paginator = iam.get_paginator("list_role_policies")
        count = 0
        for page in paginator.paginate(RoleName=role_name):
            count += len(page.get("PolicyNames", []))
        out["inline_policy_count"] = count
    except ClientError as e:
        out["warnings"].append(f"list_role_policies failed: {e}")

    return out


def _risk_level(entry: Dict[str, Any]) -> str:
    posture = entry.get("assume_path_confidence", "LOW")

    if posture in {"CONFIRMED", "HIGH"}:
        return "HIGH"
    if posture == "MEDIUM":
        return "MEDIUM"
    if posture == "INFO":
        return "LOW"
    if posture == "BLOCKED":
        trust = entry.get("trust", {}) or {}
        if trust.get("allows_wildcard") or trust.get("allows_external_account"):
            return "MEDIUM"
        return "LOW"

    trust = entry.get("trust", {}) or {}
    if trust.get("allows_wildcard"):
        return "HIGH"
    if trust.get("allows_external_account") or trust.get("allows_account_root"):
        return "MEDIUM"
    return "LOW"


def role_audit(ctx) -> Dict[str, Any]:
    print_header("IAM Role Audit (trust + assume path)")

    if not ctx.session:
        out = {"ok": False, "error": "No AWS session. Set credentials first."}
        print_json(out)
        _store_into_last_result(ctx, "iam_role_audit", out)
        return out

    sts = ctx.session.client("sts")
    iam = ctx.session.client("iam")

    try:
        ident = sts.get_caller_identity()
    except ClientError as e:
        out = {"ok": False, "error": f"get_caller_identity failed: {e}"}
        print_json(out)
        _store_into_last_result(ctx, "iam_role_audit", out)
        return out

    caller_arn = ident.get("Arn", "")
    account_id = ident.get("Account", "")
    last = ctx.last_result if isinstance(ctx.last_result, dict) else {}

    role_arns: Set[str] = set()
    discovery_sources: List[str] = []

    from_resources_block = _collect_role_arns_from_resources_block(last)
    if from_resources_block:
        role_arns |= from_resources_block
        discovery_sources.append("resources.iam.roles")

    from_targets = _collect_role_arns_from_resource_targets(last, account_id)
    if from_targets:
        role_arns |= from_targets
        discovery_sources.append("resource_targets")

    from_caller_policies = _collect_role_arns_from_caller_policies(last)
    if from_caller_policies:
        role_arns |= from_caller_policies
        discovery_sources.append("caller_policies")

    warnings: List[str] = []

    if not role_arns:
        try:
            listed = _try_list_roles(iam)
            if listed:
                role_arns |= listed
                discovery_sources.append("list_roles")
        except ClientError as e:
            warnings.append(f"list_roles failed: {e}")

    if not role_arns:
        out = {
            "ok": True,
            "caller_arn": caller_arn,
            "account_id": account_id,
            "roles_count": 0,
            "assumable_roles_count": 0,
            "public_trust_count": 0,
            "cross_account_trust_count": 0,
            "roles": [],
            "warnings": warnings or [
                "No roles discovered. Run more modules, include role resources, or require iam:ListRoles."
            ],
            "notes": [
                "Best-effort audit. Trust policy Conditions are not evaluated."
            ],
        }
        print_json(out)
        _store_into_last_result(ctx, "iam_role_audit", out)
        return out

    roles_out: List[Dict[str, Any]] = []

    for role_arn in sorted(role_arns):
        role_account, role_name = _parse_role_arn(role_arn)

        entry: Dict[str, Any] = {
            "role_arn": role_arn,
            "role_name": role_name,
            "role_account_id": role_account,
            "trust": {},
            "caller_policy_allows_assume": False,
            "caller_policy_explicit_deny_assume": False,
            "assumable_by_explicit_allow": False,
            "assumable_via_same_account_direct_trust": False,
            "assumable_by_caller": False,
        }

        if not role_name:
            entry["error"] = "Could not parse role name from ARN"
            entry["risk_level"] = "UNKNOWN"
            roles_out.append(entry)
            continue

        assume_eval = _caller_policy_assume_analysis(last, role_arn)
        entry["caller_policy_allows_assume"] = assume_eval["explicit_allow"]
        entry["caller_policy_explicit_deny_assume"] = assume_eval["explicit_deny"]

        try:
            resp = iam.get_role(RoleName=role_name)
            role = resp.get("Role", {})

            trust_doc = role.get("AssumeRolePolicyDocument")
            trust = _trust_analysis(trust_doc, caller_arn, account_id)
            
            entry["same_account_role"] = bool(role_account == account_id)
            entry["path"] = role.get("Path")
            entry["role_id"] = role.get("RoleId")
            entry["max_session_duration"] = role.get("MaxSessionDuration")
            entry["create_date"] = (
                role.get("CreateDate").isoformat() if role.get("CreateDate") else None
            )
            entry["description"] = role.get("Description")
            entry["trust"] = trust

            entry["assumable_by_explicit_allow"] = bool(
                not entry.get("caller_policy_explicit_deny_assume")
                and entry.get("caller_policy_allows_assume")
                and trust.get("trust_allows_caller")
            )

            entry["assumable_via_same_account_direct_trust"] = bool(
                not entry.get("caller_policy_explicit_deny_assume")
                and entry.get("same_account_role")
                and trust.get("allows_caller_arn")
            )

            entry["assumable_by_caller"] = bool(
                entry.get("assumable_by_explicit_allow")
                or entry.get("assumable_via_same_account_direct_trust")
            )

            entry["likely_assumable_same_account"] = bool(
                not entry.get("caller_policy_explicit_deny_assume")
                and entry.get("same_account_role")
                and (trust.get("allows_caller_arn") or trust.get("allows_account_root"))
            )

            entry["assume_path_confidence"] = _assume_path_confidence(entry)

            pol_counts = _count_role_policies(iam, role_name)
            entry["attached_policy_count"] = pol_counts["attached_policy_count"]
            entry["inline_policy_count"] = pol_counts["inline_policy_count"]
            if pol_counts["warnings"]:
                entry["warnings"] = pol_counts["warnings"]

        except ClientError as e:
            entry["error"] = f"get_role failed: {e}"

        entry["risk_level"] = _risk_level(entry)
        roles_out.append(entry)

    assumable_roles_count = sum(1 for r in roles_out if r.get("assumable_by_caller"))
    public_trust_count = sum(1 for r in roles_out if r.get("trust", {}).get("allows_wildcard"))
    cross_account_trust_count = sum(1 for r in roles_out if r.get("trust", {}).get("allows_external_account"))

    out = {
        "ok": True,
        "caller_arn": caller_arn,
        "account_id": account_id,
        "discovery_sources": discovery_sources,
        "roles_count": len(roles_out),
        "assumable_roles_count": assumable_roles_count,
        "public_trust_count": public_trust_count,
        "cross_account_trust_count": cross_account_trust_count,
        "roles": roles_out,
        "notes": [
            "Best-effort audit. Trust policy Conditions are not evaluated.",
            "assumable_by_explicit_allow requires both caller-side Allow and trust-side allow.",
            "assumable_via_same_account_direct_trust captures same-account direct trust of the caller ARN when no explicit caller-side deny is present.",
            "assumable_by_caller is the practical static conclusion and may be true via either explicit two-sided allow or same-account direct trust.",
            "Caller-side evaluation includes user-attached, user-inline, and group-derived policies when available."
        ],
    }
    if warnings:
        out["warnings"] = warnings

    print_header("ROLES (summary)")
    printable = []
    for r in roles_out:
        trust = r.get("trust", {}) or {}
        printable.append({
            "role_name": r.get("role_name"),
            "assumable": "YES" if r.get("assumable_by_caller") else "NO",
            "likely_same_account": "YES" if r.get("likely_assumable_same_account") else "NO",
            "caller_policy": "YES" if r.get("caller_policy_allows_assume") else "NO",
            "caller_deny": "YES" if r.get("caller_policy_explicit_deny_assume") else "NO",
            "trust_allows_caller": "YES" if trust.get("trust_allows_caller") else "NO",
            "public_trust": "YES" if trust.get("allows_wildcard") else "NO",
            "external_trust": "YES" if trust.get("allows_external_account") else "NO",
            "posture": r.get("assume_path_confidence"),
            "risk": r.get("risk_level"),
        })

    print_json({
        "count": len(printable),
        "assumable_roles_count": assumable_roles_count,
        "public_trust_count": public_trust_count,
        "cross_account_trust_count": cross_account_trust_count,
        "items": printable[:50],
    })

    _store_into_last_result(ctx, "iam_role_audit", out)
    return out


def handler(ctx) -> None:
    role_audit(ctx)


menu_item = MenuItem(
    key="4",
    title="IAM role audit (trust + assume path)",
    handler=handler,
    help="Audit rolí: trust policy, assume-role path, public/cross-account trust a best-effort risk.",
)
