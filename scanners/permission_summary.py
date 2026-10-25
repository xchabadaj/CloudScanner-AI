from __future__ import annotations

import fnmatch
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

from core.menu import MenuItem
from core.output import print_header, print_json

def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]


def collect_statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def _action_matches(action: str, pattern: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def extract_allow_actions_and_resources(policies: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str]]:
    actions: Set[str] = set()
    resources: Set[str] = set()

    for pol in policies:
        doc = pol.get("document")
        if not isinstance(doc, dict):
            continue

        for stmt in collect_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue

            for a in ensure_list(stmt.get("Action")):
                if isinstance(a, str):
                    actions.add(a)

            for r in ensure_list(stmt.get("Resource")):
                if isinstance(r, str):
                    resources.add(r)

    return actions, resources


def extract_interesting_actions(actions: Set[str]) -> Dict[str, List[str]]:
    interesting_patterns = {
        "iam_passrole": ["iam:PassRole"],
        "sts_assumerole": ["sts:AssumeRole", "sts:AssumeRoleWith*"],
        "secrets_read": ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"],
        "kms_decrypt": ["kms:Decrypt"],
        "lambda_invoke": ["lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"],
        "s3_read": ["s3:GetObject", "s3:GetObjectVersion", "s3:*"],
        "ec2_describe": ["ec2:Describe*"],
    }
    out: Dict[str, List[str]] = {}
    for key, patterns in interesting_patterns.items():
        matched = [a for a in sorted(actions) if any(_action_matches(a, p) for p in patterns)]
        out[key] = matched[:20]
    return out


def classify_action(action: str) -> str:
    a = action.lower()

    if a == "*" or a == "*:*":
        return "admin/wildcard"

    if ":" in a:
        svc, verb = a.split(":", 1)
    else:
        svc, verb = "unknown", a

    if verb == "*":
        return "admin/service-wildcard"

    if action.startswith("iam:") and ("passrole" in verb or "attach" in verb or "put" in verb or verb == "*"):
        return "permissions/iam"
    if action.startswith("sts:") and ("assumerole" in verb or "assumerolewith" in verb):
        return "permissions/sts"
    if action.startswith("organizations:"):
        return "permissions/org"

    if verb.startswith("list") or verb.startswith("describe"):
        return "list/describe"
    if verb.startswith("get") or verb.startswith("read"):
        return "read/get"
    if (
        verb.startswith("put")
        or verb.startswith("create")
        or verb.startswith("update")
        or verb.startswith("delete")
        or verb.startswith("start")
        or verb.startswith("stop")
        or verb.startswith("modify")
        or verb.startswith("tag")
        or verb.startswith("untag")
        or verb.startswith("attach")
        or verb.startswith("detach")
    ):
        return "write/modify"

    return "other"


def service_from_action(action: str) -> str:
    if ":" in action:
        return action.split(":", 1)[0].lower()
    if action in ("*", "*:*"):
        return "*"
    return "unknown"


def build_summary(actions: Set[str], resources: Set[str], policy_sources: Dict[str, int]) -> Dict[str, Any]:
    by_service = defaultdict(lambda: defaultdict(list))

    for act in sorted(actions):
        svc = service_from_action(act)
        cap = classify_action(act)
        by_service[svc][cap].append(act)

    interesting_actions = extract_interesting_actions(actions)

    risk = {
        "has_action_wildcard": any(a in ("*", "*:*") for a in actions),
        "has_service_wildcard": any((":" in a and a.split(":", 1)[1] == "*") for a in actions),
        "has_resource_wildcard": ("*" in resources),
        "has_iam_passrole": bool(interesting_actions["iam_passrole"]),
        "has_sts_assumerole": bool(interesting_actions["sts_assumerole"]),
        "has_secrets_read": bool(interesting_actions["secrets_read"]),
        "has_kms_decrypt": bool(interesting_actions["kms_decrypt"]),
        "has_lambda_invoke": bool(interesting_actions["lambda_invoke"]),
    }

    services_out: Dict[str, Any] = {}
    for svc, caps in by_service.items():
        services_out[svc] = {}
        for cap, acts in caps.items():
            services_out[svc][cap] = {
                "count": len(acts),
                "samples": acts[:10],
            }

    resources_list = sorted(resources)
    return {
        "services": services_out,
        "risk": risk,
        "policy_sources": policy_sources,
        "interesting_actions": interesting_actions,
        "resources_seen_count": len(resources_list),
        "resources_samples": resources_list[:20],
    }



def run(ctx) -> Dict[str, Any]:
    print_header("Permission Summary (policy-only)")

    base = ctx.last_result
    if not isinstance(base, dict):
        return {"ok": False, "error": "Najprv spusti modul 1 (IAM user policies). ctx.last_result je prázdny."}

    attached = base.get("attached_policies", [])
    inline = base.get("inline_policies", [])
    group_policies = base.get("group_policies", [])
    if not isinstance(attached, list) or not isinstance(inline, list) or not isinstance(group_policies, list):
        return {
            "ok": False,
            "error": "ctx.last_result nemá attached_policies/inline_policies/group_policies v očakávanom formáte.",
        }

    all_policies = attached + inline + group_policies
    actions, resources = extract_allow_actions_and_resources(all_policies)

    summary = build_summary(
        actions,
        resources,
        policy_sources={
            "attached_policies": len(attached),
            "inline_policies": len(inline),
            "group_policies": len(group_policies),
            "policies_total": len(all_policies),
        },
    )

    print_header("Summary (high level)")
    print_json(
        {
            "target_user_name": base.get("target_user_name"),
            "services_count": len(summary["services"]),
            "resources_seen_count": summary["resources_seen_count"],
            "policy_sources": summary["policy_sources"],
            "risk": summary["risk"],
            "interesting_actions": summary.get("interesting_actions", {}),
            "resources_samples": summary.get("resources_samples", []),
        }
    )

    return {"ok": True, "target_user_name": base.get("target_user_name"), "permission_summary": summary}



def handler(ctx):
    res = run(ctx)

    if isinstance(ctx.last_result, dict):
        ctx.last_result["permission_summary"] = res.get("permission_summary")
        ctx.last_result["permission_summary_ok"] = res.get("ok", True)
        if res.get("error"):
            ctx.last_result["permission_summary_error"] = res.get("error")
    else:
        ctx.last_result = res


menu_item = MenuItem(
    key="3",
    title="Permission summary (from policies only)",
    handler=handler,
    help="Analyzuje policy JSONy a spraví auditný prehľad služieb a typov práv (bez AWS volaní).",
)
