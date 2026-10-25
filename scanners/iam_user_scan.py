from __future__ import annotations
import json
from urllib.parse import unquote
from typing import Any, Dict, List, Optional, Set, Tuple
from botocore.exceptions import ClientError, NoCredentialsError
from core.menu import MenuItem
from core.output import print_header, print_json


def ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def normalize_policy_document(doc: Any) -> Optional[Dict[str, Any]]:
    if isinstance(doc, dict):
        return doc

    if isinstance(doc, str) and doc.strip():
        for candidate in (doc, unquote(doc)):
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

    return None


def collect_statements(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    stmts = doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def get_iam_username_from_arn(arn: str) -> Optional[str]:
    if not isinstance(arn, str):
        return None
    if ":user/" not in arn:
        return None
    return arn.split("/")[-1]


def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return None
    return {
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account": parts[4],
        "resource": parts[5],
    }


def extract_actions_resources_from_policy_doc(doc: Dict[str, Any]) -> Tuple[Set[str], Set[str]]:
    actions: Set[str] = set()
    resources: Set[str] = set()

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


def humanize_resource(resource_arn: str) -> str:
    if resource_arn == "*":
        return "*"

    p = parse_arn(resource_arn)
    if not p:
        return resource_arn

    svc = p["service"]
    res = p["resource"]

    if svc == "s3":
        rr = res.lstrip(":")
        return f"s3://{rr}"
    if svc == "iam":
        return f"iam:{res}"
    if svc == "secretsmanager":
        return f"secrets:{res}"
    if svc == "ec2":
        return f"ec2:{res}"
    if svc == "lambda":
        return f"lambda:{res}"

    return f"{svc}:{res}"


def run(ctx) -> Dict[str, Any]:
    print_header("IAM User Quick Scan (audit)")

    if ctx.session is None:
        return {"ok": False, "error": "ctx.session is None"}

    sts = ctx.session.client("sts")
    iam = ctx.session.client("iam")

    try:
        identity = sts.get_caller_identity()
    except (NoCredentialsError, ClientError) as e:
        return {"ok": False, "error": f"get_caller_identity failed: {e}"}

    
    user_name = get_iam_username_from_arn(identity.get("Arn", ""))

    if not user_name:
        return {
            "ok": False,
            "caller_identity": identity,
            "error": "Neviem určiť IAM user name z ARN (možno assumed-role/root). Tento scan funguje len pre IAM user context.",
            }


    attached_policies: List[Dict[str, Any]] = []
    inline_policies: List[Dict[str, Any]] = []

    actions_all: Set[str] = set()
    resources_all: Set[str] = set()
    errors: List[str] = []

    try:
        resp = iam.list_attached_user_policies(UserName=user_name)
        for ap in resp.get("AttachedPolicies", []):
            pol_arn = ap.get("PolicyArn")
            pol_entry = {
                "policy_name": ap.get("PolicyName"),
                "policy_arn": pol_arn,
                "default_version_id": None,
                "document": None,
                "all_versions": [],
            }

            if pol_arn:
                try:
                    pol = iam.get_policy(PolicyArn=pol_arn)
                    ver_id = pol["Policy"]["DefaultVersionId"]
                    pol_entry["default_version_id"] = ver_id

                    ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=ver_id)
                    raw_doc = ver["PolicyVersion"].get("Document")
                    doc = normalize_policy_document(raw_doc)
                    pol_entry["document"] = doc  

                    if doc:
                        a, r = extract_actions_resources_from_policy_doc(doc)
                        actions_all |= a
                        resources_all |= r
                    else:
                        errors.append(f"policy document not parsed (attached): {pol_arn}")

                    if pol_arn.startswith("arn:aws:iam::") and ":policy/" in pol_arn:
                        try:
                            versions_resp = iam.list_policy_versions(PolicyArn=pol_arn)
                            for v in versions_resp.get("Versions", []):
                                version_id = v.get("VersionId")
                                is_default = v.get("IsDefaultVersion", False)
                                if not version_id:
                                    continue
                                
                                version_entry = {
                                    "version_id": version_id,
                                    "is_default": is_default,
                                    "create_date": v.get("CreateDate").isoformat() if v.get("CreateDate") else None,
                                    "document": None,
                                }
                                
                                if is_default and doc:
                                    version_entry["document"] = doc
                                else:
                                    try:
                                        ver_data = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version_id)
                                        version_entry["document"] = normalize_policy_document(ver_data["PolicyVersion"].get("Document"))
                                    except ClientError as e:
                                        version_entry["error"] = f"get_policy_version failed: {e}"
                                
                                pol_entry["all_versions"].append(version_entry)
                        except ClientError as e:
                            errors.append(f"list_policy_versions failed ({pol_arn}): {e}")

                except ClientError as e:
                    errors.append(f"attached policy doc read failed ({pol_arn}): {e}")

            attached_policies.append(pol_entry)
    except ClientError as e:
        errors.append(f"list_attached_user_policies failed: {e}")

    try:
        resp = iam.list_user_policies(UserName=user_name)
        for pname in resp.get("PolicyNames", []):
            pol_entry = {"policy_name": pname, "document": None}
            try:
                pol = iam.get_user_policy(UserName=user_name, PolicyName=pname)
                raw_doc = pol.get("PolicyDocument")
                doc = normalize_policy_document(raw_doc)
                pol_entry["document"] = doc
                
                if doc:
                    a, r = extract_actions_resources_from_policy_doc(doc)
                    actions_all |= a
                    resources_all |= r
                else:
                    errors.append(f"policy document not parsed (inline): {pname}")

            except ClientError as e:
                errors.append(f"inline policy doc read failed ({pname}): {e}")

            inline_policies.append(pol_entry)
    except ClientError as e:
        errors.append(f"list_user_policies failed: {e}")
    
    visible_users = None
    try:
       users = []
       paginator = iam.get_paginator("list_users")
       for page in paginator.paginate():
           for u in page.get("Users", []):
               users.append(u.get("UserName"))
       visible_users = {"count": len(users), "items": sorted([u for u in users if u])}
    except ClientError as e:
       visible_users = {"error": "Not permitted (iam:ListUsers missing)", "detail": str(e)}

    
        
    groups_info = None
    try:
        resp = iam.list_groups_for_user(UserName=user_name)
        groups = [g["GroupName"] for g in resp.get("Groups", [])]
        groups_info = {"count": len(groups), "items": groups}
    except ClientError as e:
        groups_info = {"error": str(e)}

    group_policies: List[Dict[str, Any]] = []
    group_attached_names: List[str] = []
    group_inline_names: List[str] = []
    group_names = groups_info.get("items", []) if isinstance(groups_info, dict) else []
    if not isinstance(group_names, list):
        group_names = []

    for group_name in [g for g in group_names if isinstance(g, str)]:
        try:
            resp = iam.list_attached_group_policies(GroupName=group_name)
            for ap in resp.get("AttachedPolicies", []):
                pol_arn = ap.get("PolicyArn")
                pol_entry = {
                    "group_name": group_name,
                    "policy_scope": "group_attached",
                    "policy_name": ap.get("PolicyName"),
                    "policy_arn": pol_arn,
                    "default_version_id": None,
                    "document": None,
                }

                if pol_arn:
                    try:
                        pol = iam.get_policy(PolicyArn=pol_arn)
                        ver_id = pol["Policy"]["DefaultVersionId"]
                        pol_entry["default_version_id"] = ver_id

                        ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=ver_id)
                        raw_doc = ver["PolicyVersion"].get("Document")
                        doc = normalize_policy_document(raw_doc)
                        pol_entry["document"] = doc

                        if doc:
                            a, r = extract_actions_resources_from_policy_doc(doc)
                            actions_all |= a
                            resources_all |= r
                        else:
                            errors.append(f"policy document not parsed (group attached): {group_name}:{pol_arn}")
                    except ClientError as e:
                        errors.append(f"group attached policy doc read failed ({group_name}:{pol_arn}): {e}")

                group_policies.append(pol_entry)
                if pol_entry.get("policy_name"):
                    group_attached_names.append(pol_entry["policy_name"])
        except ClientError as e:
            errors.append(f"list_attached_group_policies failed ({group_name}): {e}")

        try:
            resp = iam.list_group_policies(GroupName=group_name)
            for pname in resp.get("PolicyNames", []):
                pol_entry = {
                    "group_name": group_name,
                    "policy_scope": "group_inline",
                    "policy_name": pname,
                    "document": None,
                }
                try:
                    pol = iam.get_group_policy(GroupName=group_name, PolicyName=pname)
                    raw_doc = pol.get("PolicyDocument")
                    doc = normalize_policy_document(raw_doc)
                    pol_entry["document"] = doc

                    if doc:
                        a, r = extract_actions_resources_from_policy_doc(doc)
                        actions_all |= a
                        resources_all |= r
                    else:
                        errors.append(f"policy document not parsed (group inline): {group_name}:{pname}")
                except ClientError as e:
                    errors.append(f"group inline policy doc read failed ({group_name}:{pname}): {e}")

                group_policies.append(pol_entry)
                if pname:
                    group_inline_names.append(pname)
        except ClientError as e:
            errors.append(f"list_group_policies failed ({group_name}): {e}")


    attached_names = sorted([p.get("policy_name") for p in attached_policies if p.get("policy_name")])
    inline_names = sorted([p.get("policy_name") for p in inline_policies if p.get("policy_name")])
    resources_h = sorted({humanize_resource(x) for x in resources_all})

    result: Dict[str, Any] = {
        "ok": True,
        "caller_identity": identity,
        "target_user_name": user_name,

        "attached_policies": attached_policies,
        "inline_policies": inline_policies,

        "counts": {
            "attached_policies": len(attached_policies),
            "inline_policies": len(inline_policies),
            "group_policies": len(group_policies),
            "unique_allow_actions": len(actions_all),
            "unique_allow_resources": len(resources_all),
        },
        "policy_names": {
            "attached": attached_names,
            "inline": inline_names,
            "group_attached": sorted([x for x in group_attached_names if x]),
            "group_inline": sorted([x for x in group_inline_names if x]),
        },
        "group_policies": group_policies,
        "resource_targets": resources_h,
        "groups": groups_info,
        "visible_users": visible_users,
    }

    if errors:
        result["errors"] = errors

    print_header("CALLER")
    print_json({"Account": identity.get("Account"), "Arn": identity.get("Arn")})

    print_header("POLICIES (names only)")
    print_json(result["counts"])
    print_json(result["policy_names"])

    print_header("RESOURCES (from Allow statements)")
    print_json({"resources_total": len(resources_h), "items": resources_h[:50]})
    
    print_header("GROUPS")
    print_json(groups_info)
    
    print_header("VISIBLE USERS (if permitted)")
    print_json(visible_users)
    


    if errors:
        print_header("ERRORS / WARNINGS")
        print_json({"count": len(errors), "items": errors})

    return result


def handler(ctx):
    ctx.last_result = run(ctx)


menu_item = MenuItem(
    key="1",
    title="IAM user quick scan (names + resource targets)",
    handler=handler,
    help="Rýchly audit: caller, počty/názvy policies, a resource targets z Allow statementov (docs sa neprintujú).",
)
