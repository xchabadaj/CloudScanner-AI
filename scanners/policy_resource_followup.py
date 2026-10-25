from __future__ import annotations

import fnmatch
import json
from urllib.parse import unquote
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from core.menu import MenuItem
from core.output import print_header, print_json



def ensure_list(x: Any) -> List[Any]:
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


def parse_arn(arn: str) -> Optional[Dict[str, str]]:
    if not isinstance(arn, str):
        return None
    if not arn.startswith("arn:"):
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

def extract_api_role_name_from_arn(role_arn: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    parsed = parse_arn(role_arn)
    if not parsed:
        return None, None, None

    resource = parsed["resource"]
    if not resource.startswith("role/"):
        return parsed["account"], None, None

    suffix = resource[len("role/"):].strip("/")
    if not suffix:
        return parsed["account"], None, None

    parts = suffix.split("/")
    role_name = parts[-1]             
    full_suffix = suffix               

    return parsed["account"], role_name, full_suffix


def action_matches(pattern: str, action: str) -> bool:
    p = (pattern or "").strip().lower()
    a = (action or "").strip().lower()

    if not p or not a:
        return False
    if p in {"*", "*:*"}:
        return True
    return fnmatch.fnmatchcase(a, p)


def resource_matches(pattern: str, resource: str) -> bool:
    p = (pattern or "").strip()
    r = (resource or "").strip()

    if not p or not r:
        return False
    if p == "*":
        return True
    return fnmatch.fnmatchcase(r, p)


def safe_iso(value: Any) -> Optional[str]:
    try:
        return value.isoformat() if value else None
    except Exception:
        return str(value) if value is not None else None


def flatten_policy_sources(
    attached: List[Dict[str, Any]],
    inline: List[Dict[str, Any]],
    group_policies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    all_policies: List[Dict[str, Any]] = []
    for p in attached:
        if isinstance(p, dict):
            cp = dict(p)
            cp.setdefault("source", "user_attached")
            all_policies.append(cp)
    for p in inline:
        if isinstance(p, dict):
            cp = dict(p)
            cp.setdefault("source", "user_inline")
            all_policies.append(cp)
    for p in group_policies:
        if isinstance(p, dict):
            all_policies.append(dict(p))
    return all_policies


def statement_matches(stmt: Dict[str, Any], action: str, resource: str) -> bool:
    actions = [x for x in ensure_list(stmt.get("Action")) if isinstance(x, str)]
    resources = [x for x in ensure_list(stmt.get("Resource")) if isinstance(x, str)]

    if not actions:
        return False
    if not any(action_matches(a, action) for a in actions):
        return False

    if not resources:
        return False
    return any(resource_matches(r, resource) for r in resources)


def policy_allows(policies: List[Dict[str, Any]], action: str, resource: str) -> bool:
    for pol in policies:
        doc = normalize_policy_document(pol.get("document"))
        if not doc:
            continue
        for stmt in collect_statements(doc):
            if stmt.get("Effect") != "Deny":
                continue
            if statement_matches(stmt, action, resource):
                return False

    for pol in policies:
        doc = normalize_policy_document(pol.get("document"))
        if not doc:
            continue
        for stmt in collect_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue
            if statement_matches(stmt, action, resource):
                return True

    return False


def extract_resources_and_actions_from_policies(policies: List[Dict[str, Any]]) -> Tuple[Set[str], Set[str]]:
    resource_arns: Set[str] = set()
    actions: Set[str] = set()

    for pol in policies:
        doc = normalize_policy_document(pol.get("document"))
        if not doc:
            continue

        for stmt in collect_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue

            for a in ensure_list(stmt.get("Action")):
                if isinstance(a, str):
                    actions.add(a)

            for r in ensure_list(stmt.get("Resource")):
                if isinstance(r, str):
                    resource_arns.add(r)

    return resource_arns, actions


def summarize_policy_documents(policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    services: Dict[str, Dict[str, Any]] = {}
    resource_arns: Set[str] = set()
    action_count = 0

    for pol in policies:
        doc = normalize_policy_document(pol.get("document"))
        if not doc:
            continue

        for stmt in collect_statements(doc):
            if stmt.get("Effect") != "Allow":
                continue

            for a in ensure_list(stmt.get("Action")):
                if not isinstance(a, str):
                    continue
                action_count += 1
                svc = a.split(":", 1)[0].lower() if ":" in a else "unknown"
                block = services.setdefault(svc, {"count": 0, "samples": []})
                block["count"] += 1
                if len(block["samples"]) < 8 and a not in block["samples"]:
                    block["samples"].append(a)

            for r in ensure_list(stmt.get("Resource")):
                if isinstance(r, str):
                    resource_arns.add(r)

    interesting_services = []
    for svc in ("iam", "sts", "s3", "secretsmanager", "ec2", "kms", "lambda", "ssm"):
        if svc in services:
            interesting_services.append(svc)

    return {
        "services": services,
        "service_count": len(services),
        "action_count": action_count,
        "resource_count": len(resource_arns),
        "resource_samples": sorted(resource_arns)[:20],
        "interesting_services": interesting_services,
    }



def collect_group_policies(iam, user_name: str, groups_info: Any) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "groups": [],
        "group_attached_policies": [],
        "group_inline_policies": [],
        "errors": [],
    }

    group_names: List[str] = []

    if isinstance(groups_info, dict) and isinstance(groups_info.get("items"), list):
        group_names = [g for g in groups_info["items"] if isinstance(g, str)]
    else:
        if user_name:
            try:
                resp = iam.list_groups_for_user(UserName=user_name)
                group_names = [g.get("GroupName") for g in resp.get("Groups", []) if g.get("GroupName")]
            except ClientError as e:
                report["errors"].append(f"list_groups_for_user failed: {e}")

    report["groups"] = group_names
    policies_out: List[Dict[str, Any]] = []

    for gname in group_names:
        try:
            lap = iam.list_attached_group_policies(GroupName=gname)
            for ap in lap.get("AttachedPolicies", []):
                pol_arn = ap.get("PolicyArn")
                pol_name = ap.get("PolicyName")

                pol_entry: Dict[str, Any] = {
                    "source": "group_attached",
                    "group_name": gname,
                    "policy_name": pol_name,
                    "policy_arn": pol_arn,
                    "default_version_id": None,
                    "document": None,
                }

                if pol_arn:
                    try:
                        p = iam.get_policy(PolicyArn=pol_arn)
                        default_ver = p["Policy"]["DefaultVersionId"]
                        pol_entry["default_version_id"] = default_ver
                        ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=default_ver)
                        pol_entry["document"] = normalize_policy_document(ver["PolicyVersion"].get("Document"))
                    except ClientError as e:
                        pol_entry["error"] = f"get_policy/get_policy_version failed: {e}"

                report["group_attached_policies"].append(pol_entry)
                policies_out.append(pol_entry)
        except ClientError as e:
            report["errors"].append(f"list_attached_group_policies({gname}) failed: {e}")

        try:
            resp = iam.list_group_policies(GroupName=gname)
            for pname in resp.get("PolicyNames", []):
                pol_entry: Dict[str, Any] = {
                    "source": "group_inline",
                    "group_name": gname,
                    "policy_name": pname,
                    "document": None,
                }
                try:
                    p = iam.get_group_policy(GroupName=gname, PolicyName=pname)
                    pol_entry["document"] = normalize_policy_document(p.get("PolicyDocument"))
                except ClientError as e:
                    pol_entry["error"] = f"get_group_policy failed: {e}"

                report["group_inline_policies"].append(pol_entry)
                policies_out.append(pol_entry)
        except ClientError as e:
            report["errors"].append(f"list_group_policies({gname}) failed: {e}")

    return {"report": report, "policies": policies_out}


def classify_targets(resource_arns: Set[str]) -> Dict[str, Set[str]]:
    iam_role_arns: Set[str] = set()
    iam_policy_arns: Set[str] = set()
    s3_bucket_names: Set[str] = set()
    secrets_arns: Set[str] = set()

    for rarn in resource_arns:
        parsed = parse_arn(rarn)
        if not parsed:
            continue

        svc = parsed["service"]
        res = parsed["resource"]

        if svc == "iam":
            if res.startswith("role/"):
                iam_role_arns.add(rarn)
            elif res.startswith("policy/"):
                iam_policy_arns.add(rarn)

        elif svc == "s3":
            bucket_part = res.split("/")[0]
            bucket_name = bucket_part.lstrip(":")
            import re as _re
            if bucket_name and _re.match(r'^[a-z0-9][a-z0-9\-\.]{1,61}[a-z0-9]$', bucket_name):
                s3_bucket_names.add(bucket_name)

        elif svc == "secretsmanager":
            secrets_arns.add(rarn)

    return {
        "iam_role_arns": iam_role_arns,
        "iam_policy_arns": iam_policy_arns,
        "s3_bucket_names": s3_bucket_names,
        "secrets_arns": secrets_arns,
    }


def try_list_roles(iam) -> Set[str]:
    out: Set[str] = set()
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page.get("Roles", []):
            arn = r.get("Arn")
            if isinstance(arn, str) and arn.startswith("arn:aws:iam::") and ":role/" in arn:
                out.add(arn)
    return out


def try_list_customer_policies(iam) -> Set[str]:
    out: Set[str] = set()
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for p in page.get("Policies", []):
            arn = p.get("Arn")
            if isinstance(arn, str) and arn.startswith("arn:aws:iam::") and ":policy/" in arn:
                out.add(arn)
    return out


def _extract_principals(principal: Any, key: str) -> List[str]:
    if not isinstance(principal, dict):
        return []
    vals = ensure_list(principal.get(key))
    return [v for v in vals if isinstance(v, str)]


def analyze_trust_for_caller(trust_doc: Any, caller_arn: str, account_id: str) -> Dict[str, Any]:
    out = {
        "explicit_caller_trust": False,
        "same_account_root_trust": False,
        "wildcard_trust": False,
        "external_account_trust": False,
        "aws_principals": [],
        "service_principals": [],
    }

    if not isinstance(trust_doc, dict):
        return out

    aws_seen: Set[str] = set()
    svc_seen: Set[str] = set()

    for stmt in collect_statements(trust_doc):
        if stmt.get("Effect") != "Allow":
            continue

        actions = [a for a in ensure_list(stmt.get("Action")) if isinstance(a, str)]
        if not any(action_matches(a, "sts:AssumeRole") for a in actions):
            continue

        principal = stmt.get("Principal")

        if principal == "*":
            out["wildcard_trust"] = True
            continue

        for p in _extract_principals(principal, "AWS"):
            aws_seen.add(p)

            if caller_arn and p == caller_arn:
                out["explicit_caller_trust"] = True

            if account_id and p == f"arn:aws:iam::{account_id}:root":
                out["same_account_root_trust"] = True

            if p.startswith("arn:aws:iam::") and p.endswith(":root"):
                acct = p.split(":")[4]
                if account_id and acct != account_id:
                    out["external_account_trust"] = True

            if p == "*":
                out["wildcard_trust"] = True

        for p in _extract_principals(principal, "Service"):
            svc_seen.add(p)

    out["aws_principals"] = sorted(aws_seen)
    out["service_principals"] = sorted(svc_seen)
    return out


def policy_arn_default_doc(iam, pol_arn: str, policies: List[Dict[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "policy_arn": pol_arn,
        "policy": None,
        "default_version_id": None,
        "document": None,
        "all_versions": [],
    }

    can_get_policy = policy_allows(policies, "iam:GetPolicy", pol_arn)
    can_list_versions = policy_allows(policies, "iam:ListPolicyVersions", pol_arn)
    can_get_version = policy_allows(policies, "iam:GetPolicyVersion", pol_arn)

    result["access"] = {
        "get_policy_allowed": can_get_policy,
        "list_policy_versions_allowed": can_list_versions,
        "get_policy_version_allowed": can_get_version,
    }

    if not can_get_policy:
        result["note"] = "Policy metadata not retrievable from current caller-side permissions."
        return result

    try:
        p = iam.get_policy(PolicyArn=pol_arn)
        result["policy"] = p.get("Policy")
        default_ver = p["Policy"]["DefaultVersionId"]
        result["default_version_id"] = default_ver
    except ClientError as e:
        result["error"] = f"get_policy failed: {e}"
        return result

    if result["default_version_id"] and can_get_version:
        try:
            ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=result["default_version_id"])
            result["document"] = normalize_policy_document(ver["PolicyVersion"].get("Document"))
        except ClientError as e:
            result["version_error"] = f"get_policy_version failed: {e}"

    if can_list_versions and can_get_version:
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
                    "create_date": safe_iso(v.get("CreateDate")),
                    "document": None,
                }
                
                if is_default and result.get("document"):
                    version_entry["document"] = result["document"]
                else:
                    try:
                        ver = iam.get_policy_version(PolicyArn=pol_arn, VersionId=version_id)
                        version_entry["document"] = normalize_policy_document(ver["PolicyVersion"].get("Document"))
                    except ClientError as e:
                        version_entry["error"] = f"get_policy_version failed: {e}"
                
                result["all_versions"].append(version_entry)
        except ClientError as e:
            result["list_versions_error"] = f"list_policy_versions failed: {e}"

    return result


def enumerate_targeted_roles(
    iam,
    role_arns: Set[str],
    policies: List[Dict[str, Any]],
    caller_arn: str,
    account_id: str,
) -> List[Dict[str, Any]]:
    roles_out: List[Dict[str, Any]] = []

    for role_arn in sorted(role_arns):
        role_account, role_name, role_full_name = extract_api_role_name_from_arn(role_arn)

        entry: Dict[str, Any] = {
            "role_arn": role_arn,
            "role_name": role_name,               
            "role_full_name": role_full_name,    
            "role_account_id": role_account,
            "access": {
                "get_role_allowed": policy_allows(policies, "iam:GetRole", role_arn),
                "list_attached_role_policies_allowed": policy_allows(policies, "iam:ListAttachedRolePolicies", role_arn),
                "list_role_policies_allowed": policy_allows(policies, "iam:ListRolePolicies", role_arn),
                "get_role_policy_allowed": policy_allows(policies, "iam:GetRolePolicy", role_arn),
            },
            "role": None,
            "trust": {},
            "attached_policies": [],
            "inline_policies": [],
            "role_permission_summary": {},
            "pivot_signals": [],
        }

        if not role_name:
            entry["error"] = "Could not parse role name from ARN"
            roles_out.append(entry)
            continue

        if entry["access"]["get_role_allowed"]:
            try:
                resp = iam.get_role(RoleName=role_name)
                role = resp.get("Role", {})
                entry["role"] = {
                    "Arn": role.get("Arn"),
                    "RoleName": role.get("RoleName"),
                    "Path": role.get("Path"),
                    "RoleId": role.get("RoleId"),
                    "Description": role.get("Description"),
                    "CreateDate": safe_iso(role.get("CreateDate")),
                    "MaxSessionDuration": role.get("MaxSessionDuration"),
                }
                trust_doc = role.get("AssumeRolePolicyDocument")
                entry["trust"] = analyze_trust_for_caller(trust_doc, caller_arn, account_id)
            except ClientError as e:
                entry["get_role_error"] = f"get_role failed: {e}"

        attached_docs: List[Dict[str, Any]] = []
        if entry["access"]["list_attached_role_policies_allowed"]:
            try:
                paginator = iam.get_paginator("list_attached_role_policies")
                for page in paginator.paginate(RoleName=role_name):
                    for ap in page.get("AttachedPolicies", []):
                        pol_arn = ap.get("PolicyArn")
                        pol_name = ap.get("PolicyName")
                        pol_entry: Dict[str, Any] = {
                            "policy_name": pol_name,
                            "policy_arn": pol_arn,
                            "default_version_id": None,
                            "document": None,
                        }

                        if pol_arn:
                            resolved = policy_arn_default_doc(iam, pol_arn, policies)
                            pol_entry.update(resolved)

                            doc = normalize_policy_document(pol_entry.get("document"))
                            if doc:
                                attached_docs.append({"document": doc})

                        entry["attached_policies"].append(pol_entry)
            except ClientError as e:
                entry["list_attached_role_policies_error"] = f"list_attached_role_policies failed: {e}"

        inline_docs: List[Dict[str, Any]] = []
        if entry["access"]["list_role_policies_allowed"]:
            try:
                paginator = iam.get_paginator("list_role_policies")
                for page in paginator.paginate(RoleName=role_name):
                    for pname in page.get("PolicyNames", []):
                        pol_entry: Dict[str, Any] = {
                            "policy_name": pname,
                            "document": None,
                        }

                        if entry["access"]["get_role_policy_allowed"]:
                            try:
                                gp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
                                pol_entry["document"] = normalize_policy_document(gp.get("PolicyDocument"))
                                if pol_entry["document"]:
                                    inline_docs.append({"document": pol_entry["document"]})
                            except ClientError as e:
                                pol_entry["error"] = f"get_role_policy failed: {e}"
                        else:
                            pol_entry["note"] = "ListRolePolicies allowed, but GetRolePolicy not allowed."

                        entry["inline_policies"].append(pol_entry)
            except ClientError as e:
                entry["list_role_policies_error"] = f"list_role_policies failed: {e}"
        else:
            if entry["access"]["get_role_policy_allowed"]:
                entry["inline_policy_note"] = (
                    "Caller appears to have iam:GetRolePolicy on this role, but not iam:ListRolePolicies, "
                    "so inline policy names cannot be discovered automatically."
                )

        role_side_policies = attached_docs + inline_docs
        if role_side_policies:
            entry["role_permission_summary"] = summarize_policy_documents(role_side_policies)

        trust = entry.get("trust", {}) or {}
        role_summary = entry.get("role_permission_summary", {}) or {}
        interesting_services = role_summary.get("interesting_services", []) or []

        if trust.get("explicit_caller_trust"):
            entry["pivot_signals"].append("same-account explicit caller trust")
        if trust.get("same_account_root_trust"):
            entry["pivot_signals"].append("same-account root trust")
        if trust.get("wildcard_trust"):
            entry["pivot_signals"].append("wildcard/public trust")
        if trust.get("external_account_trust"):
            entry["pivot_signals"].append("cross-account trust")
        if interesting_services:
            entry["pivot_signals"].append(f"role exposes interesting services: {', '.join(interesting_services)}")

        roles_out.append(entry)

    return roles_out


def enumerate_targeted_s3(session, bucket_names: Set[str], policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    s3 = session.client("s3")
    out: List[Dict[str, Any]] = []

    for bucket in sorted(bucket_names):
        bucket_arn = f"arn:aws:s3:::{bucket}"
        object_arn = f"arn:aws:s3:::{bucket}/*"

        entry: Dict[str, Any] = {
            "bucket_name": bucket,
            "access": {
                "list_bucket_allowed": policy_allows(policies, "s3:ListBucket", bucket_arn),
                "get_object_allowed": policy_allows(policies, "s3:GetObject", object_arn),
            },
            "exists": False,
            "location": None,
            "sample_objects": [],
        }

        if entry["access"]["list_bucket_allowed"]:
            try:
                resp = s3.list_objects_v2(Bucket=bucket, MaxKeys=20)
                entry["exists"] = True
                for obj in resp.get("Contents", []):
                    entry["sample_objects"].append({
                        "key": obj.get("Key"),
                        "size": obj.get("Size"),
                        "last_modified": safe_iso(obj.get("LastModified")),
                    })
            except ClientError as e:
                entry["list_error"] = f"list_objects_v2 failed: {e}"

        try:
            loc = s3.get_bucket_location(Bucket=bucket)
            entry["location"] = loc.get("LocationConstraint")
        except ClientError:
            pass

        out.append(entry)

    return out


def enumerate_targeted_secrets(session, secret_arns: Set[str], policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for secret_arn in sorted(secret_arns):
        parsed = parse_arn(secret_arn)
        if not parsed:
            continue

        region = parsed["region"] or session.region_name or "us-east-1"
        sm = session.client("secretsmanager", region_name=region)

        entry: Dict[str, Any] = {
            "secret_arn": secret_arn,
            "region": region,
            "access": {
                "describe_secret_allowed": policy_allows(policies, "secretsmanager:DescribeSecret", secret_arn),
                "get_secret_value_allowed": policy_allows(policies, "secretsmanager:GetSecretValue", secret_arn),
            },
            "describe_secret": None,
        }

        if entry["access"]["describe_secret_allowed"]:
            try:
                entry["describe_secret"] = sm.describe_secret(SecretId=secret_arn)
            except ClientError as e:
                entry["describe_error"] = f"describe_secret failed: {e}"

        out.append(entry)

    return out


def enumerate_ec2_if_allowed(session, policies: List[Dict[str, Any]], region: str) -> Dict[str, Any]:
    allowed = policy_allows(policies, "ec2:DescribeInstances", "*")
    result: Dict[str, Any] = {"allowed_by_policy": allowed, "instances": []}

    if not allowed:
        return result

    ec2 = session.client("ec2", region_name=region)

    try:
        resp = ec2.describe_instances()
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                result["instances"].append({
                    "instance_id": inst.get("InstanceId"),
                    "instance_type": inst.get("InstanceType"),
                    "state": inst.get("State", {}).get("Name"),
                    "private_ip": inst.get("PrivateIpAddress"),
                    "public_ip": inst.get("PublicIpAddress"),
                    "launch_time": safe_iso(inst.get("LaunchTime")),
                    "tags": inst.get("Tags", []),
                })
    except ClientError as e:
        result["error"] = f"describe_instances failed: {e}"

    return result


def build_pivot_candidates(role_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for r in role_entries:
        if not isinstance(r, dict):
            continue

        role_name = r.get("role_name") or r.get("role_arn") or "unknown-role"
        role_arn = r.get("role_arn") or ""
        trust = r.get("trust", {}) or {}
        summary = r.get("role_permission_summary", {}) or {}
        interesting_services = summary.get("interesting_services", []) or []
        resource_samples = summary.get("resource_samples", []) or []

        is_service_linked = (
            (isinstance(role_arn, str) and ":role/aws-service-role/" in role_arn)
            or (isinstance(role_name, str) and role_name.startswith("AWSServiceRoleFor"))
        )

        confidence = "LOW"
        reasons: List[str] = []

        if trust.get("explicit_caller_trust"):
            confidence = "HIGH"
            reasons.append("same-account explicit trust for current caller")
        elif trust.get("same_account_root_trust"):
            confidence = "MEDIUM"
            reasons.append("same-account root trust may allow same-account assumption path")
        elif trust.get("wildcard_trust"):
            confidence = "HIGH"
            reasons.append("wildcard/public trust")
        elif trust.get("external_account_trust"):
            confidence = "MEDIUM"
            reasons.append("cross-account trust")

        if interesting_services and confidence in {"HIGH", "MEDIUM"}:
            reasons.append(f"exposes interesting services: {', '.join(interesting_services)}")

        if confidence == "LOW":
            continue

        if is_service_linked and confidence not in {"HIGH"}:
            continue

        out.append({
            "role_name": role_name,
            "role_arn": role_arn,
            "confidence": confidence,
            "reasons": reasons,
            "interesting_services": interesting_services,
            "resource_samples": resource_samples[:10],
        })

    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    out.sort(key=lambda x: (rank.get(x["confidence"], 9), x.get("role_name") or ""))
    return out


def build_followup_summary(
    all_policies: List[Dict[str, Any]],
    resources: Dict[str, Any],
    pivot_candidates: List[Dict[str, Any]],
) -> Dict[str, Any]:
    summary = summarize_policy_documents(all_policies)

    s3_targets = resources.get("s3", []) if isinstance(resources.get("s3"), list) else []
    secret_targets = resources.get("secretsmanager", []) if isinstance(resources.get("secretsmanager"), list) else []
    roles = resources.get("iam", {}).get("roles", []) if isinstance(resources.get("iam"), dict) else []

    likely_sensitive_secrets = sum(
        1 for s in secret_targets
        if isinstance(s, dict) and s.get("access", {}).get("get_secret_value_allowed")
    )

    readable_buckets = sum(
        1 for b in s3_targets
        if isinstance(b, dict) and b.get("access", {}).get("list_bucket_allowed")
    )

    return {
        "policy_services_count": summary["service_count"],
        "policy_action_count": summary["action_count"],
        "policy_resource_count": summary["resource_count"],
        "interesting_policy_services": summary["interesting_services"],
        "roles_followed": len(roles),
        "pivot_candidates_count": len(pivot_candidates),
        "readable_buckets_count": readable_buckets,
        "secret_targets_count": len(secret_targets),
        "secret_value_candidates_count": likely_sensitive_secrets,
        "ec2_describe_allowed": bool(resources.get("ec2", {}).get("allowed_by_policy")),
    }


def run(ctx) -> Dict[str, Any]:
    print_header("Policy Resource Follow-Up (AI-ready)")

    if ctx.session is None:
        return {"ok": False, "error": "ctx.session is None"}

    base = ctx.last_result
    if not isinstance(base, dict):
        return {"ok": False, "error": "Run module 1 first. ctx.last_result is empty."}

    attached = base.get("attached_policies", [])
    inline = base.get("inline_policies", [])
    if not isinstance(attached, list) or not isinstance(inline, list):
        return {"ok": False, "error": "ctx.last_result missing expected attached/inline policies."}

    iam = ctx.session.client("iam")
    sts = ctx.session.client("sts")

    try:
        ident = sts.get_caller_identity()
        caller_arn = ident.get("Arn", "")
        account_id = ident.get("Account", "")
    except ClientError:
        caller_arn = ""
        account_id = ""

    user_name = base.get("target_user_name") or ""
    groups_info = base.get("groups")

    gp = collect_group_policies(iam, user_name, groups_info)
    group_policies = gp.get("policies", [])
    group_report = gp.get("report", {})

    all_policies = flatten_policy_sources(attached, inline, group_policies)
    resource_arns, actions = extract_resources_and_actions_from_policies(all_policies)

    targets = classify_targets(resource_arns)
    iam_role_arns = set(targets["iam_role_arns"])
    iam_policy_arns = set(targets["iam_policy_arns"])
    s3_bucket_names = set(targets["s3_bucket_names"])
    secrets_arns = set(targets["secrets_arns"])

    warnings: List[str] = []

    iam_listing_possible = (
        policy_allows(all_policies, "iam:ListRoles", "*")
        or policy_allows(all_policies, "iam:ListRoles", f"arn:aws:iam::{account_id}:role/*")
        or policy_allows(all_policies, "iam:ListPolicies", "*")
        or policy_allows(all_policies, "iam:ListPolicies", f"arn:aws:iam::{account_id}:policy/*")
    )

    if iam_listing_possible:
        try:
            iam_role_arns |= try_list_roles(iam)
        except ClientError as e:
            warnings.append(f"list_roles failed: {e}")

        try:
            iam_policy_arns |= try_list_customer_policies(iam)
        except ClientError as e:
            warnings.append(f"list_policies failed: {e}")

    iam_roles = enumerate_targeted_roles(iam, iam_role_arns, all_policies, caller_arn, account_id)

    iam_policies: List[Dict[str, Any]] = []
    for pol_arn in sorted(iam_policy_arns):
        iam_policies.append(policy_arn_default_doc(iam, pol_arn, all_policies))

    s3_targets = enumerate_targeted_s3(ctx.session, s3_bucket_names, all_policies)
    secret_targets = enumerate_targeted_secrets(ctx.session, secrets_arns, all_policies)
    ec2_targets = enumerate_ec2_if_allowed(ctx.session, all_policies, ctx.region or "us-east-1")

    resources: Dict[str, Any] = {
        "iam": {
            "roles": iam_roles,
            "policies": iam_policies,
        },
        "s3": s3_targets,
        "secretsmanager": secret_targets,
        "ec2": ec2_targets,
    }

    if warnings:
        resources["warnings"] = warnings

    pivot_candidates = build_pivot_candidates(iam_roles)
    followup_summary = build_followup_summary(all_policies, resources, pivot_candidates)

    print_header("FOLLOW-UP SUMMARY")
    print_json({
        "policy_services_count": followup_summary["policy_services_count"],
        "pivot_candidates_count": followup_summary["pivot_candidates_count"],
        "roles_followed": followup_summary["roles_followed"],
        "readable_buckets_count": followup_summary["readable_buckets_count"],
        "secret_targets_count": followup_summary["secret_targets_count"],
        "secret_value_candidates_count": followup_summary["secret_value_candidates_count"],
        "ec2_describe_allowed": followup_summary["ec2_describe_allowed"],
        "top_pivot_candidates": pivot_candidates[:5],
    })

    return {
        "ok": True,
        "caller_arn": caller_arn,
        "account_id": account_id,
        "resources": resources,
        "pivot_candidates": pivot_candidates,
        "followup_summary": followup_summary,
        "policies_source": {
            "user_attached": attached,
            "user_inline": inline,
            "groups": group_report,
        },
        "all_policies_count": len(all_policies),
        "notes": [
            "Best-effort evaluation. IAM Conditions are not evaluated.",
            "Secret values are not retrieved automatically; only metadata and access potential are reported.",
            "Inline role policies require iam:ListRolePolicies to enumerate names automatically.",
        ],
    }


def handler(ctx) -> None:
    res = run(ctx)

    if isinstance(ctx.last_result, dict) and (
        "attached_policies" in ctx.last_result or "inline_policies" in ctx.last_result
    ):
        ctx.last_result["resources"] = res.get("resources")
        ctx.last_result["resources_ok"] = res.get("ok", True)
        ctx.last_result["resources_error"] = res.get("error")
        ctx.last_result["policy_resource_followup"] = res
        ctx.last_result.setdefault("module2_runs", []).append(res)
    else:
        ctx.last_result = res


menu_item = MenuItem(
    key="2",
    title="Policy resource follow-up (AI-ready)",
    handler=handler,
    help="Z policies vytiahne high-value resources, spraví targeted follow-up a pripraví AI-ready pivot/blast-radius výstup.",
)
