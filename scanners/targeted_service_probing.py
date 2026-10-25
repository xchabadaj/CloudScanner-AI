from __future__ import annotations

import fnmatch
import io
import json
import re
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from botocore.exceptions import ClientError

from core.menu import MenuItem
from scanners.service_common import (
    dedupe_keep_order,
    env_bool,
    env_int,
    get_account_id_from_workspace,
    now_iso_utc,
    parse_json_maybe,
    policy_allows_public,
    resolve_regions,
    safe_aws_error,
    score_risk,
)

S3_KEYWORDS = (
    "flag",
    "secret",
    "password",
    "passwd",
    "credential",
    "creds",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "private",
    "backup",
    ".pem",
    ".env",
)

SECRET_NAME_KEYWORDS = (
    "prod",
    "db",
    "token",
    "secret",
    "password",
    "key",
    "credential",
)

ENV_KEYWORDS = ("secret", "token", "password", "key", "credential")

LAMBDA_CODE_FILE_EXTENSIONS = (".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".env", ".ini", ".txt", ".cfg", ".conf")
LAMBDA_SECRET_PATTERNS = (
    re.compile(r"sk_(?:live|test)_[A-Za-z0-9]+"),
    re.compile(r"whsec_[A-Za-z0-9]+"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)aws(.{0,20})?(secret|access).{0,20}[=:]\s*[\"'][^\"'\n]+"),
    re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*[\"'][^\"'\n]+"),
)

SERVICE_SIGNAL_MAP: Dict[str, Tuple[str, ...]] = {
    "s3": ("read/get", "write/modify", "admin/service-wildcard", "admin/wildcard", "other"),
    "secretsmanager": ("read/get", "write/modify", "admin/service-wildcard", "admin/wildcard", "other"),
    "lambda": ("read/get", "write/modify", "admin/service-wildcard", "admin/wildcard", "other"),
    "kms": ("read/get", "write/modify", "admin/service-wildcard", "admin/wildcard", "other"),
    "ec2": ("list/describe", "read/get", "write/modify", "admin/service-wildcard", "admin/wildcard", "other"),
}

SENSITIVE_WORLD_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB"}


def _get_workspace(ctx) -> Dict[str, Any]:
    if isinstance(getattr(ctx, "last_result", None), dict):
        return ctx.last_result
    return {}


def _services_block(workspace: Dict[str, Any]) -> Dict[str, Any]:
    perm = workspace.get("permission_summary") or {}
    if isinstance(perm, dict):
        services = perm.get("services") or {}
        if isinstance(services, dict):
            return services
    return {}



def _risk_block(workspace: Dict[str, Any]) -> Dict[str, Any]:
    perm = workspace.get("permission_summary") or {}
    if isinstance(perm, dict):
        risk = perm.get("risk") or {}
        if isinstance(risk, dict):
            return risk
    return {}



def _resources_samples(workspace: Dict[str, Any]) -> List[str]:
    perm = workspace.get("permission_summary") or {}
    if isinstance(perm, dict):
        samples = perm.get("resources_samples") or []
        if isinstance(samples, list):
            return [x for x in samples if isinstance(x, str)]
    return []



def _parse_arn(arn: str) -> Optional[Dict[str, str]]:
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



def _service_has_strong_signal(workspace: Dict[str, Any], service: str) -> Tuple[bool, List[str]]:
    services = _services_block(workspace)
    risk = _risk_block(workspace)
    svc_block = services.get(service) if isinstance(services, dict) else None
    reasons: List[str] = []
    strong = False

    if isinstance(svc_block, dict):
        interesting_caps = SERVICE_SIGNAL_MAP.get(service, ())
        for cap in interesting_caps:
            details = svc_block.get(cap)
            if isinstance(details, dict) and int(details.get("count") or 0) > 0:
                strong = True
                reasons.append(f"permission_summary:{service}:{cap}")

    if risk.get("has_action_wildcard"):
        strong = True
        reasons.append("risk:action_wildcard")
    if risk.get("has_service_wildcard"):
        strong = True
        reasons.append("risk:service_wildcard")

    return strong, dedupe_keep_order(reasons)



def _extract_explicit_targets(workspace: Dict[str, Any]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {
        "s3_buckets": [],
        "secret_arns": [],
        "lambda_arns": [],
        "kms_arns": [],
        "ec2_instance_ids": [],
    }

    followup = workspace.get("policy_resource_followup") or {}
    resources = followup.get("resources") if isinstance(followup, dict) else None
    if isinstance(resources, dict):
        for item in resources.get("s3") or []:
            if isinstance(item, dict) and isinstance(item.get("bucket_name"), str):
                out["s3_buckets"].append(item["bucket_name"])
        for item in resources.get("secretsmanager") or []:
            if isinstance(item, dict) and isinstance(item.get("secret_arn"), str):
                out["secret_arns"].append(item["secret_arn"])
        ec2_block = resources.get("ec2") or {}
        if isinstance(ec2_block, dict):
            for inst in ec2_block.get("instances") or []:
                if isinstance(inst, dict) and isinstance(inst.get("instance_id"), str):
                    out["ec2_instance_ids"].append(inst["instance_id"])

    for sample in _resources_samples(workspace):
        parsed = _parse_arn(sample)
        if not parsed:
            continue
        service = parsed["service"]
        resource = parsed["resource"]
        if service == "s3":
            bucket = resource.split("/", 1)[0]
            if bucket:
                out["s3_buckets"].append(bucket)
        elif service == "secretsmanager":
            out["secret_arns"].append(sample)
        elif service == "lambda":
            out["lambda_arns"].append(sample)
        elif service == "kms":
            out["kms_arns"].append(sample)
        elif service == "ec2" and resource.startswith("instance/"):
            instance_id = resource.split("/", 1)[1]
            if instance_id:
                out["ec2_instance_ids"].append(instance_id)

    return {k: dedupe_keep_order(v) for k, v in out.items()}



def _should_probe(workspace: Dict[str, Any], service: str, explicit_targets: Sequence[str]) -> Tuple[bool, List[str]]:
    strong, reasons = _service_has_strong_signal(workspace, service)
    if explicit_targets:
        reasons = dedupe_keep_order(list(reasons) + [f"explicit_targets:{len(explicit_targets)}"])
        return True, reasons
    if strong:
        return True, reasons
    return False, reasons



def _ensure_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _action_matches(action: str, pattern: str) -> bool:
    action_l = str(action).lower()
    pattern_l = pattern.lower()
    if pattern_l in {"*", "*:*"}:
        return action_l == pattern_l
    return fnmatch.fnmatchcase(action_l, pattern_l)


def _policy_documents_from_workspace(workspace: Dict[str, Any]) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []
    for key in ("attached_policies", "inline_policies", "group_policies"):
        items = workspace.get(key) or []
        if not isinstance(items, list):
            continue
        for pol in items:
            if isinstance(pol, dict) and isinstance(pol.get("document"), dict):
                docs.append(pol["document"])
    return docs


def _collect_allowed_actions(workspace: Dict[str, Any]) -> List[str]:
    actions: Set[str] = set()
    for doc in _policy_documents_from_workspace(workspace):
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            if str(stmt.get("Effect") or "").upper() != "ALLOW":
                continue
            for action in _ensure_list(stmt.get("Action")):
                if isinstance(action, str):
                    actions.add(action)
    return sorted(actions)


def _matching_covering_actions(workspace: Dict[str, Any], required_actions: Sequence[str]) -> List[str]:
    actions = _collect_allowed_actions(workspace)
    matched: List[str] = []
    for allowed_action in actions:
        if allowed_action in {"*", "*:*"}:
            matched.append(allowed_action)
            continue
        if any(_action_matches(allowed_action, required_action) for required_action in required_actions):
            matched.append(allowed_action)
    return matched


def _is_service_linked_role_name(role_name: Optional[str]) -> bool:
    return isinstance(role_name, str) and role_name.startswith("AWSServiceRoleFor")


def _append_normalized_finding(
    findings: List[Dict[str, Any]],
    *,
    service: str,
    category: str,
    severity: str,
    title: str,
    target: Optional[str],
    tested_apis: Sequence[str],
    evidence: Sequence[str],
    report_text: str,
    recommendation: str,
    risk_note: Optional[str] = None,
    impact_type: Optional[str] = None,
    source: str = "targeted_service_probing",
    tested: bool = True,
) -> None:
    finding_id = f"{service}:{category}:{target or title}"
    findings.append({
        "id": re.sub(r"[^a-zA-Z0-9:_-]+", "-", finding_id)[:160],
        "service": service,
        "category": category,
        "severity": severity,
        "title": title,
        "target": target,
        "tested_apis": list(tested_apis),
        "evidence": dedupe_keep_order([str(x) for x in evidence if isinstance(x, str)]),
        "report_text": report_text,
        "recommendation": recommendation,
        "risk_note": risk_note,
        "impact_type": impact_type,
        "source": source,
        "tested": tested,
    })


def _build_normalized_findings(
    workspace: Dict[str, Any],
    service_results: Dict[str, Dict[str, Any]],
    service_plan: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # S3
    for bucket in ((service_results.get("s3") or {}).get("buckets") or []):
        if not isinstance(bucket, dict):
            continue
        bucket_name = bucket.get("bucket_name") or bucket.get("name") or "unknown-bucket"
        if bucket.get("public") or bucket.get("acl_public"):
            _append_normalized_finding(
                findings,
                service="s3",
                category="public_data_exposure",
                severity="HIGH",
                title="S3 bucket appears publicly exposed",
                target=bucket_name,
                tested_apis=["GetBucketPolicyStatus", "GetBucketAcl"],
                evidence=bucket.get("findings") or ["Bucket policy/ACL indicates public exposure."],
                report_text=f"S3 bucket `{bucket_name}` appears publicly exposed via bucket policy or ACL.",
                recommendation="Enable Block Public Access and remove public ACL/policy grants unless they are explicitly required.",
                risk_note="Public S3 access can expose bucket contents without requiring an authenticated pivot.",
                impact_type="sensitive_data_access",
            )
        if bucket.get("listable"):
            _append_normalized_finding(
                findings,
                service="s3",
                category="bucket_enumeration",
                severity="MEDIUM",
                title="S3 bucket is listable by the current principal",
                target=bucket_name,
                tested_apis=["ListObjectsV2"],
                evidence=bucket.get("interesting_objects") or bucket.get("findings") or ["Bucket listing succeeded."],
                report_text=f"S3 bucket `{bucket_name}` is listable by the current principal, enabling immediate object discovery.",
                recommendation="Restrict s3:ListBucket / s3:GetObject to required buckets, prefixes, and principals only.",
                risk_note="Successful bucket listing supports reconnaissance and follow-on data access.",
                impact_type="reconnaissance",
            )
        if bucket.get("interesting_objects"):
            interesting = bucket.get("interesting_objects") or []
            _append_normalized_finding(
                findings,
                service="s3",
                category="interesting_object_names",
                severity="MEDIUM",
                title="Interesting object names were discovered in S3",
                target=bucket_name,
                tested_apis=["ListObjectsV2"],
                evidence=[f"Interesting object hint: {x}" for x in interesting[:10]],
                report_text=f"Bucket `{bucket_name}` contains object names that look sensitive (for example secrets, backups, or flags).",
                recommendation="Review accessible objects and remove or further restrict sensitive artifacts.",
                risk_note="Object-name reconnaissance can quickly identify likely credentials, backups, or proof files.",
                impact_type="sensitive_data_access",
            )

    # Secrets Manager
    for secret in ((service_results.get("secretsmanager") or {}).get("secrets") or []):
        if not isinstance(secret, dict):
            continue
        target = secret.get("secret_arn") or secret.get("name") or "unknown-secret"
        if secret.get("policy_public"):
            _append_normalized_finding(
                findings,
                service="secretsmanager",
                category="public_resource_policy",
                severity="HIGH",
                title="Secret resource policy contains a wildcard principal",
                target=target,
                tested_apis=["DescribeSecret", "GetResourcePolicy"],
                evidence=secret.get("findings") or ["Resource policy contains wildcard principal."],
                report_text=f"Secret `{target}` exposes a wildcard principal in its resource policy.",
                recommendation="Remove wildcard principals from Secrets Manager resource policies and scope access to explicit roles or accounts.",
                risk_note="A permissive secret resource policy can expose secret metadata and may enable secret-value access by unintended principals.",
                impact_type="sensitive_data_access",
            )
        elif secret.get("policy_external"):
            _append_normalized_finding(
                findings,
                service="secretsmanager",
                category="external_resource_policy",
                severity="MEDIUM",
                title="Secret resource policy references external principals",
                target=target,
                tested_apis=["DescribeSecret", "GetResourcePolicy"],
                evidence=secret.get("findings") or ["Resource policy contains external principal(s)."],
                report_text=f"Secret `{target}` references external principals in its resource policy.",
                recommendation="Review cross-account secret sharing and keep it scoped to the smallest required principal set.",
                risk_note="Cross-account secret access expands the trust boundary for sensitive data.",
                impact_type="sensitive_data_access",
            )
        if secret.get("rotation_enabled") is False:
            _append_normalized_finding(
                findings,
                service="secretsmanager",
                category="rotation_disabled",
                severity="LOW",
                title="Secret rotation is disabled",
                target=target,
                tested_apis=["DescribeSecret"],
                evidence=secret.get("findings") or ["Rotation is disabled."],
                report_text=f"Secret `{target}` has rotation disabled.",
                recommendation="Enable rotation where applicable and document approved exceptions.",
            )

    # Lambda
    for fn in ((service_results.get("lambda") or {}).get("functions") or []):
        if not isinstance(fn, dict):
            continue
        target = fn.get("function_arn") or fn.get("name") or "unknown-function"
        if fn.get("enumeration_confirmed"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="enumeration_capability",
                severity="LOW",
                title="Lambda enumeration succeeded for the current principal",
                target=target,
                tested_apis=["ListFunctions", "GetFunctionConfiguration"],
                evidence=[
                    f"FunctionName={fn.get('name')}",
                    f"Runtime={fn.get('runtime')}",
                    f"LastModified={fn.get('last_modified')}",
                ],
                report_text=f"The current principal can enumerate Lambda function `{target}` and read its basic configuration.",
                recommendation="Scope Lambda read permissions to only the functions and metadata that are operationally required.",
                risk_note="Successful enumeration confirms that Lambda discovery is possible even without IAM policy listing rights.",
                impact_type="reconnaissance",
            )
        if fn.get("public_url"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="public_function_url",
                severity="HIGH",
                title="Lambda function URL is public",
                target=target,
                tested_apis=["GetFunctionConfiguration", "GetFunctionUrlConfig"],
                evidence=fn.get("findings") or ["Function URL is public (AuthType=NONE)."],
                report_text=f"Lambda function `{target}` has a public function URL with `AuthType=NONE`.",
                recommendation="Require AWS_IAM or a dedicated authentication layer before exposing Lambda URLs publicly.",
                risk_note="An unauthenticated Lambda URL may expose application logic or trigger sensitive code paths.",
                impact_type="code_execution",
            )
        if fn.get("policy_public"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="public_resource_policy",
                severity="HIGH",
                title="Lambda resource policy contains a wildcard principal",
                target=target,
                tested_apis=["GetPolicy"],
                evidence=fn.get("findings") or ["Resource policy contains wildcard principal."],
                report_text=f"Lambda function `{target}` appears publicly invokable through its resource policy.",
                recommendation="Restrict Lambda resource policies to explicit principals and add SourceArn/SourceAccount conditions where possible.",
                risk_note="A permissive Lambda resource policy can expose function invocation to unintended principals.",
                impact_type="code_execution",
            )
        elif fn.get("policy_external"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="external_resource_policy",
                severity="MEDIUM",
                title="Lambda resource policy references external principals",
                target=target,
                tested_apis=["GetPolicy"],
                evidence=fn.get("findings") or ["Resource policy contains external principal(s)."],
                report_text=f"Lambda function `{target}` references external principals in its resource policy.",
                recommendation="Review cross-account Lambda invoke permissions and keep them narrowly scoped.",
                risk_note="Cross-account invoke permissions widen the service exposure surface.",
                impact_type="code_execution",
            )
        if fn.get("sensitive_env_key_hints"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="sensitive_environment_hints",
                severity="MEDIUM",
                title="Lambda environment variable names suggest embedded secrets",
                target=target,
                tested_apis=["GetFunctionConfiguration"],
                evidence=[f"Sensitive environment key hint: {x}" for x in (fn.get("sensitive_env_key_hints") or [])[:10]],
                report_text=f"Lambda function `{target}` contains environment variable names that suggest embedded secrets or credentials.",
                recommendation="Move secrets to Secrets Manager / Parameter Store and minimize sensitive environment variables.",
                risk_note="Configuration disclosure can reveal where application secrets likely reside.",
                impact_type="sensitive_data_access",
            )
        if fn.get("sensitive_env_values"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="sensitive_environment_values",
                severity="HIGH",
                title="Lambda environment variables expose secret material",
                target=target,
                tested_apis=["GetFunctionConfiguration"],
                evidence=[f"{item.get('key')}={item.get('value_masked')}" for item in (fn.get("sensitive_env_values") or [])[:10]],
                report_text=f"Lambda function `{target}` exposes secret-like environment variable values to the current principal.",
                recommendation="Move secrets into Secrets Manager or Parameter Store and remove them from plaintext Lambda environment variables.",
                risk_note="Readable environment variables can directly disclose credentials, tokens, or database secrets.",
                impact_type="sensitive_data_access",
            )
        if fn.get("code_download_confirmed"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="deployment_package_access",
                severity="MEDIUM",
                title="Lambda deployment package can be downloaded",
                target=target,
                tested_apis=["GetFunction"],
                evidence=([f"Code.Location returned for {target}"] + [f"Code finding: {item.get('file')}:{item.get('match')}" for item in (fn.get("code_secret_findings") or [])[:5]]),
                report_text=f"The current principal can obtain a presigned deployment package URL for Lambda function `{target}`.",
                recommendation="Restrict lambda:GetFunction to trusted audit roles only and avoid embedding sensitive material in deployment packages.",
                risk_note="Deployment package access enables offline source review and hardcoded secret discovery.",
                impact_type="sensitive_data_access",
            )
        if fn.get("code_secret_findings"):
            _append_normalized_finding(
                findings,
                service="lambda",
                category="hardcoded_secret_in_code",
                severity="HIGH",
                title="Lambda deployment package contains hardcoded secret material",
                target=target,
                tested_apis=["GetFunction"],
                evidence=[f"{item.get('file')}: {item.get('match')}" for item in (fn.get("code_secret_findings") or [])[:10]],
                report_text=f"Offline review of the deployment package for `{target}` found hardcoded secret-like material.",
                recommendation="Remove hardcoded secrets from the function package, rotate exposed values, and re-deploy using a managed secret store.",
                risk_note="Deployment package access combined with hardcoded secrets can immediately expose sensitive credentials or flags.",
                impact_type="sensitive_data_access",
            )
        if fn.get("invoke_responses"):
            _all_bodies = [r.get("response_body", "") for r in fn["invoke_responses"]]
            _append_normalized_finding(
                findings,
                service="lambda",
                category="public_function_invocation",
                severity="HIGH",
                title="Public Lambda function invoked and response captured",
                target=target,
                tested_apis=["InvokeFunction"],
                evidence=[
                    f"Payload: {r.get('payload_sent')} | StatusCode: {r.get('status_code')} | Response: {r.get('response_body')}"
                    for r in fn["invoke_responses"]
                ],
                report_text=f"Lambda function `{target}` is publicly invokable and returned responses. Review the response bodies for sensitive data or flags.",
                recommendation="Restrict the resource policy to explicit principals. Review responses for exposed sensitive data.",
                risk_note="Publicly invokable functions can expose sensitive data, internal state, or flags in their response.",
                impact_type="sensitive_data_access",
            )

    # KMS
    for key in ((service_results.get("kms") or {}).get("keys") or []):
        if not isinstance(key, dict):
            continue
        target = key.get("key_arn") or key.get("key_id") or "unknown-kms-key"
        if key.get("policy_public"):
            _append_normalized_finding(
                findings,
                service="kms",
                category="public_key_policy",
                severity="HIGH",
                title="KMS key policy contains a wildcard principal",
                target=target,
                tested_apis=["DescribeKey", "GetKeyPolicy"],
                evidence=key.get("findings") or ["Key policy contains wildcard principal."],
                report_text=f"KMS key `{target}` exposes a wildcard principal in its key policy.",
                recommendation="Restrict KMS key policies to explicit principals and validate all cross-account key use cases.",
                risk_note="A permissive KMS key policy can broaden access to cryptographic operations and protected data.",
                impact_type="sensitive_data_access",
            )
        if key.get("key_state") == "PendingDeletion":
            _append_normalized_finding(
                findings,
                service="kms",
                category="pending_deletion",
                severity="MEDIUM",
                title="KMS key is pending deletion",
                target=target,
                tested_apis=["DescribeKey"],
                evidence=key.get("findings") or ["Key is pending deletion."],
                report_text=f"KMS key `{target}` is in `PendingDeletion` state.",
                recommendation="Review pending deletion keys carefully to avoid breaking dependent encrypted data flows.",
            )
        if key.get("key_manager") == "CUSTOMER" and key.get("rotation_enabled") is False:
            _append_normalized_finding(
                findings,
                service="kms",
                category="rotation_disabled",
                severity="LOW",
                title="Customer-managed KMS key rotation is disabled",
                target=target,
                tested_apis=["DescribeKey", "GetKeyRotationStatus"],
                evidence=key.get("findings") or ["Key rotation is disabled."],
                report_text=f"Customer-managed KMS key `{target}` has rotation disabled.",
                recommendation="Enable automatic key rotation for customer-managed symmetric keys where applicable.",
            )

    # EC2
    for inst in ((service_results.get("ec2") or {}).get("instances") or []):
        if not isinstance(inst, dict):
            continue
        target = inst.get("instance_id") or "unknown-instance"
        if inst.get("public_ip") and inst.get("world_open_management_ports"):
            ports = ", ".join(inst.get("world_open_management_ports")[:10])
            _append_normalized_finding(
                findings,
                service="ec2",
                category="public_management_exposure",
                severity="HIGH",
                title="EC2 instance exposes sensitive management/database ports to the world",
                target=target,
                tested_apis=["DescribeInstances", "DescribeSecurityGroups"],
                evidence=inst.get("findings") or [f"World-open sensitive ports: {ports}"],
                report_text=f"EC2 instance `{target}` has a public IP and world-open sensitive ingress ({ports}).",
                recommendation="Restrict security group ingress, remove 0.0.0.0/0 and ::/0 exposure on management/database ports, and prefer private administration paths.",
                risk_note="A publicly reachable instance with world-open management or database ports increases the chance of remote compromise and follow-on lateral movement.",
                impact_type="initial_access",
            )
        elif inst.get("public_ip") and inst.get("world_open_ports"):
            ports = ", ".join(inst.get("world_open_ports")[:10])
            _append_normalized_finding(
                findings,
                service="ec2",
                category="public_network_exposure",
                severity="HIGH",
                title="EC2 instance has a public IP and world-open ingress",
                target=target,
                tested_apis=["DescribeInstances", "DescribeSecurityGroups"],
                evidence=inst.get("findings") or [f"World-open ports: {ports}"],
                report_text=f"EC2 instance `{target}` has a public IP and world-open ingress defined in its security groups.",
                recommendation="Tighten security groups and limit direct internet exposure to only explicitly required ports and sources.",
                risk_note="Internet-reachable instances widen the initial access surface and can support lateral movement after compromise.",
                impact_type="initial_access",
            )
        elif inst.get("public_ip"):
            _append_normalized_finding(
                findings,
                service="ec2",
                category="public_ip",
                severity="MEDIUM",
                title="EC2 instance has a public IP address",
                target=target,
                tested_apis=["DescribeInstances"],
                evidence=inst.get("findings") or ["Instance has a public IP address."],
                report_text=f"EC2 instance `{target}` has a public IP address.",
                recommendation="Prefer private subnets or tightly restrict internet-facing instances to approved use cases.",
                risk_note="A public IP increases the reachable surface area of the instance.",
                impact_type="initial_access",
            )
        if inst.get("iam_instance_profile"):
            _append_normalized_finding(
                findings,
                service="ec2",
                category="instance_profile_attached",
                severity="MEDIUM",
                title="EC2 instance has an attached IAM instance profile",
                target=target,
                tested_apis=["DescribeInstances"],
                evidence=inst.get("findings") or [f"Attached instance profile: {inst.get('iam_instance_profile')}"],
                report_text=f"EC2 instance `{target}` has an attached IAM instance profile, which could expand blast radius if the host is compromised.",
                recommendation="Review attached instance roles and keep them minimal necessary scope; avoid placing broad roles on internet-exposed workloads.",
                risk_note="Compromise of an instance with an attached role can lead to credential theft and broader access expansion.",
                impact_type="lateral_access_expansion",
            )
        if inst.get("imdsv1_enabled"):
            sev = "HIGH" if inst.get("public_ip") and inst.get("iam_instance_profile") else "MEDIUM"
            _append_normalized_finding(
                findings,
                service="ec2",
                category="imdsv1_enabled",
                severity=sev,
                title="EC2 instance has IMDSv1 enabled (HttpTokens=optional)",
                target=target,
                tested_apis=["DescribeInstances"],
                evidence=[f"MetadataOptions.HttpTokens=optional on {target}"] + ([f"Instance profile: {inst.get('iam_instance_profile')}"] if inst.get("iam_instance_profile") else []),
                report_text=f"EC2 instance `{target}` allows IMDSv1 (HttpTokens=optional). An SSRF vulnerability on this host can retrieve instance role credentials from http://169.254.169.254 without requiring a session token (UNC2903 / Capital One pattern).",
                recommendation="Enforce IMDSv2 by setting HttpTokens=required via modify-instance-metadata-options. This blocks SSRF-based credential theft from the metadata service.",
                risk_note="IMDSv1 combined with an instance profile and any SSRF vector enables unauthenticated credential theft and lateral movement.",
                impact_type="credential_theft",
            )

    # IAM
    non_service_roles = [
        r for r in ((workspace.get("iam_role_audit") or {}).get("roles") or [])
        if isinstance(r, dict) and not _is_service_linked_role_name(r.get("role_name"))
    ]
    pivot_roles = [
        r for r in non_service_roles
        if str(r.get("assume_path_confidence") or "").upper() in {"CONFIRMED", "HIGH", "MEDIUM"}
    ]

    passrole_actions = _matching_covering_actions(workspace, ["iam:PassRole"])
    if passrole_actions:
        evidence = [f"Allowed action: {x}" for x in passrole_actions[:10]]
        if pivot_roles:
            evidence.extend([
                f"Related role candidate: {r.get('role_name') or r.get('role_arn')} ({r.get('assume_path_confidence')})"
                for r in pivot_roles[:5]
            ])
        _append_normalized_finding(
            findings,
            service="iam",
            category="passrole_capability",
            severity="HIGH" if pivot_roles else "MEDIUM",
            title="iam:PassRole is present in the effective permissions",
            target=None,
            tested_apis=["policy_analysis"],
            evidence=evidence,
            report_text="Effective permissions include `iam:PassRole`, which is a common building block for service-mediated access expansion when combined with create/update permissions on compute or orchestration services.",
            recommendation="Scope iam:PassRole to only explicitly approved roles and services, and review every role that can be passed.",
            risk_note="PassRole can allow the principal to attach a more sensitive role to a service and then pivot through that service.",
            impact_type="service_access_expansion",
            source="policy_analysis",
            tested=False,
        )

    assume_actions = _matching_covering_actions(workspace, ["sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity"])
    if assume_actions and pivot_roles:
        _append_normalized_finding(
            findings,
            service="sts",
            category="assumerole_path",
            severity="HIGH" if any(str(r.get("assume_path_confidence") or "").upper() in {"CONFIRMED", "HIGH"} for r in pivot_roles) else "MEDIUM",
            title="Role-assumption path is supported by effective permissions and trust analysis",
            target=None,
            tested_apis=["policy_analysis", "GetRole"],
            evidence=[f"Allowed action: {x}" for x in assume_actions[:10]] + [
                f"Role candidate: {r.get('role_name') or r.get('role_arn')} ({r.get('assume_path_confidence')})"
                for r in pivot_roles[:10]
            ],
            report_text="The effective permissions include role-assumption capability and the role audit identified one or more practical assume-role paths.",
            recommendation="Tighten sts:AssumeRole permissions and review trust policies on all pivot candidate roles.",
            risk_note="Successful role assumption can enable lateral movement and, depending on the target role, access expansion.",
            impact_type="lateral_access_expansion",
            source="policy_analysis",
            tested=False,
        )

    secret_read_actions = _matching_covering_actions(workspace, ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"])
    if secret_read_actions:
        secret_targets = (((workspace.get("policy_resource_followup") or {}).get("followup_summary") or {}).get("secret_targets_count") or 0)
        _append_normalized_finding(
            findings,
            service="secretsmanager",
            category="secret_value_read_capability",
            severity="HIGH" if secret_targets else "MEDIUM",
            title="Secret-value read capability is present in the effective permissions",
            target=None,
            tested_apis=["policy_analysis"],
            evidence=[f"Allowed action: {x}" for x in secret_read_actions[:10]] + ([f"Immediate secret targets observed: {secret_targets}"] if secret_targets else []),
            report_text="The effective permissions include Secrets Manager secret-value read capability, which can directly expose credentials or application secrets.",
            recommendation="Scope secret read permissions to the smallest required secret set and prefer explicit ARNs over wildcards.",
            risk_note="Direct secret-value access can lead to credential theft and rapid broader access expansion into other AWS or application components.",
            impact_type="sensitive_data_access",
            source="policy_analysis",
            tested=False,
        )

    kms_decrypt_actions = _matching_covering_actions(workspace, ["kms:Decrypt"])
    if kms_decrypt_actions:
        explicit_kms_targets = len(((service_plan.get("kms") or {}).get("explicit_targets") or []))
        _append_normalized_finding(
            findings,
            service="kms",
            category="kms_decrypt_capability",
            severity="HIGH" if explicit_kms_targets else "MEDIUM",
            title="KMS decrypt capability is present in the effective permissions",
            target=None,
            tested_apis=["policy_analysis"],
            evidence=[f"Allowed action: {x}" for x in kms_decrypt_actions[:10]] + ([f"Explicit KMS targets observed: {explicit_kms_targets}"] if explicit_kms_targets else []),
            report_text="The effective permissions include `kms:Decrypt`, which can enable access to encrypted data, secrets, or configuration values when paired with ciphertext access.",
            recommendation="Limit kms:Decrypt to explicitly required keys and applications only.",
            risk_note="KMS decrypt rights can unlock otherwise protected data and amplify the impact of other read access.",
            impact_type="sensitive_data_access",
            source="policy_analysis",
            tested=False,
        )

    lambda_invoke_actions = _matching_covering_actions(workspace, ["lambda:InvokeFunction", "lambda:InvokeAsync", "lambda:InvokeFunctionUrl"])
    if lambda_invoke_actions:
        lambda_total = len(((service_results.get("lambda") or {}).get("functions") or []))
        _append_normalized_finding(
            findings,
            service="lambda",
            category="invoke_capability",
            severity="MEDIUM" if lambda_total else "LOW",
            title="Lambda invoke capability is present in the effective permissions",
            target=None,
            tested_apis=["policy_analysis"],
            evidence=[f"Allowed action: {x}" for x in lambda_invoke_actions[:10]] + ([f"Discovered Lambda targets: {lambda_total}"] if lambda_total else []),
            report_text="The effective permissions include Lambda invoke capability. Depending on target function behavior, this may expose sensitive workflows or chained execution paths.",
            recommendation="Limit Lambda invoke permissions to explicitly approved functions and review any functions that broker sensitive operations.",
            risk_note="Invoking sensitive or automation-oriented functions can expose data or trigger downstream actions under a different trust boundary.",
            impact_type="code_execution",
            source="policy_analysis",
            tested=False,
        )

    return findings


def _policy_external_accounts(policy_doc: Any, account_id_hint: Optional[str]) -> Tuple[bool, List[str]]:
    doc = parse_json_maybe(policy_doc)
    if not doc:
        return (False, ["no_policy"])
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    reasons: List[str] = []
    external = False
    for st in statements:
        if not isinstance(st, dict):
            continue
        if str(st.get("Effect") or "").upper() != "ALLOW":
            continue
        principal = st.get("Principal")
        aws_principals: List[str] = []
        if principal == "*":
            aws_principals = ["*"]
        elif isinstance(principal, dict):
            aws_val = principal.get("AWS")
            if isinstance(aws_val, str):
                aws_principals = [aws_val]
            elif isinstance(aws_val, list):
                aws_principals = [x for x in aws_val if isinstance(x, str)]
        for p in aws_principals:
            if p == "*":
                external = True
                reasons.append("wildcard_principal")
                continue
            if account_id_hint and account_id_hint in p:
                continue
            external = True
            reasons.append(f"external:{p}")
    return external, dedupe_keep_order(reasons or ["no_external"])



def _bucket_acl_public(acl: Dict[str, Any]) -> bool:
    for grant in acl.get("Grants", []) or []:
        if not isinstance(grant, dict):
            continue
        grantee = grant.get("Grantee") or {}
        if not isinstance(grantee, dict):
            continue
        uri = grantee.get("URI")
        if uri in (
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ):
            return True
    return False



def _detect_interesting_keys(keys: Sequence[str]) -> List[str]:
    hits: List[str] = []
    for key in keys:
        low = key.lower()
        if any(word in low for word in S3_KEYWORDS):
            hits.append(key)
    return hits


def _mask_secret_value(value: Any) -> str:
    if value is None:
        return ""
    s = str(value)
    if len(s) <= 8:
        return "***"
    return f"{s[:4]}***{s[-4:]}"


def _extract_sensitive_env_values(env_vars: Dict[str, Any]) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    for key, value in (env_vars or {}).items():
        if not isinstance(key, str):
            continue
        low = key.lower()
        if any(word in low for word in ENV_KEYWORDS):
            hits.append({
                "key": key,
                "value_masked": _mask_secret_value(value),
            })
    return hits


def _download_and_scan_lambda_code(code_url: str, *, max_bytes: int = 8_000_000) -> Tuple[List[Dict[str, str]], Optional[str]]:
    findings: List[Dict[str, str]] = []
    if not isinstance(code_url, str) or not code_url.startswith(("http://", "https://")):
        return findings, "missing_or_invalid_code_url"
    try:
        with urllib.request.urlopen(code_url, timeout=20) as resp:
            blob = resp.read(max_bytes + 1)
        if len(blob) > max_bytes:
            return findings, f"download_truncated_over_{max_bytes}_bytes"
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for member in zf.infolist():
                name = member.filename
                low = name.lower()
                if member.is_dir() or not low.endswith(LAMBDA_CODE_FILE_EXTENSIONS):
                    continue
                try:
                    text = zf.read(member).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for pattern in LAMBDA_SECRET_PATTERNS:
                    for match in pattern.finditer(text):
                        findings.append({
                            "file": name,
                            "match": _mask_secret_value(match.group(0)),
                        })
                        if len(findings) >= 20:
                            return findings, None
        return findings, None
    except Exception as exc:
        return findings, safe_aws_error(exc)



def _probe_s3(ctx, workspace: Dict[str, Any], bucket_targets: Sequence[str], reasons: Sequence[str]) -> Dict[str, Any]:
    session = ctx.session
    s3 = session.client("s3")
    max_buckets = env_int("CLOUDSCANNER_MAX_BUCKETS", 40)
    max_objects = env_int("CLOUDSCANNER_MAX_OBJECTS_PER_BUCKET", 30)
    allow_global_list = env_bool("CLOUDSCANNER_S3_ALLOW_LIST_BUCKETS", default=True)

    candidates = list(bucket_targets)
    errors: List[Dict[str, Any]] = []
    if allow_global_list:
        try:
            resp = s3.list_buckets()
            for bucket in resp.get("Buckets", []) or []:
                if isinstance(bucket, dict) and isinstance(bucket.get("Name"), str):
                    candidates.append(bucket["Name"])
        except Exception as exc:
            errors.append({"step": "list_buckets", "error": safe_aws_error(exc)})

    buckets: List[Dict[str, Any]] = []
    public_buckets = 0
    listable_buckets = 0
    unencrypted_buckets = 0
    missing_pab = 0
    interesting_hits = 0

    for bucket_name in dedupe_keep_order(candidates)[:max_buckets]:
        entry: Dict[str, Any] = {
            "bucket_name": bucket_name,
            "name": bucket_name,
            "public": False,
            "acl_public": False,
            "listable": False,
            "readable": False,
            "interesting_objects": [],
            "findings": [],
            "risk_level": "INFO",
        }
        try:
            status = s3.get_bucket_policy_status(Bucket=bucket_name)
            policy_public = bool((status.get("PolicyStatus") or {}).get("IsPublic"))
            entry["public"] = policy_public
            if policy_public:
                public_buckets += 1
                entry["findings"].append("Bucket policy status indicates public exposure.")
        except Exception as exc:
            entry["policy_status_error"] = safe_aws_error(exc)

        try:
            acl = s3.get_bucket_acl(Bucket=bucket_name)
            acl_public = _bucket_acl_public(acl)
            entry["acl_public"] = acl_public
            if acl_public:
                public_buckets += 1
                entry["findings"].append("Bucket ACL exposes the bucket publicly.")
        except Exception as exc:
            entry["acl_error"] = safe_aws_error(exc)

        try:
            s3.get_public_access_block(Bucket=bucket_name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            entry["public_access_block_error"] = safe_aws_error(exc)
            if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                missing_pab += 1
                entry["findings"].append("Bucket-level PublicAccessBlock is missing.")
        except Exception as exc:
            entry["public_access_block_error"] = safe_aws_error(exc)

        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            entry["encryption_error"] = safe_aws_error(exc)
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                unencrypted_buckets += 1
                entry["findings"].append("Bucket encryption is not configured.")
        except Exception as exc:
            entry["encryption_error"] = safe_aws_error(exc)

        keys: List[str] = []
        try:
            resp = s3.list_objects_v2(Bucket=bucket_name, MaxKeys=max_objects)
            entry["listable"] = True
            listable_buckets += 1
            for obj in resp.get("Contents", []) or []:
                key = obj.get("Key")
                if isinstance(key, str):
                    keys.append(key)
        except Exception as exc:
            entry["list_objects_error"] = safe_aws_error(exc)

        interesting = _detect_interesting_keys(keys)
        if interesting:
            entry["readable"] = True
            entry["interesting_objects"] = interesting[:20]
            interesting_hits += len(interesting)
            entry["findings"].append("Interesting object names detected in bucket listing.")

        entry["risk_level"] = score_risk(
            high=bool(entry["public"] or entry["acl_public"]),
            medium=bool(entry["listable"] or interesting),
            low=bool(keys),
        )
        buckets.append(entry)

    return {
        "ok": True,
        "module": "s3_access_audit",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_reasons": list(reasons),
        "buckets": buckets,
        "summary": {
            "counts": {
                "public_buckets": public_buckets,
                "listable_buckets": listable_buckets,
                "unencrypted_buckets": unencrypted_buckets,
                "buckets_without_full_public_access_block": missing_pab,
                "interesting_object_keyword_hits": interesting_hits,
                "errors": len(errors),
            },
            "errors": errors[:20],
        },
        "notes": [
            "READ-only targeted S3 probing.",
            "Object bodies are not downloaded; only listing metadata and bucket posture are checked.",
        ],
        "error": None,
    }



def _probe_secrets(ctx, workspace: Dict[str, Any], secret_targets: Sequence[str], reasons: Sequence[str]) -> Dict[str, Any]:
    session = ctx.session
    regions = resolve_regions(ctx, "secretsmanager")
    max_secrets = env_int("CLOUDSCANNER_MAX_SECRETS", 80)
    account_id = get_account_id_from_workspace(workspace)
    secrets: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    explicit_by_region: Dict[str, Set[str]] = {}
    for arn in secret_targets:
        parsed = _parse_arn(arn)
        if not parsed or parsed["service"] != "secretsmanager":
            continue
        explicit_by_region.setdefault(parsed["region"] or session.region_name or "us-east-1", set()).add(arn)

    rotation_disabled = 0
    public_policy = 0
    external_policy = 0

    for region in regions:
        sm = session.client("secretsmanager", region_name=region)
        discovered: List[str] = []
        if region in explicit_by_region:
            discovered.extend(sorted(explicit_by_region[region]))
        else:
            try:
                paginator = sm.get_paginator("list_secrets")
                for page in paginator.paginate(PaginationConfig={"MaxItems": max_secrets, "PageSize": 100}):
                    for item in page.get("SecretList", []) or []:
                        arn = item.get("ARN")
                        if isinstance(arn, str):
                            if any(word in (item.get("Name") or "").lower() for word in SECRET_NAME_KEYWORDS):
                                discovered.append(arn)
                            elif len(discovered) < 10:
                                discovered.append(arn)
                    if len(discovered) >= max_secrets:
                        break
            except Exception as exc:
                errors.append({"region": region, "step": "list_secrets", "error": safe_aws_error(exc)})

        for arn in dedupe_keep_order(discovered)[:max_secrets]:
            entry: Dict[str, Any] = {
                "secret_arn": arn,
                "region": region,
                "rotation_enabled": None,
                "policy_public": None,
                "policy_external": None,
                "findings": [],
                "risk_level": "INFO",
            }
            try:
                meta = sm.describe_secret(SecretId=arn)
                entry["name"] = meta.get("Name")
                entry["rotation_enabled"] = meta.get("RotationEnabled")
                if meta.get("RotationEnabled") is False:
                    rotation_disabled += 1
                    entry["findings"].append("Rotation is disabled.")
            except Exception as exc:
                entry["describe_error"] = safe_aws_error(exc)

            try:
                pol = sm.get_resource_policy(SecretId=arn)
                policy_doc = pol.get("ResourcePolicy")
                is_public, public_reasons = policy_allows_public(policy_doc)
                is_external, external_reasons = _policy_external_accounts(policy_doc, account_id)
                entry["policy_public"] = is_public
                entry["policy_public_reasons"] = public_reasons
                entry["policy_external"] = is_external
                entry["policy_external_reasons"] = external_reasons
                if is_public:
                    public_policy += 1
                    entry["findings"].append("Resource policy contains wildcard principal.")
                elif is_external:
                    external_policy += 1
                    entry["findings"].append("Resource policy contains external principal(s).")
            except Exception as exc:
                entry["policy_error"] = safe_aws_error(exc)

            entry["risk_level"] = score_risk(
                high=bool(entry.get("policy_public")),
                medium=bool(entry.get("policy_external") or entry.get("rotation_enabled") is False),
                low=True,
            )
            secrets.append(entry)

    return {
        "ok": True,
        "module": "secrets_manager_audit",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_reasons": list(reasons),
        "secrets": secrets,
        "summary": {
            "counts": {
                "rotation_disabled": rotation_disabled,
                "public_policy_secrets": public_policy,
                "external_principal_policy_secrets": external_policy,
                "errors": len(errors),
            },
            "errors": errors[:20],
        },
        "notes": [
            "READ-only targeted Secrets Manager probing.",
            "Secret values are never retrieved; only metadata and resource policies are inspected.",
        ],
        "error": None,
    }



def _probe_lambda(ctx, workspace: Dict[str, Any], lambda_targets: Sequence[str], reasons: Sequence[str]) -> Dict[str, Any]:
    session = ctx.session
    regions = resolve_regions(ctx, "lambda")
    max_functions = env_int("CLOUDSCANNER_MAX_LAMBDAS", 80)
    account_id = get_account_id_from_workspace(workspace)
    functions: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    include_env_values = env_bool("CLOUDSCANNER_LAMBDA_CAPTURE_ENV_VALUES", default=True)
    download_code = env_bool("CLOUDSCANNER_LAMBDA_DOWNLOAD_CODE", default=True)

    public_policy = 0
    external_policy = 0
    public_urls = 0
    sensitive_env = 0
    sensitive_env_values = 0
    downloadable_packages = 0
    code_secret_hits = 0

    explicit_targets = set(lambda_targets)

    for region in regions:
        lam = session.client("lambda", region_name=region)
        discovered: List[Dict[str, Any]] = []
        try:
            paginator = lam.get_paginator("list_functions")
            for page in paginator.paginate(PaginationConfig={"MaxItems": max_functions, "PageSize": 50}):
                for item in page.get("Functions", []) or []:
                    if not isinstance(item, dict):
                        continue
                    arn = item.get("FunctionArn")
                    if explicit_targets and arn not in explicit_targets and len(discovered) >= 20:
                        continue
                    discovered.append(item)
                if len(discovered) >= max_functions:
                    break
        except Exception as exc:
            errors.append({"region": region, "step": "list_functions", "error": safe_aws_error(exc)})
            continue

        for item in discovered[:max_functions]:
            name = item.get("FunctionName")
            arn = item.get("FunctionArn")
            fn: Dict[str, Any] = {
                "name": name,
                "function_arn": arn,
                "region": region,
                "runtime": item.get("Runtime"),
                "last_modified": item.get("LastModified"),
                "enumeration_confirmed": True,
                "policy_public": False,
                "public_url": False,
                "findings": [],
                "risk_level": "INFO",
            }
            try:
                pol = lam.get_policy(FunctionName=name)
                policy_doc = pol.get("Policy")
                is_public, public_reasons = policy_allows_public(policy_doc)
                is_external, external_reasons = _policy_external_accounts(policy_doc, account_id)
                fn["policy_public"] = is_public
                fn["policy_public_reasons"] = public_reasons
                fn["policy_external"] = is_external
                fn["policy_external_reasons"] = external_reasons
                if is_public:
                    public_policy += 1
                    fn["findings"].append("Resource policy contains wildcard principal.")
                elif is_external:
                    external_policy += 1
                    fn["findings"].append("Resource policy contains external principal(s).")
            except Exception as exc:
                fn["policy_error"] = safe_aws_error(exc)

            try:
                cfg = lam.get_function_configuration(FunctionName=name)
                fn["execution_role_arn"] = cfg.get("Role")
                fn["memory_size"] = cfg.get("MemorySize")
                fn["timeout"] = cfg.get("Timeout")
                fn["handler"] = cfg.get("Handler")
                fn["package_type"] = cfg.get("PackageType")
                env_vars = (((cfg.get("Environment") or {}).get("Variables") or {}))
                sensitive_keys = [k for k in env_vars.keys() if any(word in k.lower() for word in ENV_KEYWORDS)]
                if sensitive_keys:
                    sensitive_env += 1
                    fn["sensitive_env_key_hints"] = sensitive_keys[:10]
                    fn["findings"].append("Environment variable key names suggest embedded secrets.")
                if include_env_values:
                    env_hits = _extract_sensitive_env_values(env_vars)
                    if env_hits:
                        sensitive_env_values += 1
                        fn["sensitive_env_values"] = env_hits[:10]
                        fn["findings"].append("Sensitive environment variable values are readable via GetFunctionConfiguration.")
            except Exception as exc:
                fn["configuration_error"] = safe_aws_error(exc)

            try:
                url_cfg = lam.get_function_url_config(FunctionName=name)
                auth_type = url_cfg.get("AuthType")
                fn["function_url"] = url_cfg.get("FunctionUrl")
                fn["function_url_auth_type"] = auth_type
                if fn.get("function_url") and auth_type == "NONE":
                    fn["public_url"] = True
                    public_urls += 1
                    fn["findings"].append("Function URL is public (AuthType=NONE).")
            except Exception as exc:
                fn["function_url_error"] = safe_aws_error(exc)

            if download_code:
                try:
                    gf = lam.get_function(FunctionName=name)
                    code = gf.get("Code") or {}
                    code_location = code.get("Location")
                    if code_location:
                        downloadable_packages += 1
                        fn["code_download_confirmed"] = True
                        fn["findings"].append("GetFunction returned a deployment package URL.")
                        code_findings, code_err = _download_and_scan_lambda_code(code_location)
                        if code_findings:
                            code_secret_hits += len(code_findings)
                            fn["code_secret_findings"] = code_findings
                            fn["findings"].append("Deployment package review found hardcoded secret-like material.")
                        if code_err:
                            fn["code_download_error"] = code_err
                except Exception as exc:
                    fn["get_function_error"] = safe_aws_error(exc)

            if fn.get("policy_public") or fn.get("public_url"):
                import base64
                _invoke_payloads = [
                    b'{}',
                    b'{"operation":"admin"}',
                    b'{"action":"info"}',
                ]
                _invoke_responses = []
                for _payload in _invoke_payloads:
                    try:
                        _resp = lam.invoke(
                            FunctionName=name,
                            InvocationType="RequestResponse",
                            Payload=_payload,
                        )
                        _body = _resp.get("Payload")
                        _body_str = _body.read().decode("utf-8", errors="replace") if _body else ""
                        _invoke_responses.append({
                            "payload_sent": _payload.decode(),
                            "status_code": _resp.get("StatusCode"),
                            "function_error": _resp.get("FunctionError"),
                            "response_body": _body_str,
                        })
                    except Exception as exc:
                        fn["invoke_error"] = safe_aws_error(exc)
                if _invoke_responses:
                    fn["invoke_responses"] = _invoke_responses
                    fn["findings"].append("Public function invoked successfully; responses captured.")

            fn["risk_level"] = score_risk(
                high=bool(fn.get("policy_public") or fn.get("public_url") or fn.get("sensitive_env_values") or fn.get("code_secret_findings")),
                medium=bool(fn.get("policy_external") or fn.get("sensitive_env_key_hints") or fn.get("code_download_confirmed")),
                low=True,
            )
            functions.append(fn)

    return {
        "ok": True,
        "module": "lambda_audit",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_reasons": list(reasons),
        "functions": functions,
        "summary": {
            "counts": {
                "functions_total": len(functions),
                "functions_with_public_policy": public_policy,
                "functions_with_external_policy": external_policy,
                "functions_with_public_url": public_urls,
                "functions_with_sensitive_env_keys": sensitive_env,
                "functions_with_sensitive_env_values": sensitive_env_values,
                "functions_with_downloadable_code": downloadable_packages,
                "code_secret_hits": code_secret_hits,
                "errors": len(errors),
            },
            "errors": errors[:20],
        },
        "notes": [
            "Read-only Lambda probing confirms actual Lambda visibility and configuration access even when IAM policy listing is denied.",
            "GetFunction may expose a temporary deployment package URL; deployment packages are scanned offline only.",
            "Functions with a public resource policy (Principal:*) or public URL are invoked with common payloads to capture live response data including flags.",
        ],
        "error": None,
    }


def _probe_kms(ctx, workspace: Dict[str, Any], kms_targets: Sequence[str], reasons: Sequence[str]) -> Dict[str, Any]:
    session = ctx.session
    regions = resolve_regions(ctx, "kms")
    max_keys = env_int("CLOUDSCANNER_MAX_KMS_KEYS", 80)
    include_policy = env_bool("CLOUDSCANNER_KMS_INCLUDE_KEY_POLICY", default=True)

    explicit_targets = set(kms_targets)
    keys: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    rotation_disabled = 0
    pending_deletion = 0
    public_policy = 0

    for region in regions:
        kms = session.client("kms", region_name=region)
        try:
            paginator = kms.get_paginator("list_keys")
            count = 0
            for page in paginator.paginate(PaginationConfig={"MaxItems": max_keys, "PageSize": 50}):
                for item in page.get("Keys", []) or []:
                    key_arn = item.get("KeyArn")
                    if explicit_targets and key_arn not in explicit_targets and count >= 20:
                        continue
                    key_id = item.get("KeyId")
                    if not key_id:
                        continue
                    entry: Dict[str, Any] = {
                        "region": region,
                        "key_id": key_id,
                        "key_arn": key_arn,
                        "findings": [],
                        "risk_level": "INFO",
                    }
                    try:
                        meta = kms.describe_key(KeyId=key_id).get("KeyMetadata") or {}
                        entry["key_manager"] = meta.get("KeyManager")
                        entry["key_state"] = meta.get("KeyState")
                        if entry.get("key_state") == "PendingDeletion":
                            pending_deletion += 1
                            entry["findings"].append("Key is pending deletion.")
                    except Exception as exc:
                        entry["describe_error"] = safe_aws_error(exc)

                    try:
                        rot = kms.get_key_rotation_status(KeyId=key_id)
                        entry["rotation_enabled"] = rot.get("KeyRotationEnabled")
                        if entry.get("key_manager") == "CUSTOMER" and entry.get("rotation_enabled") is False:
                            rotation_disabled += 1
                            entry["findings"].append("Key rotation is disabled.")
                    except Exception as exc:
                        entry["rotation_error"] = safe_aws_error(exc)

                    if include_policy:
                        try:
                            pol = kms.get_key_policy(KeyId=key_id, PolicyName="default")
                            policy_doc = pol.get("Policy")
                            is_public, public_reasons = policy_allows_public(policy_doc)
                            entry["policy_public"] = is_public
                            entry["policy_public_reasons"] = public_reasons
                            if is_public:
                                public_policy += 1
                                entry["findings"].append("Key policy contains wildcard principal.")
                        except Exception as exc:
                            entry["policy_error"] = safe_aws_error(exc)

                    entry["risk_level"] = score_risk(
                        high=bool(entry.get("policy_public") or entry.get("key_state") == "PendingDeletion"),
                        medium=bool(entry.get("rotation_enabled") is False and entry.get("key_manager") == "CUSTOMER"),
                        low=True,
                    )
                    keys.append(entry)
                    count += 1
                    if count >= max_keys:
                        break
                if count >= max_keys:
                    break
        except Exception as exc:
            errors.append({"region": region, "step": "list_keys", "error": safe_aws_error(exc)})

    return {
        "ok": True,
        "module": "kms_key_audit",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_reasons": list(reasons),
        "keys": keys,
        "summary": {
            "counts": {
                "keys_total": len(keys),
                "customer_keys_rotation_disabled": rotation_disabled,
                "keys_pending_deletion": pending_deletion,
                "keys_with_public_policy": public_policy if include_policy else None,
                "errors": len(errors),
            },
            "errors": errors[:20],
        },
        "notes": [
            "READ-only targeted KMS probing.",
            "No encrypt/decrypt operations are performed.",
        ],
        "error": None,
    }



def _extract_world_open_ports(ip_permissions: Sequence[Dict[str, Any]]) -> Tuple[List[str], List[str], bool]:
    world_open_ports: List[str] = []
    world_open_management: List[str] = []
    world_open_all = False

    for perm in ip_permissions or []:
        if not isinstance(perm, dict):
            continue
        peers: List[str] = []
        for rng in perm.get("IpRanges", []) or []:
            cidr = rng.get("CidrIp") if isinstance(rng, dict) else None
            if cidr == "0.0.0.0/0":
                peers.append(cidr)
        for rng in perm.get("Ipv6Ranges", []) or []:
            cidr = rng.get("CidrIpv6") if isinstance(rng, dict) else None
            if cidr == "::/0":
                peers.append(cidr)
        if not peers:
            continue

        proto = perm.get("IpProtocol")
        if proto == "-1":
            world_open_all = True
            world_open_ports.extend([f"all ({peer})" for peer in peers])
            world_open_management.extend([f"all ({peer})" for peer in peers])
            continue

        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        if isinstance(from_port, int) and isinstance(to_port, int):
            labels: List[str] = []
            mgmt_labels: List[str] = []
            for port, name in SENSITIVE_WORLD_PORTS.items():
                if from_port <= port <= to_port:
                    label = f"{port}/{name}"
                    labels.append(label)
                    mgmt_labels.append(label)
            if not labels:
                labels = [str(from_port) if from_port == to_port else f"{from_port}-{to_port}"]
            for peer in peers:
                world_open_ports.extend([f"{label} ({peer})" for label in labels])
                world_open_management.extend([f"{label} ({peer})" for label in mgmt_labels])
        else:
            desc = str(proto or "unknown")
            for peer in peers:
                world_open_ports.append(f"protocol={desc} ({peer})")

    return dedupe_keep_order(world_open_ports), dedupe_keep_order(world_open_management), world_open_all


def _probe_ec2(ctx, workspace: Dict[str, Any], ec2_targets: Sequence[str], reasons: Sequence[str]) -> Dict[str, Any]:
    session = ctx.session
    regions = resolve_regions(ctx, "ec2")
    max_instances = env_int("CLOUDSCANNER_MAX_EC2_INSTANCES", 120)
    instances: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    public_ip = 0
    with_instance_profile = 0
    world_open_sg = 0
    public_mgmt = 0
    imdsv1_instances = 0
    exposure_indicators = 0

    explicit_ids = set(ec2_targets)

    for region in regions:
        ec2 = session.client("ec2", region_name=region)
        try:
            paginator = ec2.get_paginator("describe_instances")
            count = 0
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []) or []:
                    for item in reservation.get("Instances", []) or []:
                        instance_id = item.get("InstanceId")
                        if explicit_ids and instance_id not in explicit_ids and count >= 30:
                            continue
                        entry = {
                            "instance_id": instance_id,
                            "region": region,
                            "state": ((item.get("State") or {}).get("Name")),
                            "public_ip": item.get("PublicIpAddress"),
                            "private_ip": item.get("PrivateIpAddress"),
                            "iam_instance_profile": ((item.get("IamInstanceProfile") or {}).get("Arn")),
                            "security_group_ids": [sg.get("GroupId") for sg in (item.get("SecurityGroups") or []) if isinstance(sg, dict) and sg.get("GroupId")],
                            "world_open_ports": [],
                            "world_open_management_ports": [],
                            "world_open_all_ports": False,
                            "findings": [],
                            "risk_level": "INFO",
                        }
                        if entry.get("public_ip"):
                            public_ip += 1
                            entry["findings"].append("Instance has a public IP address.")
                        if entry.get("iam_instance_profile"):
                            with_instance_profile += 1
                            entry["findings"].append(f"Instance has an attached IAM instance profile: {entry.get('iam_instance_profile')}")

                        http_tokens = ((item.get("MetadataOptions") or {}).get("HttpTokens"))
                        entry["imdsv1_enabled"] = (http_tokens == "optional")
                        if entry["imdsv1_enabled"]:
                            imdsv1_instances += 1
                            entry["findings"].append("IMDSv1 enabled (HttpTokens=optional) — SSRF-to-credential-theft risk (UNC2903 pattern).")

                        sg_ids = entry.get("security_group_ids") or []
                        if sg_ids:
                            try:
                                sg_resp = ec2.describe_security_groups(GroupIds=sg_ids)
                                permissions: List[Dict[str, Any]] = []
                                for sg in sg_resp.get("SecurityGroups", []) or []:
                                    if isinstance(sg, dict):
                                        permissions.extend([p for p in (sg.get("IpPermissions") or []) if isinstance(p, dict)])
                                world_ports, world_mgmt, world_all = _extract_world_open_ports(permissions)
                                entry["world_open_ports"] = world_ports
                                entry["world_open_management_ports"] = world_mgmt
                                entry["world_open_all_ports"] = world_all
                                if world_ports:
                                    world_open_sg += 1
                                    entry["findings"].append(
                                        "Security groups allow world ingress: " + ", ".join(world_ports[:10])
                                    )
                                if entry.get("public_ip") and world_mgmt:
                                    public_mgmt += 1
                            except Exception as exc:
                                entry["security_group_error"] = safe_aws_error(exc)

                        if instance_id:
                            try:
                                ud_resp = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
                                ud_b64 = (ud_resp.get("UserData") or {}).get("Value")
                                if ud_b64:
                                    import base64
                                    ud_text = base64.b64decode(ud_b64).decode("utf-8", errors="replace")
                                    entry["user_data_present"] = True
                                    hits = []
                                    for line in ud_text.splitlines():
                                        ll = line.lower()
                                        if any(kw in ll for kw in ENV_KEYWORDS):
                                            hits.append(line.strip()[:200])
                                    if hits:
                                        entry["user_data_sensitive_lines"] = hits[:20]
                                        entry["findings"].append(f"UserData contains {len(hits)} line(s) with sensitive keywords.")
                                        entry["risk_level"] = "HIGH"
                                else:
                                    entry["user_data_present"] = False
                            except Exception as exc:
                                entry["user_data_error"] = safe_aws_error(exc)

                        if entry.get("public_ip") or entry.get("iam_instance_profile") or entry.get("world_open_ports"):
                            exposure_indicators += 1

                        entry["risk_level"] = score_risk(
                            high=bool(
                                (entry.get("public_ip") and (entry.get("world_open_management_ports") or entry.get("world_open_all_ports")))
                                or (entry.get("imdsv1_enabled") and entry.get("iam_instance_profile") and entry.get("public_ip"))
                            ),
                            medium=bool(entry.get("public_ip") or entry.get("iam_instance_profile") or entry.get("world_open_ports") or entry.get("imdsv1_enabled")),
                            low=True,
                        )
                        instances.append(entry)
                        count += 1
                        if count >= max_instances:
                            break
                    if count >= max_instances:
                        break
                if count >= max_instances:
                    break
        except Exception as exc:
            errors.append({"region": region, "step": "describe_instances", "error": safe_aws_error(exc)})

    return {
        "ok": True,
        "module": "ec2_inventory",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_reasons": list(reasons),
        "instances": instances,
        "summary": {
            "counts": {
                "instances_total": len(instances),
                "instances_with_public_ip": public_ip,
                "instances_with_instance_profile": with_instance_profile,
                "instances_with_imdsv1": imdsv1_instances,
                "instances_with_world_open_security_group": world_open_sg,
                "instances_publicly_reachable_sensitive_ports": public_mgmt,
                "instances_with_exposure_indicators": exposure_indicators,
                "instances_risky_exposure": exposure_indicators,
                "instances_with_sensitive_user_data": sum(1 for i in instances if i.get("user_data_sensitive_lines")),
                "errors": len(errors),
            },
            "errors": errors[:20],
        },
        "notes": [
            "READ-only targeted EC2 probing.",
            "DescribeInstances, DescribeSecurityGroups, and DescribeInstanceAttribute (userData) are used; no instance actions are executed.",
        ],
        "error": None,
    }


def run(ctx) -> Dict[str, Any]:
    workspace = _get_workspace(ctx)
    explicit_targets = _extract_explicit_targets(workspace)

    service_plan: Dict[str, Dict[str, Any]] = {}
    services: Dict[str, Dict[str, Any]] = {}
    probed: List[str] = []

    s3_should, s3_reasons = _should_probe(workspace, "s3", explicit_targets["s3_buckets"])
    if not s3_should and env_bool("CLOUDSCANNER_S3_OPPORTUNISTIC_PROBE", default=True):
        s3_should = True
        s3_reasons = dedupe_keep_order(list(s3_reasons) + ["opportunistic_s3_read_probe"])
    s3_reasons = s3_reasons or ["no_strong_signal_or_explicit_targets"]
    service_plan["s3"] = {"should_probe": s3_should, "reasons": s3_reasons, "explicit_targets": explicit_targets["s3_buckets"][:20]}
    if s3_should:
        services["s3"] = _probe_s3(ctx, workspace, explicit_targets["s3_buckets"], s3_reasons)
        probed.append("s3")

    sec_should, sec_reasons = _should_probe(workspace, "secretsmanager", explicit_targets["secret_arns"])
    if not sec_should and env_bool("CLOUDSCANNER_SECRETS_OPPORTUNISTIC_PROBE", default=True):
        sec_should = True
        sec_reasons = dedupe_keep_order(list(sec_reasons) + ["opportunistic_secrets_read_probe"])
    sec_reasons = sec_reasons or ["no_strong_signal_or_explicit_targets"]
    service_plan["secretsmanager"] = {"should_probe": sec_should, "reasons": sec_reasons, "explicit_targets": explicit_targets["secret_arns"][:20]}
    if sec_should:
        services["secretsmanager"] = _probe_secrets(ctx, workspace, explicit_targets["secret_arns"], sec_reasons)
        probed.append("secretsmanager")

    lam_should, lam_reasons = _should_probe(workspace, "lambda", explicit_targets["lambda_arns"])
    if not lam_should and env_bool("CLOUDSCANNER_LAMBDA_OPPORTUNISTIC_PROBE", default=True):
        lam_should = True
        lam_reasons = dedupe_keep_order(list(lam_reasons) + ["opportunistic_lambda_read_probe"]) 
    lam_reasons = lam_reasons or ["no_strong_signal_or_explicit_targets"]
    service_plan["lambda"] = {"should_probe": lam_should, "reasons": lam_reasons, "explicit_targets": explicit_targets["lambda_arns"][:20]}
    if lam_should:
        services["lambda"] = _probe_lambda(ctx, workspace, explicit_targets["lambda_arns"], lam_reasons)
        probed.append("lambda")

    kms_should, kms_reasons = _should_probe(workspace, "kms", explicit_targets["kms_arns"])
    if not kms_should and env_bool("CLOUDSCANNER_KMS_OPPORTUNISTIC_PROBE", default=True):
        kms_should = True
        kms_reasons = dedupe_keep_order(list(kms_reasons) + ["opportunistic_kms_read_probe"])
    kms_reasons = kms_reasons or ["no_strong_signal_or_explicit_targets"]
    service_plan["kms"] = {"should_probe": kms_should, "reasons": kms_reasons, "explicit_targets": explicit_targets["kms_arns"][:20]}
    if kms_should:
        services["kms"] = _probe_kms(ctx, workspace, explicit_targets["kms_arns"], kms_reasons)
        probed.append("kms")

    ec2_followup = (((workspace.get("policy_resource_followup") or {}).get("followup_summary") or {}).get("ec2_describe_allowed"))
    ec2_should, ec2_reasons = _should_probe(workspace, "ec2", explicit_targets["ec2_instance_ids"])
    if ec2_followup:
        ec2_should = True
        ec2_reasons = dedupe_keep_order(list(ec2_reasons) + ["followup:ec2_describe_allowed"])
    if not ec2_should and env_bool("CLOUDSCANNER_EC2_OPPORTUNISTIC_PROBE", default=True):
        ec2_should = True
        ec2_reasons = dedupe_keep_order(list(ec2_reasons) + ["opportunistic_ec2_read_probe"])
    ec2_reasons = ec2_reasons or ["no_strong_signal_or_explicit_targets"]
    service_plan["ec2"] = {"should_probe": ec2_should, "reasons": ec2_reasons, "explicit_targets": explicit_targets["ec2_instance_ids"][:20]}
    if ec2_should:
        services["ec2"] = _probe_ec2(ctx, workspace, explicit_targets["ec2_instance_ids"], ec2_reasons)
        probed.append("ec2")

    findings = _build_normalized_findings(workspace, services, service_plan)
    severity_counts = {
        "HIGH": sum(1 for f in findings if f.get("severity") == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.get("severity") == "LOW"),
        "INFO": sum(1 for f in findings if f.get("severity") == "INFO"),
    }
    skipped = sorted([svc for svc, plan in service_plan.items() if not plan.get("should_probe")])

    return {
        "ok": True,
        "module": "targeted_service_probing",
        "started_at": now_iso_utc(),
        "completed_at": now_iso_utc(),
        "probe_plan": service_plan,
        "services_probed": probed,
        "services_skipped": skipped,
        "services": services,
        "findings": findings,
        "summary": {
            "services_considered": sorted(service_plan.keys()),
            "services_probed": probed,
            "services_skipped": skipped,
            "counts": {
                "services_probed": len(probed),
                "services_skipped": len(skipped),
                "findings_total": len(findings),
                "high_severity_findings": severity_counts["HIGH"],
                "medium_severity_findings": severity_counts["MEDIUM"],
                "explicit_s3_targets": len(explicit_targets["s3_buckets"]),
                "explicit_secret_targets": len(explicit_targets["secret_arns"]),
                "explicit_lambda_targets": len(explicit_targets["lambda_arns"]),
                "explicit_kms_targets": len(explicit_targets["kms_arns"]),
                "explicit_ec2_targets": len(explicit_targets["ec2_instance_ids"]),
            },
            "severity_counts": severity_counts,
        },
        "notes": [
            "Targeted service probing only runs for services with meaningful policy signals or explicit resource targets.",
            "All AWS API calls executed by this module are read-only; function invocation, decrypt operations, and state changes are intentionally avoided.",
            "Lambda probing can confirm enumeration, configuration access, function URL posture, and deployment-package access without requiring IAM policy listing rights.",
        ],
        "error": None,
    }


def handler(ctx) -> None:
    res = run(ctx)
    if not isinstance(getattr(ctx, "last_result", None), dict):
        ctx.last_result = {}
    workspace: Dict[str, Any] = ctx.last_result
    workspace["targeted_service_probing"] = res
    workspace["targeted_service_probing_ok"] = res.get("ok", True)
    workspace["targeted_service_probing_error"] = res.get("error")

    service_map = {
        "s3": "s3_access_audit",
        "secretsmanager": "secrets_manager_audit",
        "lambda": "lambda_audit",
        "kms": "kms_key_audit",
        "ec2": "ec2_inventory",
    }
    for service_name, workspace_key in service_map.items():
        if service_name in (res.get("services") or {}):
            workspace[workspace_key] = res["services"][service_name]
            workspace[f"{workspace_key}_ok"] = res["services"][service_name].get("ok", True)
            workspace[f"{workspace_key}_error"] = res["services"][service_name].get("error")


menu_item = MenuItem(
    key="5",
    title="Targeted service probing",
    handler=handler,
    help="Risk-driven read-only service probing for S3, Secrets Manager, Lambda, KMS, and EC2.",
)
