from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data


def bullet(items: List[str]) -> str:
    if not items:
        return "- None"
    return "\n".join(f"- {item}" for item in items)


def dedupe(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def extract_count(obj: Any) -> int:
    if isinstance(obj, dict):
        if isinstance(obj.get("count"), int):
            return obj["count"]
        items = obj.get("items")
        if isinstance(items, list):
            return len(items)
        return 0
    if isinstance(obj, list):
        return len(obj)
    return 0


def extract_items(obj: Any) -> List[Any]:
    if isinstance(obj, dict):
        items = obj.get("items")
        if isinstance(items, list):
            return items
        return []
    if isinstance(obj, list):
        return obj
    return []


def counts_from_module(module_obj: Any) -> Dict[str, Any]:
    if not isinstance(module_obj, dict):
        return {}
    summary = module_obj.get("summary") or {}
    if not isinstance(summary, dict):
        return {}
    counts = summary.get("counts") or {}
    return counts if isinstance(counts, dict) else {}


def is_service_linked_role(name: str, role_arn: str = "") -> bool:
    return (
        (isinstance(role_arn, str) and ":role/aws-service-role/" in role_arn)
        or (isinstance(name, str) and name.startswith("AWSServiceRoleFor"))
    )


def yes_no(value: Any) -> str:
    return "YES" if bool(value) else "NO"


def count_pivots_by_confidence(pivot_candidates: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "UNKNOWN": 0}
    for item in pivot_candidates:
        if not isinstance(item, dict):
            continue
        confidence = str(item.get("confidence") or "UNKNOWN").upper()
        if confidence not in counts:
            confidence = "UNKNOWN"
        counts[confidence] += 1
    return counts


def collect_role_side_secret_arns(role_entries: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    for r in role_entries:
        if not isinstance(r, dict):
            continue

        role_name = r.get("role_name") or r.get("role_arn") or "unknown-role"
        role_arn = r.get("role_arn") or ""
        if is_service_linked_role(role_name, role_arn):
            continue

        summary = r.get("role_permission_summary", {}) or {}
        samples = summary.get("resource_samples", []) or []
        for s in samples:
            if isinstance(s, str) and s.startswith("arn:aws:secretsmanager:") and s not in out:
                out.append(s)
    return out


def collect_role_side_interesting_services(role_entries: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for r in role_entries:
        if not isinstance(r, dict):
            continue

        role_name = r.get("role_name") or r.get("role_arn") or "unknown-role"
        role_arn = r.get("role_arn") or ""
        if is_service_linked_role(role_name, role_arn):
            continue

        summary = r.get("role_permission_summary", {}) or {}
        services = summary.get("interesting_services", []) or []
        if services:
            out[role_name] = services
    return out


def detect_interesting_s3_objects(s3_targets: List[Dict[str, Any]]) -> List[str]:
    hits: List[str] = []
    keywords = ("flag", "secret", "password", "credential", "token", "key", "backup")
    for bucket in s3_targets:
        if not isinstance(bucket, dict):
            continue
        bucket_name = bucket.get("bucket_name", "unknown-bucket")
        for obj in bucket.get("sample_objects", []) or []:
            if not isinstance(obj, dict):
                continue
            key = obj.get("key")
            if not isinstance(key, str):
                continue
            lower = key.lower()
            if any(k in lower for k in keywords):
                hits.append(f"{bucket_name}/{key}")
    return hits


def derive_followup_findings(
    followup: Dict[str, Any]
) -> Tuple[List[str], List[str], List[str], List[str], List[str], List[str]]:
    confirmed: List[str] = []
    paths: List[str] = []
    recs: List[str] = []

    immediate_access: List[str] = []
    likely_pivots: List[str] = []
    post_pivot_blast: List[str] = []

    resources = followup.get("resources", {}) or {}
    s3_targets = resources.get("s3", []) or []
    iam_block = resources.get("iam", {}) or {}
    role_entries = iam_block.get("roles", []) or []
    pivot_candidates = followup.get("pivot_candidates", []) or []

    readable_buckets = []
    for bucket in s3_targets:
        if not isinstance(bucket, dict):
            continue
        bucket_name = bucket.get("bucket_name", "unknown-bucket")
        access = bucket.get("access", {}) or {}
        if access.get("list_bucket_allowed"):
            readable_buckets.append(bucket_name)

    if readable_buckets:
        confirmed.append(
            f"Immediate S3 access confirmed: {len(readable_buckets)} readable bucket(s) were enumerated."
        )
        for b in readable_buckets:
            immediate_access.append(f"S3 bucket `{b}` is listable by the current user.")
        paths.append(
            "The current principal can directly enumerate at least one S3 bucket, enabling immediate data discovery."
        )
        recs.append(
            "Review direct S3 read access and restrict bucket/object permissions to only required principals."
        )

    interesting_objects = detect_interesting_s3_objects(s3_targets)
    if interesting_objects:
        confirmed.append(
            f"High-value S3 artifact(s) were discovered during enumeration, including {len(interesting_objects)} interesting object(s)."
        )
        for item in interesting_objects[:10]:
            immediate_access.append(f"Interesting object discovered: `{item}`")
        paths.append(
            "Named high-value objects in S3 may expose sensitive data, proof files, backups, or credentials."
        )
        recs.append(
            "Review accessible S3 object inventory and remove or further restrict sensitive artifacts."
        )

    high_pivots = []
    medium_pivots = []
    lower_conf_pivots = []
    for p in pivot_candidates:
        if not isinstance(p, dict):
            continue
        role_name = p.get("role_name") or p.get("role_arn") or "unknown-role"
        confidence = (p.get("confidence") or "LOW").upper()
        reasons = p.get("reasons", []) or []
        reason_text = "; ".join(reasons) if reasons else "no reason captured"
        line = f"`{role_name}` ({confidence}) — {reason_text}"
        if confidence == "HIGH":
            high_pivots.append(line)
        elif confidence == "MEDIUM":
            medium_pivots.append(line)
        else:
            lower_conf_pivots.append(line)

    if high_pivots:
        confirmed.append(f"{len(high_pivots)} high-confidence role pivot candidate(s) were identified.")
        likely_pivots.extend(high_pivots[:10])
        paths.append(
            "A same-account trusted role may provide a practical lateral movement path if role assumption succeeds."
        )
        recs.append(
            "Review role trust policies and explicitly validate whether the trusted principal should still be allowed to assume the role."
        )

    if medium_pivots:
        confirmed.append(f"{len(medium_pivots)} medium-confidence role pivot candidate(s) were identified.")
        likely_pivots.extend(medium_pivots[:10])
        paths.append(
            "Cross-account or broader trust relationships increase exposure surface and should be treated as trust-boundary exposure."
        )
        recs.append(
            "Review cross-account and broad trust relationships and remove any that are not operationally required."
        )

    if lower_conf_pivots:
        likely_pivots.extend(lower_conf_pivots[:10])

    role_side_secret_arns = collect_role_side_secret_arns(role_entries)
    role_side_services = collect_role_side_interesting_services(role_entries)

    if role_side_secret_arns:
        confirmed.append(
            f"Role-side policy analysis identified {len(role_side_secret_arns)} Secrets Manager resource(s) reachable after a successful role pivot."
        )
        for secret_arn in role_side_secret_arns[:10]:
            post_pivot_blast.append(f"Post-pivot secret target: `{secret_arn}`")
        paths.append(
            "A successful role pivot could expose Secrets Manager metadata or secret values beyond the current user's direct permissions."
        )
        recs.append(
            "Review role-attached policies for secret access and scope Secrets Manager permissions to only required secrets."
        )

    for role_name, services in role_side_services.items():
        svc_text = ", ".join(services)
        post_pivot_blast.append(f"`{role_name}` exposes additional services post-pivot: {svc_text}")

    if role_side_services:
        confirmed.append(
            "Role-side blast radius expansion was identified: at least one role exposes additional sensitive services after pivot."
        )
        paths.append(
            "Role assumption can expand the blast radius from basic enumeration into broader service visibility or resource access."
        )
        recs.append(
            "Model post-assumption permissions when reviewing IAM trust relationships; do not assess trust in isolation."
        )

    return confirmed, paths, recs, immediate_access, likely_pivots, post_pivot_blast


def build_role_review_line(role: Dict[str, Any]) -> str:
    role_name = role.get("role_name") or role.get("role_arn") or "unknown-role"
    trust = role.get("trust", {}) or {}
    return (
        f"`{role_name}` | "
        f"risk=`{role.get('risk_level', 'UNKNOWN')}` | "
        f"confidence=`{role.get('assume_path_confidence', 'UNKNOWN')}` | "
        f"trust_allows_caller=`{yes_no(trust.get('trust_allows_caller'))}` | "
        f"caller_policy_assume=`{yes_no(role.get('caller_policy_allows_assume'))}` | "
        f"explicit_deny_assume=`{yes_no(role.get('caller_policy_explicit_deny_assume'))}` | "
        f"likely_same_account_pivot=`{yes_no(role.get('likely_assumable_same_account'))}` | "
        f"cross_account_trust=`{yes_no(trust.get('allows_external_account'))}`"
    )


def role_sort_key(role: Dict[str, Any]) -> Tuple[int, int, str]:
    risk_rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    confidence_rank = {"CONFIRMED": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    risk = str(role.get("risk_level") or "INFO").upper()
    confidence = str(role.get("assume_path_confidence") or "INFO").upper()
    name = str(role.get("role_name") or role.get("role_arn") or "")
    return (risk_rank.get(risk, 9), confidence_rank.get(confidence, 9), name.lower())


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_rel(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path.resolve())


def build_priority_role_summary(role: Dict[str, Any]) -> Dict[str, Any]:
    role_name = role.get("role_name") or role.get("role_arn") or "unknown-role"
    trust = role.get("trust", {}) or {}
    return {
        "role_name": role_name,
        "risk": role.get("risk_level", "UNKNOWN"),
        "confidence": role.get("assume_path_confidence", "UNKNOWN"),
        "trust_allows_caller": bool(trust.get("trust_allows_caller")),
        "caller_policy_assume": bool(role.get("caller_policy_allows_assume")),
        "explicit_deny_assume": bool(role.get("caller_policy_explicit_deny_assume")),
        "likely_same_account_pivot": bool(role.get("likely_assumable_same_account")),
        "cross_account_trust": bool(trust.get("allows_external_account")),
    }


def build_top_findings(
    *,
    confirmed_findings: List[str],
    readable_buckets_count: int,
    interesting_objects_count: int,
    assumable_roles_count: int,
    high_pivots_count: int,
    medium_pivots_count: int,
    role_side_secret_count: int,
    public_trust_count: int,
    cross_account_trust_count: int,
    probe_high_findings: int,
) -> List[str]:
    top: List[str] = []
    if readable_buckets_count > 0:
        top.append(f"Immediate S3 access confirmed: {readable_buckets_count} readable bucket(s).")
    if interesting_objects_count > 0:
        top.append(f"Interesting S3 object(s) discovered: {interesting_objects_count}.")
    if assumable_roles_count > 0:
        top.append(f"Identified {assumable_roles_count} practical assume-role path(s) by static policy/trust evaluation.")
    elif high_pivots_count > 0:
        top.append(f"Identified {high_pivots_count} HIGH-confidence likely role pivot candidate(s).")
    if medium_pivots_count > 0:
        top.append(f"Identified {medium_pivots_count} MEDIUM-confidence pivot candidate(s).")
    if role_side_secret_count > 0:
        top.append(f"Post-pivot Secrets Manager target(s) identified: {role_side_secret_count}.")
    if cross_account_trust_count > 0:
        top.append(f"Cross-account trust exposure present in {cross_account_trust_count} role(s).")
    if public_trust_count > 0:
        top.append(f"Public-trust role exposure present in {public_trust_count} role(s).")
    if probe_high_findings > 0:
        top.append(f"Targeted service probing produced {probe_high_findings} HIGH-severity finding(s).")
    for finding in confirmed_findings:
        if len(top) >= 5:
            break
        if finding not in top:
            top.append(finding)
    return top[:5]


def format_probe_finding_line(finding: Dict[str, Any]) -> str:
    severity = finding.get("severity", "INFO")
    service = finding.get("service", "unknown")
    title = finding.get("title", "unnamed finding")
    target = finding.get("target")
    suffix = f" on `{target}`" if isinstance(target, str) and target else ""
    basis = "probed" if bool(finding.get("tested", True)) else "policy-derived"
    escalation = finding.get("impact_type")
    escalation_suffix = f" | impact=`{escalation}`" if isinstance(escalation, str) and escalation else ""
    return f"[{severity}] {service}: {title}{suffix} | basis=`{basis}`{escalation_suffix}"


def split_targeted_findings(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    tested: List[Dict[str, Any]] = []
    policy_derived: List[Dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if bool(finding.get("tested", True)):
            tested.append(finding)
        else:
            policy_derived.append(finding)
    return tested, policy_derived


def format_review_path_line(path: Dict[str, Any]) -> str:
    title = path.get("title") or path.get("type") or "review path"
    risk = path.get("risk") or "INFO"
    steps = " -> ".join([str(x) for x in (path.get("steps") or []) if isinstance(x, str) and x])
    if steps:
        return f"[{risk}] {title}: {steps}"
    return f"[{risk}] {title}"



def summarize_validation_status(validation_summary: Dict[str, Any]) -> Dict[str, int]:
    totals = validation_summary.get("totals") or {}
    if not isinstance(totals, dict):
        totals = {}
    return {
        "total_candidates": int(totals.get("total_candidates") or 0),
        "validated_candidates": int(totals.get("validated_candidates") or 0),
        "confirmed": int(totals.get("confirmed_access_paths") or 0),
        "capability_only": int(totals.get("capability_confirmed") or 0),
        "failed": int(totals.get("failed") or 0),
        "inconclusive": int(totals.get("inconclusive") or 0),
        "not_validated": int(totals.get("not_validated") or 0),
    }


def format_validation_entry(entry: Dict[str, Any]) -> str:
    candidate_id = entry.get("candidate_id") or "unknown-candidate"
    family = entry.get("family") or "unknown-family"
    status = entry.get("status") or "unknown-status"
    target = (
        entry.get("target_role_arn")
        or entry.get("target_function_arn")
        or entry.get("target")
        or entry.get("target_service")
        or "unknown-target"
    )
    proof = entry.get("proof_strategy") or "unspecified"
    return f"[{status}] {candidate_id} | family=`{family}` | target=`{target}` | proof=`{proof}`"


def choose_priority_paths(validation_summary: Dict[str, Any], fallback_paths: List[str]) -> List[str]:
    top = validation_summary.get("top_validated_paths") or []
    if isinstance(top, list) and top:
        out = [format_validation_entry(item) for item in top if isinstance(item, dict)]
        return out[:3]
    return fallback_paths[:3]

def summarize_probe_plan(targeted: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    covered: List[str] = []
    skipped: List[str] = []
    probe_plan = targeted.get("probe_plan") or {}
    if not isinstance(probe_plan, dict):
        return covered, skipped
    for service, plan in probe_plan.items():
        if not isinstance(plan, dict):
            continue
        reasons = ", ".join(plan.get("reasons") or []) or "no reason captured"
        targets = len(plan.get("explicit_targets") or [])
        if plan.get("should_probe"):
            covered.append(f"{service}: probed (reasons: {reasons}; explicit targets: {targets})")
        else:
            skipped.append(f"{service}: skipped (reasons: {reasons}; explicit targets: {targets})")
    return covered, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description="Build markdown report from workspace.json")
    parser.add_argument("run_dir", nargs="?", help="Legacy positional path to a run directory")
    parser.add_argument("--run-id", help="Run identifier under runs/<run_id>")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    if args.run_id:
        run_id = args.run_id
        run_dir = root / "runs" / run_id
    elif args.run_dir:
        run_dir = Path(args.run_dir).expanduser().resolve()
        run_id = run_dir.name
    else:
        raise SystemExit("Usage: python tools/build_report.py --run-id <run_id> | <run_dir>")
    workspace_path = run_dir / "workspace.json"
    report_path = run_dir / "report.md"
    report_summary_path = run_dir / "report_summary.json"
    validation_summary_path = run_dir / "16_validation_summary.json"

    ws = load_json(workspace_path)
    validation_summary = load_json(validation_summary_path) if validation_summary_path.exists() else None

    target_user = ws.get("target_user_name", "unknown")
    caller = ws.get("caller_identity", {}) or {}
    caller_arn = caller.get("Arn", "unknown")

    visible_users_obj = ws.get("visible_users", {})
    groups_obj = ws.get("groups", {})
    counts_obj = ws.get("counts", {}) if isinstance(ws.get("counts"), dict) else {}

    visible_users_count = extract_count(visible_users_obj)
    groups_count = extract_count(groups_obj)
    visible_user_items = extract_items(visible_users_obj)
    group_policy_count = int(counts_obj.get("group_policies") or 0)

    perm = ws.get("permission_summary", {}) or {}
    risk = perm.get("risk", {}) or {}
    services = perm.get("services", {}) or {}
    interesting_actions = perm.get("interesting_actions", {}) or {}
    services_count = len(services)
    resources_seen_count = int(perm.get("resources_seen_count") or 0)
    resources_samples = perm.get("resources_samples", []) or []

    role_audit = ws.get("iam_role_audit", {}) or {}
    roles = role_audit.get("roles", []) or []
    roles_count = int(role_audit.get("roles_count", len(roles)) or 0)
    assumable_roles_count = int(role_audit.get("assumable_roles_count") or 0)
    public_trust_count = int(role_audit.get("public_trust_count") or 0)
    cross_account_trust_count = int(role_audit.get("cross_account_trust_count") or 0)

    followup = ws.get("policy_resource_followup", {}) or {}
    followup_summary = followup.get("followup_summary", {}) or {}
    followup_resources = followup.get("resources", {}) or {}
    pivot_candidates = followup.get("pivot_candidates", []) or []
    followup_roles = (followup_resources.get("iam", {}) or {}).get("roles", []) or []
    s3_targets = followup_resources.get("s3", []) or []

    readable_buckets_count = int(followup_summary.get("readable_buckets_count") or 0)
    pivot_candidates_count = int(followup_summary.get("pivot_candidates_count", len(pivot_candidates)) or 0)
    secret_targets_count = int(followup_summary.get("secret_targets_count") or 0)
    role_side_secret_count = len(collect_role_side_secret_arns(followup_roles))
    interesting_objects_count = len(detect_interesting_s3_objects(s3_targets))
    pivot_counts = count_pivots_by_confidence(pivot_candidates)
    high_pivots_count = pivot_counts["HIGH"]
    medium_pivots_count = pivot_counts["MEDIUM"]

    targeted = ws.get("targeted_service_probing", {}) or {}
    targeted_services = targeted.get("services", {}) or {}
    targeted_findings = targeted.get("findings", []) or []
    targeted_summary = targeted.get("summary", {}) or {}
    targeted_counts = targeted_summary.get("counts", {}) or {}
    probe_covered, probe_skipped = summarize_probe_plan(targeted)

    services_visible = sorted({str(s) for s in services.keys() if isinstance(s, str) and s} | {str(s) for s in (targeted.get("services_probed") or targeted_summary.get("services_probed") or []) if isinstance(s, str) and s})
    validation_trace = validation_summary.get("validation_trace") if isinstance(validation_summary, dict) else []
    if not isinstance(validation_trace, list):
        validation_trace = []
    sensitive_info_trace = validation_summary.get("sensitive_info_trace") if isinstance(validation_summary, dict) else []
    if not isinstance(sensitive_info_trace, list):
        sensitive_info_trace = []

    s3_audit = ws.get("s3_access_audit") or targeted_services.get("s3") or {}
    s3_counts = counts_from_module(s3_audit)
    s3_public_buckets = int(s3_counts.get("public_buckets") or 0)
    s3_listable_buckets = int(s3_counts.get("listable_buckets") or 0)
    s3_unencrypted_buckets = int(s3_counts.get("unencrypted_buckets") or 0)
    s3_no_pab_buckets = int(s3_counts.get("buckets_without_full_public_access_block") or 0)
    s3_interesting_hits = int(s3_counts.get("interesting_object_keyword_hits") or 0)

    secrets_audit = ws.get("secrets_manager_audit") or targeted_services.get("secretsmanager") or {}
    secrets_counts = counts_from_module(secrets_audit)
    secrets_rotation_disabled = int(secrets_counts.get("rotation_disabled") or 0)
    secrets_public_policy = int(secrets_counts.get("public_policy_secrets") or 0)
    secrets_external_policy = int(secrets_counts.get("external_principal_policy_secrets") or 0)

    ec2_inv = ws.get("ec2_inventory") or targeted_services.get("ec2") or {}
    ec2_counts = counts_from_module(ec2_inv)
    ec2_instances_total = int(ec2_counts.get("instances_total") or 0)
    ec2_public_instances = int(ec2_counts.get("instances_with_public_ip") or 0)
    ec2_instance_profiles = int(ec2_counts.get("instances_with_instance_profile") or 0)
    ec2_world_open_sg = int(ec2_counts.get("instances_with_world_open_security_group") or 0)
    ec2_public_sensitive = int(ec2_counts.get("instances_publicly_reachable_sensitive_ports") or 0)
    ec2_exposure_indicators = int(ec2_counts.get("instances_with_exposure_indicators") or ec2_counts.get("instances_risky_exposure") or 0)

    lambda_a = ws.get("lambda_audit") or targeted_services.get("lambda") or {}
    lambda_counts = counts_from_module(lambda_a)
    lambda_total = int(lambda_counts.get("functions_total") or 0)
    lambda_public_policy = int(lambda_counts.get("functions_with_public_policy") or 0)
    lambda_public_url = int(lambda_counts.get("functions_with_public_url") or 0)
    lambda_sensitive_env = int(lambda_counts.get("functions_with_sensitive_env_keys") or 0)

    kms_a = ws.get("kms_key_audit") or targeted_services.get("kms") or {}
    kms_counts = counts_from_module(kms_a)
    kms_total = int(kms_counts.get("keys_total") or 0)
    kms_rot_disabled = int(kms_counts.get("customer_keys_rotation_disabled") or 0)
    kms_pending_del = int(kms_counts.get("keys_pending_deletion") or 0)
    kms_public_policy = int(kms_counts.get("keys_with_public_policy") or 0)

    tested_probe_findings, policy_probe_findings = split_targeted_findings(targeted_findings)
    tested_probe_lines: List[str] = []
    policy_probe_lines: List[str] = []
    service_summary_lines: List[str] = [
        f"- **S3:** public buckets={s3_public_buckets}, listable buckets={s3_listable_buckets}, unencrypted buckets={s3_unencrypted_buckets}, missing public access block={s3_no_pab_buckets}, keyword hits={s3_interesting_hits}",
        f"- **Secrets Manager:** rotation disabled={secrets_rotation_disabled}, public-policy={secrets_public_policy}, external-policy={secrets_external_policy}",
        f"- **EC2:** instances={ec2_instances_total}, public IP={ec2_public_instances}, instance profiles={ec2_instance_profiles}, world-open SG={ec2_world_open_sg}, public+sensitive ports={ec2_public_sensitive}, exposure indicators={ec2_exposure_indicators}",
        f"- **Lambda:** functions={lambda_total}, public URLs={lambda_public_url}, public-policy={lambda_public_policy}, sensitive-env-hints={lambda_sensitive_env}",
        f"- **KMS:** keys={kms_total}, public-policy={kms_public_policy}, rotation disabled={kms_rot_disabled}, pending deletion={kms_pending_del}",
    ]

    confirmed_findings: List[str] = []
    possible_review_paths: List[str] = []
    recommendations: List[str] = []
    immediate_access: List[str] = []
    likely_pivots: List[str] = []
    post_pivot_blast: List[str] = []
    probe_finding_lines: List[str] = []

    if risk.get("has_resource_wildcard"):
        confirmed_findings.append("Resource wildcard detected (`*`), which indicates at least one overly broad resource scope.")
        possible_review_paths.append("Potential expansion of access beyond intended resources if permissions are attached to sensitive actions.")
        recommendations.append("Restrict IAM policy `Resource` elements to specific ARNs instead of `*` where possible.")
    if risk.get("has_action_wildcard"):
        confirmed_findings.append("Action wildcard detected, which may allow broader access than intended.")
        possible_review_paths.append("Potential broader-than-intended access or misuse through unintended API actions.")
        recommendations.append("Replace wildcard actions with explicit minimal-access action lists.")
    if risk.get("has_service_wildcard"):
        confirmed_findings.append("Service wildcard detected, implying permissions may span multiple AWS services.")
        possible_review_paths.append("Cross-service abuse may be possible if wildcard permissions include sensitive services.")
        recommendations.append("Scope policy actions to only the required AWS services.")
    if risk.get("has_iam_passrole"):
        confirmed_findings.append("The effective permissions include `iam:PassRole`, which is a notable service-mediated access primitive.")
        recommendations.append("Scope `iam:PassRole` to explicitly approved roles and services only.")
    if risk.get("has_sts_assumerole"):
        confirmed_findings.append("The effective permissions include `sts:AssumeRole` or related assume-role capability.")
    if risk.get("has_secrets_read"):
        confirmed_findings.append("The effective permissions include Secrets Manager secret-read capability.")
    if risk.get("has_kms_decrypt"):
        confirmed_findings.append("The effective permissions include `kms:Decrypt`, which can expand access to encrypted data.")

    if visible_users_count > 0:
        confirmed_findings.append(
            f"Identity enumeration appears possible: the principal can see {visible_users_count} IAM users."
        )
        possible_review_paths.append(
            "User enumeration can support reconnaissance and targeting of higher-value identities."
        )
        recommendations.append("Review whether IAM listing permissions are necessary for this identity.")

    if roles_count > 0:
        confirmed_findings.append(f"IAM role audit completed successfully: {roles_count} role(s) were discovered for review.")
    if assumable_roles_count > 0:
        confirmed_findings.append(
            f"{assumable_roles_count} role(s) appear practically assumable by the current principal based on static trust and permission analysis."
        )
        possible_review_paths.append(
            "Direct lateral movement or broader access may be possible via `sts:AssumeRole` into trusted roles."
        )
        recommendations.append(
            "Review trust policies, explicit deny conditions, and any `sts:AssumeRole` grants on practically assumable roles."
        )
    elif roles_count > 0:
        if high_pivots_count > 0:
            confirmed_findings.append(
                "No strict caller-side `sts:AssumeRole` allow was observed, but at least one high-confidence same-account direct-trust pivot path was identified."
            )
        elif pivot_candidates_count > 0:
            confirmed_findings.append(
                "No direct practical assume-role path was fully established, but additional likely pivot candidates were identified and should be validated."
            )
        else:
            confirmed_findings.append("No practical assume-role path was established from the currently collected trust and permission evidence.")
    if public_trust_count > 0:
        confirmed_findings.append(f"{public_trust_count} role(s) expose wildcard/public trust in their trust policy.")
        possible_review_paths.append("Wildcard trust can broaden who may enter a role, depending on caller-side permissions.")
        recommendations.append("Remove wildcard principals from role trust policies unless strictly required.")
    if cross_account_trust_count > 0:
        confirmed_findings.append(f"{cross_account_trust_count} role(s) include cross-account trust relationships.")
        possible_review_paths.append("Cross-account trust can create boundary-crossing access paths and should be explicitly justified.")
        recommendations.append("Review external account principals in trust policies and validate business need.")

    f_confirmed, f_paths, f_recs, f_immediate, f_pivots, f_post = derive_followup_findings(followup)
    confirmed_findings.extend(f_confirmed)
    possible_review_paths.extend(f_paths)
    recommendations.extend(f_recs)
    immediate_access.extend(f_immediate)
    likely_pivots.extend(f_pivots)
    post_pivot_blast.extend(f_post)

    if s3_public_buckets > 0:
        confirmed_findings.append(f"S3 service audit detected {s3_public_buckets} public bucket(s) (policy/ACL heuristics).")
        possible_review_paths.append("Public S3 buckets can expose data directly over the internet.")
        recommendations.append("Enable S3 Block Public Access and remove public bucket policies/ACL grants unless explicitly required.")
    if s3_listable_buckets > 0:
        confirmed_findings.append(f"S3 enumeration confirmed: {s3_listable_buckets} bucket(s) are listable by the current principal.")
        recommendations.append("Restrict `s3:ListBucket` / `s3:GetObject` to specific buckets/prefixes and required principals only.")
    if s3_unencrypted_buckets > 0:
        confirmed_findings.append(f"S3 encryption gap: {s3_unencrypted_buckets} bucket(s) have no server-side encryption configuration.")
        recommendations.append("Enforce default server-side encryption and consider denying unencrypted writes.")
    if secrets_public_policy > 0:
        confirmed_findings.append(f"Secrets Manager exposure: {secrets_public_policy} secret(s) have wildcard principals in resource policy.")
        possible_review_paths.append("A permissive secret resource policy can allow unintended principals to access sensitive secret metadata or values.")
        recommendations.append("Remove wildcard principals from secret resource policies and scope access to explicit roles or accounts.")
    if secrets_external_policy > 0:
        confirmed_findings.append(f"Secrets Manager cross-account exposure: {secrets_external_policy} secret(s) reference external principals.")
        recommendations.append("Review cross-account secret sharing and enforce least privilege.")
    if secrets_rotation_disabled > 0:
        confirmed_findings.append(f"Secrets rotation disabled: {secrets_rotation_disabled} secret(s) have RotationEnabled=False.")
        recommendations.append("Enable rotation where applicable and document approved exceptions.")
    if ec2_public_sensitive > 0:
        confirmed_findings.append(f"EC2 public exposure: {ec2_public_sensitive} instance(s) have a public IP and world-open sensitive ports.")
        possible_review_paths.append("Publicly reachable instances with world-open sensitive ports can enable remote compromise and follow-on movement.")
        recommendations.append("Restrict security group ingress and remove world-open access on management and database ports.")
    elif ec2_world_open_sg > 0:
        confirmed_findings.append(f"EC2 security-group exposure: {ec2_world_open_sg} instance(s) have world-open ingress in attached security groups.")
        possible_review_paths.append("World-open security groups expand the network exposure surface of EC2 workloads.")
        recommendations.append("Review and tighten security group rules attached to internet-reachable instances.")
    elif ec2_public_instances > 0:
        confirmed_findings.append(f"EC2 network exposure: {ec2_public_instances} instance(s) have a public IP address.")
        recommendations.append("Prefer private subnets and tightly justify each internet-facing instance.")
    if ec2_instance_profiles > 0:
        confirmed_findings.append(f"EC2 blast-radius indicator: {ec2_instance_profiles} instance(s) have an attached IAM instance profile.")
        recommendations.append("Keep EC2 instance roles minimal-accessd and avoid broad roles on exposed workloads.")
    if lambda_public_url > 0:
        confirmed_findings.append(f"Lambda public endpoints: {lambda_public_url} function URL(s) are configured with AuthType=NONE.")
        possible_review_paths.append("Public Lambda Function URLs can be invoked anonymously unless protected by auth or authorizers.")
        recommendations.append("Set Function URL AuthType to AWS_IAM or add a dedicated authentication layer.")
    if lambda_public_policy > 0:
        confirmed_findings.append(f"Lambda resource policy exposure: {lambda_public_policy} function(s) have wildcard principals in policy.")
        recommendations.append("Restrict Lambda resource policies to specific principals and add conditions where applicable.")
    if lambda_sensitive_env > 0:
        confirmed_findings.append(f"Lambda secret-hint posture: {lambda_sensitive_env} function(s) contain environment variable names that suggest embedded secrets.")
        recommendations.append("Prefer Secrets Manager / Parameter Store over sensitive environment variables.")
    if kms_public_policy > 0:
        confirmed_findings.append(f"KMS key-policy exposure: {kms_public_policy} key(s) contain wildcard principals.")
        recommendations.append("Restrict KMS key policies to explicit principals and validate all key-sharing use cases.")
    if kms_rot_disabled > 0:
        confirmed_findings.append(f"KMS hygiene: {kms_rot_disabled} customer-managed key(s) have rotation disabled.")
        recommendations.append("Enable automatic KMS key rotation for customer-managed symmetric keys where applicable.")
    if kms_pending_del > 0:
        confirmed_findings.append(f"KMS lifecycle risk: {kms_pending_del} key(s) are in PendingDeletion state.")
        recommendations.append("Review pending deletion keys carefully to avoid accidental data loss.")

    for finding in targeted_findings:
        if not isinstance(finding, dict):
            continue
        report_text = finding.get("report_text")
        if isinstance(report_text, str) and report_text:
            if bool(finding.get("tested", True)):
                confirmed_findings.append(report_text)
            else:
                possible_review_paths.append(f"Policy-derived access indicator: {report_text}")
        risk_note = finding.get("risk_note")
        if isinstance(risk_note, str) and risk_note:
            possible_review_paths.append(risk_note)
        recommendation = finding.get("recommendation")
        if isinstance(recommendation, str) and recommendation:
            recommendations.append(recommendation)
        line = format_probe_finding_line(finding)
        probe_finding_lines.append(line)
        if bool(finding.get("tested", True)):
            tested_probe_lines.append(line)
        else:
            policy_probe_lines.append(line)

    structured_review_paths = ws.get("review_paths", []) or []
    structured_review_path_lines = [format_review_path_line(p) for p in structured_review_paths if isinstance(p, dict)]
    possible_review_paths.extend(structured_review_path_lines)

    if not confirmed_findings:
        confirmed_findings.append("No high-level policy, role-audit, follow-up, or service-probing risk was detected by the currently enabled modules.")
    if not recommendations:
        recommendations.append("Continue with deeper analysis and validate any assumptions in a controlled lab before drawing conclusions.")

    confirmed_findings = dedupe(confirmed_findings)
    possible_review_paths = dedupe(possible_review_paths)
    recommendations = dedupe(recommendations)
    immediate_access = dedupe(immediate_access)
    likely_pivots = dedupe(likely_pivots)
    post_pivot_blast = dedupe(post_pivot_blast)
    probe_finding_lines = dedupe(probe_finding_lines)
    tested_probe_lines = dedupe(tested_probe_lines)
    policy_probe_lines = dedupe(policy_probe_lines)
    structured_review_path_lines = dedupe(structured_review_path_lines)
    probe_covered = dedupe(probe_covered)
    probe_skipped = dedupe(probe_skipped)
    service_summary_lines = dedupe(service_summary_lines)

    review_roles: List[Dict[str, Any]] = []
    for r in roles:
        if not isinstance(r, dict):
            continue
        role_name = r.get("role_name") or r.get("role_arn") or "unknown-role"
        role_arn = r.get("role_arn") or ""
        if is_service_linked_role(role_name, role_arn):
            continue
        review_roles.append(r)
    top_non_service_roles = [build_role_review_line(r) for r in sorted(review_roles, key=role_sort_key)]

    tested_probe_high_findings = sum(1 for f in tested_probe_findings if str(f.get("severity") or "").upper() == "HIGH")
    policy_probe_high_findings = sum(1 for f in policy_probe_findings if str(f.get("severity") or "").upper() == "HIGH")
    probe_high_findings = tested_probe_high_findings + policy_probe_high_findings
    validation_status = summarize_validation_status(validation_summary) if isinstance(validation_summary, dict) else None
    priority_review_lines = choose_priority_paths(validation_summary, structured_review_path_lines) if isinstance(validation_summary, dict) else structured_review_path_lines[:3]

    top_findings = build_top_findings(
        confirmed_findings=confirmed_findings,
        readable_buckets_count=readable_buckets_count,
        interesting_objects_count=interesting_objects_count,
        assumable_roles_count=assumable_roles_count,
        high_pivots_count=high_pivots_count,
        medium_pivots_count=medium_pivots_count,
        role_side_secret_count=role_side_secret_count,
        public_trust_count=public_trust_count,
        cross_account_trust_count=cross_account_trust_count,
        probe_high_findings=probe_high_findings,
    )

    lines: List[str] = [
        "# CloudScanner-AI Report",
        "",
        f"**Run ID:** `{run_id}`",
        f"**Target user:** `{target_user}`",
        f"**Caller ARN:** `{caller_arn}`",
        "",
        "## Executive Summary",
        "",
        f"The scan identified **{len(confirmed_findings)} confirmed finding(s)** based on deterministic analysis.",
        f"The policy summary observed **{services_count} service(s)** and **{resources_seen_count} resource pattern(s)**.",
        (
            f"The role audit reviewed **{roles_count} role(s)**, with **{assumable_roles_count} practical assume-role path(s) identified by static trust and permission analysis**, "
            f"**{high_pivots_count} HIGH-confidence likely pivot(s)**, **{medium_pivots_count} MEDIUM-confidence pivot(s)**, "
            f"**{public_trust_count} public-trust**, and **{cross_account_trust_count} cross-account trust** case(s)."
        ),
        f"The follow-up module identified **{pivot_candidates_count} pivot candidate(s)**, **{readable_buckets_count} readable S3 bucket(s)**, **{secret_targets_count} immediate secret target(s)**, and **{role_side_secret_count} post-pivot secret target(s)**.",
        (
            f"Targeted service probing covered **{int(targeted_counts.get('services_probed') or len(targeted.get('services_probed') or []))} service(s)** and produced **{int(targeted_counts.get('findings_total') or len(targeted_findings))} normalized finding(s)**: "
            f"**{len(tested_probe_findings)} empirically probed** and **{len(policy_probe_findings)} policy-derived access indicator(s)**."
        ),
        "",
        "## Top Findings",
        "",
        bullet(top_findings),
        "",
        "## Confirmed Findings",
        "",
        bullet(confirmed_findings),
        "",
        "## Possible Follow-on Paths",
        "",
        bullet(possible_review_paths),
        "",
        "## Priority Review Paths",
        "",
        bullet(priority_review_lines),
        "",
        "## Recommendations",
        "",
        bullet(recommendations),
        "",
        "## Evidence",
        "",
        f"- Visible IAM users: **{visible_users_count}**",
        f"- IAM groups: **{groups_count}**",
        f"- Group-derived policies collected: **{group_policy_count}**",
        f"- Resources sampled in user policy summary: **{len(resources_samples)}**",
        f"- Roles reviewed: **{roles_count}**",
        f"- Practical assume-role paths identified: **{assumable_roles_count}**",
        f"- HIGH-confidence likely pivots: **{high_pivots_count}**",
        f"- MEDIUM-confidence pivot candidates: **{medium_pivots_count}**",
        f"- Public-trust roles: **{public_trust_count}**",
        f"- Cross-account trust roles: **{cross_account_trust_count}**",
        f"- Pivot candidates: **{pivot_candidates_count}**",
        f"- Readable S3 buckets: **{readable_buckets_count}**",
        f"- Immediate secret targets: **{secret_targets_count}**",
        f"- Post-pivot secret targets: **{role_side_secret_count}**",
        f"- S3 public buckets: **{s3_public_buckets}**",
        f"- S3 listable buckets (service scanner): **{s3_listable_buckets}**",
        f"- S3 unencrypted buckets (service scanner): **{s3_unencrypted_buckets}**",
        f"- Secrets with rotation disabled: **{secrets_rotation_disabled}**",
        f"- Secrets with public policy (heuristic): **{secrets_public_policy}**",
        f"- EC2 instances (all regions): **{ec2_instances_total}**",
        f"- EC2 instances with public IP: **{ec2_public_instances}**",
        f"- EC2 instances with attached instance profile: **{ec2_instance_profiles}**",
        f"- EC2 instances with world-open security groups: **{ec2_world_open_sg}**",
        f"- EC2 instances with public + sensitive world-open ports: **{ec2_public_sensitive}**",
        f"- Lambda functions: **{lambda_total}**",
        f"- Lambda public URLs (AuthType=NONE): **{lambda_public_url}**",
        f"- Lambda functions with sensitive env key hints: **{lambda_sensitive_env}**",
        f"- KMS keys: **{kms_total}**",
        f"- KMS keys with public policy: **{kms_public_policy}**",
        f"- KMS customer keys with rotation disabled: **{kms_rot_disabled}**",
        f"- Targeted probing normalized findings: **{len(targeted_findings)}**",
        f"- Empirically probed findings: **{len(tested_probe_findings)}**",
        f"- Policy-derived access indicators: **{len(policy_probe_findings)}**",
        f"- Structured review paths: **{len(structured_review_paths)}**",
    ]

    lines.extend([
        "",
        "## Targeted Service Probing Coverage",
        "",
        "### Probed Services",
        "",
        bullet(probe_covered),
        "",
        "### Skipped Services",
        "",
        bullet(probe_skipped),
        "",
        "### Empirically Probed Findings",
        "",
        bullet(tested_probe_lines),
        "",
        "### Policy-derived Access Indicators",
        "",
        bullet(policy_probe_lines),
        "",
        "### All Normalized Probe Findings",
        "",
        bullet(probe_finding_lines),
        "",
        "## Targeted Service Probing Summary",
        "",
        *service_summary_lines,
    ])

    if isinstance(interesting_actions, dict) and interesting_actions:
        lines.extend([
            "",
            "## Sensitive Permission Signals",
            "",
            f"- iam:PassRole matches: **{len(interesting_actions.get('iam_passrole') or [])}**",
            f"- sts:AssumeRole matches: **{len(interesting_actions.get('sts_assumerole') or [])}**",
            f"- Secrets read matches: **{len(interesting_actions.get('secrets_read') or [])}**",
            f"- KMS decrypt matches: **{len(interesting_actions.get('kms_decrypt') or [])}**",
            f"- Lambda invoke matches: **{len(interesting_actions.get('lambda_invoke') or [])}**",
        ])

    if validation_status is not None:
        lines.extend([
            "",
            "## Access Validation",
            "",
            f"- Total candidates: **{validation_status['total_candidates']}**",
            f"- Validated candidates: **{validation_status['validated_candidates']}**",
            f"- Confirmed access findings: **{validation_status['confirmed']}**",
            f"- Capability confirmed without end-state proof: **{validation_status['capability_only']}**",
            f"- Failed: **{validation_status['failed']}**",
            f"- Inconclusive: **{validation_status['inconclusive']}**",
            f"- Not validated: **{validation_status['not_validated']}**",
        ])
        if priority_review_lines:
            lines.extend(["", "### Top Validated Paths", "", *[f"- {x}" for x in priority_review_lines[:10]]])
        if validation_trace:
            trace_lines = []
            for item in validation_trace[:10]:
                if not isinstance(item, dict):
                    continue
                target = item.get("target") or "unknown-target"
                trace_lines.append(
                    f"- [{item.get('status') or 'unknown'}] {item.get('candidate_id') or 'unknown-candidate'} | target=`{target}` | proof=`{item.get('proof_strategy') or 'unspecified'}` | commands=`{', '.join(item.get('commands_used') or []) or 'n/a'}`"
                )
            if trace_lines:
                lines.extend(["", "### Validation Trace", "", *trace_lines])
        if sensitive_info_trace:
            redacted_lines = []
            for item in sensitive_info_trace[:10]:
                if not isinstance(item, dict):
                    continue
                target = item.get("target") or "unknown-target"
                locations = ", ".join(item.get("locations") or []) or "location-not-captured"
                commands = ", ".join(item.get("commands_used") or []) or "n/a"
                redacted_lines.append(
                    f"- target=`{target}` | method=`{item.get('proof_strategy') or 'unspecified'}` | locations=`{locations}` | commands=`{commands}` | values_disclosed=`{yes_no(item.get('secret_values_disclosed'))}`"
                )
            if redacted_lines:
                lines.extend(["", "### Sensitive Info Trace (redacted values)", "", *redacted_lines])

    if structured_review_path_lines:
        lines.extend(["", "## Structured Review Paths", "", *[f"- {x}" for x in structured_review_path_lines[:30]]])

    if visible_user_items:
        lines.extend(["", "## Visible IAM Users", "", *[f"- `{item}`" for item in visible_user_items[:20]]])
    if resources_samples:
        lines.extend(["", "## User-Policy Resource Samples", "", *[f"- `{item}`" for item in resources_samples]])
    if immediate_access:
        lines.extend(["", "## Immediate Access Confirmed", "", *[f"- {item}" for item in immediate_access[:20]]])
    if likely_pivots:
        lines.extend(["", "## Likely Role Pivot Opportunities", "", *[f"- {item}" for item in likely_pivots[:20]]])
    if post_pivot_blast:
        lines.extend(["", "## Post-Pivot Blast Radius", "", *[f"- {item}" for item in post_pivot_blast[:20]]])
    if top_non_service_roles:
        lines.extend(["", "## Priority Role Review", "", *[f"- {item}" for item in top_non_service_roles[:20]]])

    service_linked_errors = 0
    for r in followup_roles:
        if not isinstance(r, dict):
            continue
        if r.get("get_role_error") and is_service_linked_role(r.get("role_name", ""), r.get("role_arn", "")):
            service_linked_errors += 1
    if service_linked_errors > 0:
        lines.extend([
            "",
            "## Analysis Notes",
            "",
            f"- {service_linked_errors} service-linked role(s) produced follow-up parsing errors due to path-style role naming. This is an analyzer limitation, not necessarily a permission failure.",
            "- Strict explicit-allow assume-role detection is intentionally conservative; same-account explicit trust can still represent a practical pivot path and should be validated separately.",
            "- IAM condition keys, SCPs, permissions boundaries, and session policies are not fully modeled by this report and must be considered separately.",
        ])

    content = "\n".join(lines) + "\n"
    report_path.write_text(content, encoding="utf-8")

    priority_role_summaries = [build_priority_role_summary(role) for role in sorted(review_roles, key=role_sort_key)[:5]]

    summary_payload: Dict[str, Any] = {
        "ok": True,
        "run_id": run_id,
        "generated_at": now_iso_utc(),
        "artifacts": {
            "workspace": to_rel(root, workspace_path),
            "report": to_rel(root, report_path),
            "report_summary": to_rel(root, report_summary_path),
            **({"validation_summary": to_rel(root, validation_summary_path)} if validation_summary_path.exists() else {}),
        },
        "target_user": target_user,
        "caller_arn": caller_arn,
        "services_visible": services_visible,
        "totals": {
            "confirmed_findings": len(confirmed_findings),
            "possible_review_paths": len(possible_review_paths),
            "recommendations": len(recommendations),
            "targeted_probe_findings": len(targeted_findings),
            "targeted_probe_tested_findings": len(tested_probe_findings),
            "targeted_probe_policy_findings": len(policy_probe_findings),
            "structured_review_paths": len(structured_review_paths),
            **({
                "validated_candidates": validation_status["validated_candidates"],
                "validated_confirmed_access_paths": validation_status["confirmed"],
                "validated_capability_only": validation_status["capability_only"],
                "validated_failed": validation_status["failed"],
                "validated_inconclusive": validation_status["inconclusive"],
                "validated_not_validated": validation_status["not_validated"],
            } if validation_status is not None else {}),
        },
        "role_audit": {
            "roles_reviewed": roles_count,
            "roles_fully_confirmed": assumable_roles_count,
            "high_confidence_likely_pivots": high_pivots_count,
            "medium_confidence_pivots": medium_pivots_count,
            "public_trust_roles": public_trust_count,
            "cross_account_trust_roles": cross_account_trust_count,
        },
        "followup": {
            "pivot_candidates": pivot_candidates_count,
            "readable_s3_buckets": readable_buckets_count,
            "immediate_secret_targets": secret_targets_count,
            "post_pivot_secret_targets": role_side_secret_count,
            "interesting_s3_objects": interesting_objects_count,
        },
        "targeted_service_probing": {
            "services_probed": targeted.get("services_probed") or targeted_summary.get("services_probed") or [],
            "services_skipped": targeted.get("services_skipped") or targeted_summary.get("services_skipped") or [],
            "probe_plan": targeted.get("probe_plan") or {},
            "findings_total": len(targeted_findings),
            "empirically_probed_findings": len(tested_probe_findings),
            "policy_derived_findings": len(policy_probe_findings),
            "severity_counts": targeted_summary.get("severity_counts") or {},
        },
        "service_scanners": {
            "s3": {
                "public_buckets": s3_public_buckets,
                "listable_buckets": s3_listable_buckets,
                "unencrypted_buckets": s3_unencrypted_buckets,
                "missing_public_access_block": s3_no_pab_buckets,
                "interesting_object_keyword_hits": s3_interesting_hits,
            },
            "secrets_manager": {
                "rotation_disabled": secrets_rotation_disabled,
                "public_policy_secrets": secrets_public_policy,
                "external_policy_secrets": secrets_external_policy,
            },
            "ec2": {
                "instances_total": ec2_instances_total,
                "instances_with_public_ip": ec2_public_instances,
                "instances_with_instance_profile": ec2_instance_profiles,
                "instances_with_world_open_security_group": ec2_world_open_sg,
                "instances_publicly_reachable_sensitive_ports": ec2_public_sensitive,
                "instances_with_exposure_indicators": ec2_exposure_indicators,
            },
            "lambda": {
                "functions_total": lambda_total,
                "functions_with_public_policy": lambda_public_policy,
                "functions_with_public_url": lambda_public_url,
                "functions_with_sensitive_env_keys": lambda_sensitive_env,
            },
            "kms": {
                "keys_total": kms_total,
                "keys_with_public_policy": kms_public_policy,
                "customer_keys_rotation_disabled": kms_rot_disabled,
                "keys_pending_deletion": kms_pending_del,
            },
        },
        "top_findings": top_findings,
        "priority_review_paths": priority_review_lines[:3],
        "priority_roles": priority_role_summaries,
        "validation_trace": validation_trace[:10],
        "sensitive_info_trace": sensitive_info_trace[:10],
        "highlights": {
            "immediate_access": immediate_access[:5],
            "likely_pivots": likely_pivots[:5],
            "post_pivot_blast_radius": post_pivot_blast[:5],
            "probe_findings": probe_finding_lines[:10],
            "empirically_probed_findings": tested_probe_lines[:10],
            "policy_derived_findings": policy_probe_lines[:10],
            "structured_review_paths": structured_review_path_lines[:10],
        },
        **({"validation": validation_summary} if validation_summary is not None else {}),
    }
    report_summary_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[OK] Report written to: {report_path}")
    print(f"[OK] Report summary written to: {report_summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
