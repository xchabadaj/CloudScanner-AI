from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if isinstance(item, str) and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def run(workspace: Dict[str, Any], run_dir: str = ".") -> Dict[str, Any]:
    caller = (workspace.get("caller_identity") or {}).get("Arn") or "unknown"
    permission_summary = workspace.get("permission_summary") or {}
    iam_role_audit = workspace.get("iam_role_audit") or {}
    targeted = workspace.get("targeted_service_probing") or {}

    hints: List[Dict[str, Any]] = []

    for pivot in (iam_role_audit.get("pivot_candidates") or []):
        if not isinstance(pivot, dict):
            continue
        role_arn = pivot.get("role_arn") or pivot.get("role_name")
        reasons = [str(x) for x in (pivot.get("reasons") or []) if isinstance(x, str)]
        if not role_arn:
            continue
        hints.append({
            "kind": "iam_review_hint",
            "source_identity_arn": caller,
            "target": role_arn,
            "confidence": str(pivot.get("confidence") or "LOW").lower(),
            "evidence_refs": _dedupe(["12_iam_role_audit.json"] + reasons[:5]),
            "notes": "Role-audit review candidate for agent curation.",
        })

    for finding in (targeted.get("findings") or []):
        if not isinstance(finding, dict):
            continue
        hints.append({
            "kind": str(finding.get("category") or "service_review_hint"),
            "source_identity_arn": caller,
            "target": finding.get("target"),
            "target_service": finding.get("service"),
            "confidence": str(finding.get("risk") or "medium").lower(),
            "evidence_refs": _dedupe(["03_targeted_service_probing.json"] + [str(x) for x in (finding.get("evidence") or []) if isinstance(x, str)][:5]),
            "notes": str(finding.get("title") or "Targeted service probing hint"),
        })

    workspace["review_path_inputs"] = {
        "ok": True,
        "module": "review_path_input_builder",
        "generated_at": now_iso_utc(),
        "source_identity_arn": caller,
        "hints": hints,
        "summary": {"total_hints": len(hints)},
        "sources": ["11_permission_summary.json", "12_iam_role_audit.json", "03_targeted_service_probing.json"],
    }
    return workspace
