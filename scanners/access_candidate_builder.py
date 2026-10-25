from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(workspace: Dict[str, Any], run_dir: str = ".") -> Dict[str, Any]:
    perm = workspace.get("permission_summary") or {}
    role_audit = workspace.get("iam_role_audit") or {}
    targeted = workspace.get("targeted_service_probing") or {}
    review_inputs = workspace.get("review_path_inputs") or {}
    caller = (workspace.get("caller_identity") or {}).get("Arn") or "unknown"

    bundle: Dict[str, Any] = {
        "ok": True,
        "module": "review_signal_bundle",
        "generated_at": now_iso_utc(),
        "source_identity_arn": caller,
        "source_artifacts": [
            "11_permission_summary.json",
            "12_iam_role_audit.json",
            "03_targeted_service_probing.json",
            "13_review_paths.json",
        ],
        "role_pivot_hints": role_audit.get("pivot_candidates") or [],
        "interesting_services": ((perm.get("summary") or {}).get("interesting_services") or []),
        "service_findings": targeted.get("findings") or [],
        "review_path_hints": review_inputs.get("hints") or [],
        "notes": [
            "This file is a deterministic signal bundle for the review planner.",
            "Final candidate selection should be done by cloudscanner_risk_planner.",
        ],
    }

    workspace["review_candidates"] = bundle
    return workspace
