from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

OUTPUT_FILENAME = "16_validation_summary.json"
VALIDATION_FILES = {
    "cloudscanner_iam_access_reviewer": ["15_review_iam_access.json", "14_review_iam_access.json"],
    "cloudscanner_lambda_access_reviewer": ["15_review_lambda_access.json"],
    "cloudscanner_general_access_reviewer": ["15_review_general_access.json", "15b_review_general_access.json"],
}
STATUS_MAP = {
    "confirmed": "confirmed_access_paths",
    "capability_only": "capability_confirmed",
    "failed": "failed",
    "inconclusive": "inconclusive",
}


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json_if_exists(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def dedupe_strings(items: List[Any]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        if isinstance(item, str) and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def first_non_empty_str(*values: Any) -> Optional[str]:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def normalize_evidence(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    return dedupe_strings(value)


def build_candidate_stub(candidate: Dict[str, Any], *, status: str = "not_validated") -> Dict[str, Any]:
    return {
        "candidate_id": candidate.get("candidate_id"),
        "family": candidate.get("family"),
        "preferred_validator": candidate.get("preferred_validator"),
        "title": candidate.get("title"),
        "target_role_arn": candidate.get("target_role_arn"),
        "target_function_arn": candidate.get("target_function_arn"),
        "target_service": candidate.get("target_service"),
        "target_region": candidate.get("target_region"),
        "target": candidate.get("target"),
        "source_identity_arn": candidate.get("source_identity_arn"),
        "resulting_identity_arn": None,
        "status": status,
        "confidence": candidate.get("confidence"),
        "proof_strategy": candidate.get("proof_strategy"),
        "validation_goal": candidate.get("validation_goal"),
        "commands_scope_hint": normalize_evidence(candidate.get("commands_scope_hint")),
        "commands_used": [],
        "evidence_basis": candidate.get("evidence_basis"),
        "evidence": normalize_evidence(candidate.get("evidence")),
        "evidence_refs": normalize_evidence(candidate.get("evidence_refs")),
        "source_artifacts": normalize_evidence(candidate.get("source_artifacts")),
        "reasoning": candidate.get("reasoning"),
        "why_it_matters": candidate.get("why_it_matters"),
        "confirmation_reason": None,
        "sensitive_info_found": False,
        "sensitive_locations": normalize_evidence(candidate.get("sensitive_signal_summary")),
        "secret_values_disclosed": False,
        "validator_module": None,
        "validator_artifact": None,
        "error": None,
    }


def normalize_validator_result(item: Dict[str, Any]) -> Dict[str, Any]:
    result = dict(item)
    if not result.get('status') and result.get('verdict'): result['status'] = result['verdict']
    if not result.get("resulting_identity_arn"):
        proof = result.get("proof")
        if isinstance(proof, dict):
            result["resulting_identity_arn"] = proof.get("assumed_role_arn") or proof.get("resulting_identity_arn")
    if not result.get("evidence_basis"):
        result["evidence_basis"] = proof.get("method") if isinstance((proof := result.get("proof")), dict) else None
    return result


def validator_items_from_doc(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    validated_paths = doc.get("validated_paths")
    if isinstance(validated_paths, list):
        return [normalize_validator_result(item) for item in validated_paths if isinstance(item, dict)]

    legacy_results = doc.get("results")
    if isinstance(legacy_results, list):
        return [normalize_validator_result(item) for item in legacy_results if isinstance(item, dict)]

    legacy_validations = doc.get("validations")
    if isinstance(legacy_validations, list):
        return [normalize_validator_result(item) for item in legacy_validations if isinstance(item, dict)]

    reviewed = doc.get('reviewed_candidates')
    if isinstance(reviewed, list):
        return [normalize_validator_result(item) for item in reviewed if isinstance(item, dict)]

    return []


def merge_result(candidate: Dict[str, Any], validator_result: Dict[str, Any], *, validator_module: str | None = None, validator_artifact: str | None = None) -> Dict[str, Any]:
    entry = build_candidate_stub(candidate, status=str(validator_result.get("status") or "inconclusive"))
    entry.update(
        {
            "family": first_non_empty_str(validator_result.get("family"), candidate.get("family")),
            "preferred_validator": first_non_empty_str(
                validator_result.get("preferred_validator"), candidate.get("preferred_validator")
            ),
            "title": first_non_empty_str(validator_result.get("title"), candidate.get("title")),
            "target_role_arn": first_non_empty_str(
                validator_result.get("target_role_arn"), candidate.get("target_role_arn")
            ),
            "target_function_arn": first_non_empty_str(
                validator_result.get("target_function_arn"), candidate.get("target_function_arn")
            ),
            "target_service": first_non_empty_str(
                validator_result.get("target_service"), candidate.get("target_service")
            ),
            "target_region": first_non_empty_str(
                validator_result.get("target_region"), candidate.get("target_region")
            ),
            "target": first_non_empty_str(validator_result.get("target"), candidate.get("target")),
            "source_identity_arn": first_non_empty_str(
                validator_result.get("source_identity_arn"), candidate.get("source_identity_arn")
            ),
            "resulting_identity_arn": first_non_empty_str(
                validator_result.get("resulting_identity_arn"), candidate.get("resulting_identity_arn")
            ),
            "confidence": first_non_empty_str(validator_result.get("confidence"), candidate.get("confidence")),
            "proof_strategy": first_non_empty_str(validator_result.get("proof_strategy"), candidate.get("proof_strategy")),
            "validation_goal": first_non_empty_str(
                validator_result.get("validation_goal"), candidate.get("validation_goal")
            ),
            "commands_scope_hint": normalize_evidence(validator_result.get("commands_scope_hint"))
            or normalize_evidence(candidate.get("commands_scope_hint")),
            "commands_used": normalize_evidence(validator_result.get("commands_used")),
            "evidence_basis": first_non_empty_str(
                validator_result.get("evidence_basis"), candidate.get("evidence_basis")
            ),
            "evidence": normalize_evidence(validator_result.get("evidence"))
            or normalize_evidence(candidate.get("evidence")),
            "evidence_refs": normalize_evidence(validator_result.get("evidence_refs"))
            or normalize_evidence(candidate.get("evidence_refs")),
            "source_artifacts": normalize_evidence(validator_result.get("source_artifacts"))
            or normalize_evidence(candidate.get("source_artifacts")),
            "reasoning": first_non_empty_str(validator_result.get("reasoning"), candidate.get("reasoning")),
            "why_it_matters": first_non_empty_str(
                validator_result.get("why_it_matters"), candidate.get("why_it_matters")
            ),
            "confirmation_reason": first_non_empty_str(
                validator_result.get("confirmation_reason"), validator_result.get("notes")
            ),
            "sensitive_info_found": bool(validator_result.get("sensitive_info_found")),
            "sensitive_locations": normalize_evidence(validator_result.get("sensitive_locations"))
            or normalize_evidence(candidate.get("sensitive_signal_summary")),
            "secret_values_disclosed": bool(validator_result.get("secret_values_disclosed")),
            "validator_module": validator_module,
            "validator_artifact": validator_artifact,
            "error": validator_result.get("error"),
        }
    )
    return entry


def strength_rank(status_group: str) -> int:
    order = {
        "confirmed_access_paths": 0,
        "capability_confirmed": 1,
        "failed": 2,
        "inconclusive": 3,
        "not_validated": 4,
    }
    return order.get(status_group, 99)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build deterministic validation summary")
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
        raise SystemExit("Usage: python tools/build_validation_summary.py --run-id <run_id> | <run_dir>")

    candidates_path = run_dir / "14_review_candidates.json"
    output_path = run_dir / OUTPUT_FILENAME

    candidates_doc = load_json_if_exists(candidates_path)
    if candidates_doc is None:
        raise FileNotFoundError(f"Missing candidate file: {candidates_path}")

    candidates = candidates_doc.get("candidates") or candidates_doc.get("review_candidates") or []
    if not isinstance(candidates, list):
        raise ValueError("Expected 'candidates' list in 14_review_candidates.json")

    results_by_candidate: Dict[str, Dict[str, Any]] = {}
    validation_files_present: List[str] = []
    for validator_name, filenames in VALIDATION_FILES.items():
        for filename in filenames:
            doc = load_json_if_exists(run_dir / filename)
            if doc is None:
                continue
            validation_files_present.append(filename)
            for item in validator_items_from_doc(doc):
                candidate_id = item.get("candidate_id")
                if not isinstance(candidate_id, str) or not candidate_id:
                    continue
                enriched_item = dict(item)
                enriched_item["validator_module"] = validator_name
                enriched_item["validator_artifact"] = filename
                current_group = STATUS_MAP.get(str(enriched_item.get("status") or "inconclusive"), "inconclusive")
                prior = results_by_candidate.get(candidate_id)
                if prior is None:
                    results_by_candidate[candidate_id] = enriched_item
                    continue
                prior_group = STATUS_MAP.get(str(prior.get("status") or "inconclusive"), "inconclusive")
                if strength_rank(current_group) < strength_rank(prior_group):
                    results_by_candidate[candidate_id] = enriched_item
            break

    grouped: Dict[str, List[Dict[str, Any]]] = {
        "confirmed_access_paths": [],
        "capability_confirmed": [],
        "failed": [],
        "inconclusive": [],
        "not_validated": [],
    }

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        candidate_id = candidate.get("candidate_id")
        if not isinstance(candidate_id, str) or not candidate_id:
            continue
        validator_result = results_by_candidate.get(candidate_id)
        if validator_result is None:
            grouped["not_validated"].append(build_candidate_stub(candidate, status="not_validated"))
            continue
        merged = merge_result(
            candidate,
            validator_result,
            validator_module=validator_result.get("validator_module"),
            validator_artifact=validator_result.get("validator_artifact"),
        )
        group_name = STATUS_MAP.get(str(validator_result.get("status") or "inconclusive"), "inconclusive")
        grouped[group_name].append(merged)

    validated_candidates = sum(
        len(grouped[k])
        for k in (
            "confirmed_access_paths",
            "capability_confirmed",
            "failed",
            "inconclusive",
        )
    )

    top_validated_paths: List[Dict[str, Any]] = []
    for group_name in (
        "confirmed_access_paths",
        "capability_confirmed",
        "failed",
        "inconclusive",
    ):
        for item in grouped[group_name]:
            top_validated_paths.append(item)
            if len(top_validated_paths) >= 5:
                break
        if len(top_validated_paths) >= 5:
            break

    validation_trace: List[Dict[str, Any]] = []
    sensitive_info_trace: List[Dict[str, Any]] = []
    for group_name in ("confirmed_access_paths", "capability_confirmed", "failed", "inconclusive"):
        for item in grouped[group_name]:
            trace_item = {
                "candidate_id": item.get("candidate_id"),
                "status": item.get("status"),
                "family": item.get("family"),
                "target": item.get("target") or item.get("target_role_arn") or item.get("target_function_arn"),
                "target_service": item.get("target_service"),
                "proof_strategy": item.get("proof_strategy"),
                "validation_goal": item.get("validation_goal"),
                "validator_module": item.get("validator_module"),
                "validator_artifact": item.get("validator_artifact"),
                "commands_used": item.get("commands_used") or [],
                "confirmation_reason": item.get("confirmation_reason"),
            }
            validation_trace.append(trace_item)
            if item.get("sensitive_info_found"):
                sensitive_info_trace.append(
                    {
                        "candidate_id": item.get("candidate_id"),
                        "family": item.get("family"),
                        "target": item.get("target") or item.get("target_role_arn") or item.get("target_function_arn"),
                        "target_service": item.get("target_service"),
                        "proof_strategy": item.get("proof_strategy"),
                        "validator_module": item.get("validator_module"),
                        "validator_artifact": item.get("validator_artifact"),
                        "locations": item.get("sensitive_locations") or [],
                        "commands_used": item.get("commands_used") or [],
                        "secret_values_disclosed": bool(item.get("secret_values_disclosed")),
                    }
                )

    payload: Dict[str, Any] = {
        "ok": True,
        "module": "validation_summary",
        "run_id": run_id,
        "generated_at": now_iso_utc(),
        "sources": {
            "candidates": str(candidates_path.resolve()),
            "validation_files_present": validation_files_present,
        },
        "totals": {
            "total_candidates": len([c for c in candidates if isinstance(c, dict)]),
            "validated_candidates": validated_candidates,
            "confirmed_access_paths": len(grouped["confirmed_access_paths"]),
            "capability_confirmed": len(grouped["capability_confirmed"]),
            "failed": len(grouped["failed"]),
            "inconclusive": len(grouped["inconclusive"]),
            "not_validated": len(grouped["not_validated"]),
            "confirmed": len(grouped["confirmed_access_paths"]),
            "capability_only": len(grouped["capability_confirmed"]),
        },
        "confirmed_access_paths": grouped["confirmed_access_paths"],
        "capability_confirmed": grouped["capability_confirmed"],
        "failed": grouped["failed"],
        "inconclusive": grouped["inconclusive"],
        "not_validated": grouped["not_validated"],
        "top_validated_paths": top_validated_paths,
        "validation_trace": validation_trace,
        "sensitive_info_trace": sensitive_info_trace,
    }

    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "module": "validation_summary",
                "run_id": run_id,
                "output": str(output_path.resolve()),
                "totals": payload["totals"],
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
