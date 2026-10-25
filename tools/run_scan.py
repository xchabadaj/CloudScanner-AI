from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import boto3

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.context import AppContext
from core.output import save_json
from scanners import iam_user_scan, policy_resource_followup, permission_summary, iam_role_audit, targeted_service_probing
from scanners.review_path_curator import run as review_path_curator
from scanners.access_candidate_builder import run as access_candidate_builder


def load_json(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Input file not found: {p}")
    with p.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Input JSON must be an object/dict.")
    return data


def build_ctx() -> AppContext:
    access_key = os.getenv("AWS_ACCESS_KEY_ID", "")
    secret_key = os.getenv("AWS_SECRET_ACCESS_KEY", "")
    session_token = os.getenv("AWS_SESSION_TOKEN")
    region = os.getenv("AWS_DEFAULT_REGION") or os.getenv("AWS_REGION") or "us-east-1"

    ctx = AppContext(
        aws_access_key=access_key,
        aws_secret_key=secret_key,
        aws_session_token=session_token,
        region=region,
    )

    ctx.session = boto3.Session(
        aws_access_key_id=access_key or None,
        aws_secret_access_key=secret_key or None,
        aws_session_token=session_token or None,
        region_name=region,
    )
    return ctx


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_workspace(out_path: Path, workspace: Dict[str, Any]) -> None:
    workspace_path = out_path.parent / "workspace.json"
    save_json(str(workspace_path), workspace)


def run_module(module_name: str, ctx: AppContext) -> Dict[str, Any]:
    if module_name == "iam_user_scan":
        iam_user_scan.handler(ctx)
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "iam_user_scan did not produce a dict result"}
        return ctx.last_result

    if module_name == "policy_resource_followup":
        policy_resource_followup.handler(ctx)
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "policy_resource_followup did not preserve workspace"}
        mod = ctx.last_result.get("policy_resource_followup")
        if not isinstance(mod, dict):
            return {"ok": False, "error": "policy_resource_followup result missing in workspace"}
        return mod

    if module_name == "targeted_service_probing":
        targeted_service_probing.handler(ctx)
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "targeted_service_probing did not preserve workspace"}
        mod = ctx.last_result.get("targeted_service_probing")
        if not isinstance(mod, dict):
            return {"ok": False, "error": "targeted_service_probing result missing in workspace"}
        return mod

    if module_name == "permission_summary":
        permission_summary.handler(ctx)
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "permission_summary did not preserve workspace"}
        return {
            "ok": ctx.last_result.get("permission_summary_ok", True),
            "target_user_name": ctx.last_result.get("target_user_name"),
            "permission_summary": ctx.last_result.get("permission_summary"),
            "error": ctx.last_result.get("permission_summary_error"),
        }

    if module_name == "iam_role_audit":
        iam_role_audit.handler(ctx)
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "iam_role_audit did not preserve workspace"}
        audit = ctx.last_result.get("iam_role_audit")
        if not isinstance(audit, dict):
            return {"ok": False, "error": "iam_role_audit result missing in workspace"}
        return audit

    if module_name == "review_path_curator":
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "review_path_curator requires workspace input"}
        workspace = ctx.last_result
        result_workspace = review_path_curator(workspace, run_dir=".")
        ctx.last_result = result_workspace
        mod = result_workspace.get("review_path_inputs")
        if not isinstance(mod, dict):
            return {"ok": False, "error": "review_path_inputs missing"}
        return mod

    if module_name == "access_candidate_builder":
        if not isinstance(ctx.last_result, dict):
            return {"ok": False, "error": "access_candidate_builder requires workspace input"}
        workspace = ctx.last_result
        result_workspace = access_candidate_builder(workspace, run_dir=".")
        ctx.last_result = result_workspace
        mod = result_workspace.get("review_candidates")
        if not isinstance(mod, dict):
            return {"ok": False, "error": "review_candidates missing"}
        return mod

    return {"ok": False, "error": f"Unsupported module: {module_name}"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--module", required=True, choices=["iam_user_scan", "policy_resource_followup", "targeted_service_probing", "permission_summary", "iam_role_audit", "review_path_curator", "access_candidate_builder"])
    parser.add_argument("--in", dest="input_path")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    out_path = Path(args.out).resolve()
    ensure_parent(out_path)

    ctx = build_ctx()
    input_data = load_json(args.input_path)
    if input_data is not None:
        ctx.last_result = input_data

    result = run_module(args.module, ctx)
    save_json(str(out_path), result)

    if isinstance(ctx.last_result, dict):
        write_workspace(out_path, ctx.last_result)

    print(json.dumps({
        "ok": result.get("ok", True),
        "module": args.module,
        "out": str(out_path),
        "workspace": str(out_path.parent / "workspace.json")
    }, indent=2, ensure_ascii=False))

    return 0 if result.get("ok", False) else 1


if __name__ == "__main__":
    raise SystemExit(main())
