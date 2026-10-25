from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.runtime.preflight import run_preflight
from core.runtime.run_id import build_run_id

ROOT = Path(__file__).resolve().parents[1]
RUN_SCAN = ROOT / "tools" / "run_scan.py"
BUILD_REPORT = ROOT / "tools" / "build_report.py"
BUILD_VALIDATION_SUMMARY = ROOT / "tools" / "build_validation_summary.py"
PIPELINE_VERSION = "1.3"

MODULE_OUTPUTS: Dict[str, str] = {
    "iam_user_scan": "01_iam_user_scan.json",
    "policy_resource_followup": "02_policy_resource_followup.json",
    "targeted_service_probing": "03_targeted_service_probing.json",
    "permission_summary": "11_permission_summary.json",
    "iam_role_audit": "12_iam_role_audit.json",
    "review_path_curator": "13_review_paths.json",
    "access_candidate_builder": "14_review_candidates.json",
    "validation_summary": "16_validation_summary.json",
    "report": "report.md",
}
REPORT_SUMMARY_FILENAME = "report_summary.json"

STAGE_MODULES: Dict[str, List[str]] = {
    "collect": ["iam_user_scan", "policy_resource_followup"],
    "service_collect": ["targeted_service_probing"],
    "analyze": ["permission_summary", "iam_role_audit", "targeted_service_probing"],
    "access_prepare": [],
    "validation_summary": ["validation_summary"],
    "report": ["report"],
    "full": [
        "iam_user_scan",
        "policy_resource_followup",
        "permission_summary",
        "iam_role_audit",
        "targeted_service_probing",
        "validation_summary",
        "report",
    ],
}


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def to_rel(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def load_manifest(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def write_manifest(path: Path, data: Dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def init_manifest(
    path: Path,
    *,
    run_id: str,
    stage: str,
    stage_modules: List[str],
    workspace_path: Path,
    preflight_data: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    existing = load_manifest(path)
    now = now_iso_utc()

    existing_modules_completed = existing.get("modules_completed", [])
    if not isinstance(existing_modules_completed, list):
        existing_modules_completed = []

    existing_modules_requested = existing.get("modules_requested", [])
    if not isinstance(existing_modules_requested, list):
        existing_modules_requested = []

    existing_stages = existing.get("stages_requested", [])
    if not isinstance(existing_stages, list):
        existing_stages = []

    existing_artifacts = existing.get("artifacts", {})
    if not isinstance(existing_artifacts, dict):
        existing_artifacts = {}

    existing_module_runs = existing.get("module_runs", {})
    if not isinstance(existing_module_runs, dict):
        existing_module_runs = {}

    manifest: Dict[str, Any] = {
        "run_id": run_id,
        "pipeline_version": PIPELINE_VERSION,
        "started_at": existing.get("started_at") or now,
        "last_started_at": now,
        "completed_at": None,
        "status": "RUNNING",
        "last_requested_stage": stage,
        "stages_requested": dedupe_keep_order(existing_stages + [stage]),
        "modules_requested": dedupe_keep_order(existing_modules_requested + stage_modules),
        "modules_completed": dedupe_keep_order([m for m in existing_modules_completed if isinstance(m, str)]),
        "artifacts": existing_artifacts,
        "workspace": to_rel(workspace_path),
        "error": None,
        "preflight": preflight_data if preflight_data is not None else existing.get("preflight"),
        "module_runs": existing_module_runs,
    }
    write_manifest(path, manifest)
    return manifest


def update_manifest(
    path: Path,
    manifest: Dict[str, Any],
    *,
    completed_module: Optional[str] = None,
    module_name: Optional[str] = None,
    module_record: Optional[Dict[str, Any]] = None,
    artifacts: Optional[Dict[str, str]] = None,
    status: Optional[str] = None,
    error: Optional[Dict[str, Any]] = None,
    finalize: bool = False,
) -> Dict[str, Any]:
    if completed_module:
        completed = manifest.get("modules_completed", [])
        if not isinstance(completed, list):
            completed = []
        if completed_module not in completed:
            completed.append(completed_module)
        manifest["modules_completed"] = completed

    if module_name and module_record:
        current_module_runs = manifest.get("module_runs", {})
        if not isinstance(current_module_runs, dict):
            current_module_runs = {}
        current_module_runs[module_name] = module_record
        manifest["module_runs"] = current_module_runs

    if artifacts:
        current_artifacts = manifest.get("artifacts", {})
        if not isinstance(current_artifacts, dict):
            current_artifacts = {}
        current_artifacts.update(artifacts)
        manifest["artifacts"] = current_artifacts

    if status:
        manifest["status"] = status

    manifest["error"] = error

    if finalize:
        manifest["completed_at"] = now_iso_utc()

    write_manifest(path, manifest)
    return manifest


def summarize_process_result(result: subprocess.CompletedProcess[str]) -> Dict[str, Any]:
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    return {
        "returncode": result.returncode,
        "stdout_tail": stdout[-4000:] if stdout else "",
        "stderr_tail": stderr[-4000:] if stderr else "",
    }


def run_subprocess(cmd: List[str], *, debug: bool = False) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )

    if debug:
        command = shlex.join(cmd)
        print(f"[DEBUG] {command}", file=sys.stderr)
        if completed.stdout:
            print(completed.stdout, file=sys.stderr, end="" if completed.stdout.endswith("\n") else "\n")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="" if completed.stderr.endswith("\n") else "\n")

    return completed


def require_workspace(path: Path, stage: str) -> None:
    if not path.exists():
        raise FileNotFoundError(
            f"Workspace not found for stage '{stage}': {path}. "
            f"Run 'collect' first or provide --workspace."
        )


def maybe_seed_workspace(source: Optional[str], destination: Path) -> Optional[Path]:
    if not source:
        return None

    src = Path(source).expanduser().resolve()
    if not src.exists():
        raise FileNotFoundError(f"Workspace seed not found: {src}")

    if src == destination.resolve():
        return src

    ensure_dir(destination.parent)
    shutil.copyfile(src, destination)
    return src


def module_out_path(run_dir: Path, module_name: str) -> Path:
    return run_dir / MODULE_OUTPUTS[module_name]


def build_run_scan_command(module_name: str, out_path: Path, input_path: Optional[Path]) -> List[str]:
    cmd = [
        sys.executable,
        str(RUN_SCAN),
        "--module",
        module_name,
        "--out",
        str(out_path),
    ]
    if input_path is not None:
        cmd.extend(["--in", str(input_path)])
    return cmd


def build_report_command(run_id: str) -> List[str]:
    return [
        sys.executable,
        str(BUILD_REPORT),
        "--run-id",
        run_id,
    ]


def build_validation_summary_command(run_id: str) -> List[str]:
    return [
        sys.executable,
        str(BUILD_VALIDATION_SUMMARY),
        "--run-id",
        run_id,
    ]


def print_summary(
    *,
    ok: bool,
    stage: str,
    run_id: str,
    status: str,
    completed_modules: List[str],
    artifacts: Dict[str, str],
    error: Optional[Dict[str, Any]] = None,
) -> None:
    payload: Dict[str, Any] = {
        "ok": ok,
        "stage": stage,
        "run_id": run_id,
        "status": status,
        "completed_modules": completed_modules,
        "artifacts": artifacts,
    }
    if error:
        payload["error"] = error
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description="CloudScanner-AI pipeline runner (CAO-friendly)")
    parser.add_argument(
        "--stage",
        required=True,
        choices=sorted(STAGE_MODULES.keys()),
        help="collect = IAM+policy follow-up, service_collect = targeted service probing only, analyze = permission summary + role audit + targeted service probing, access_prepare = reserved for agent-written candidates, validation_summary = aggregate validator outputs, report = build report, full = collect+analyze+validation_summary+report",
    )
    parser.add_argument(
        "--run-id",
        help="Existing or custom run ID. If omitted, a new run ID is created.",
    )
    parser.add_argument(
        "--workspace",
        help=(
            "Optional workspace seed path for analyze/report stages. "
            "If provided, it is copied or reused as runs/<run_id>/workspace.json before execution."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Mirror child command stdout/stderr to stderr for troubleshooting. Final summary remains on stdout.",
    )
    args = parser.parse_args()

    needs_preflight = args.stage in {"collect", "service_collect", "analyze", "full"}
    preflight = None

    if needs_preflight:
        preflight = run_preflight()

        if not preflight.ok:
            payload = {
                "ok": False,
                "stage": args.stage,
                "run_id": None,
                "status": "FAILED",
                "error": {
                    "step": "preflight",
                    "message": "AWS credential preflight failed",
                    "details": preflight.to_dict(),
                },
            }
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            return 2

    if args.run_id:
        run_id = args.run_id
    elif preflight is not None:
        run_id = build_run_id(account_id=preflight.account_id)
    else:
        run_id = build_run_id(account_id=None)

    run_dir = ROOT / "runs" / run_id
    ensure_dir(run_dir)

    manifest_path = run_dir / "run_manifest.json"
    workspace_path = run_dir / "workspace.json"

    stage_modules = STAGE_MODULES[args.stage]
    manifest = init_manifest(
        manifest_path,
        run_id=run_id,
        stage=args.stage,
        stage_modules=stage_modules,
        workspace_path=workspace_path,
        preflight_data=preflight.to_dict() if preflight is not None else None,
    )

    stage_completed: List[str] = []
    stage_artifacts: Dict[str, str] = {
        "manifest": to_rel(manifest_path),
        "workspace": to_rel(workspace_path),
    }

    try:
        if args.stage in {"analyze", "access_prepare", "validation_summary", "report"} and args.workspace:
            seeded = maybe_seed_workspace(args.workspace, workspace_path)
            if seeded is not None:
                stage_artifacts["workspace_seed"] = to_rel(seeded)

        if args.stage in {"analyze", "service_collect", "access_prepare", "validation_summary"}:
            require_workspace(workspace_path, args.stage)
        elif args.stage == "report":
            require_workspace(workspace_path, args.stage)

        for module_name in stage_modules:
            if module_name in {"report", "validation_summary"}:
                cmd = build_report_command(run_id) if module_name == "report" else build_validation_summary_command(run_id)

                module_started_at = now_iso_utc()
                t0 = time.perf_counter()
                process = run_subprocess(cmd, debug=args.debug)
                duration_ms = int((time.perf_counter() - t0) * 1000)
                module_completed_at = now_iso_utc()

                if process.returncode != 0:
                    error = {
                        "step": module_name,
                        "command": shlex.join(cmd),
                        **summarize_process_result(process),
                    }

                    module_record = {
                        "stage": args.stage,
                        "status": "FAILED",
                        "started_at": module_started_at,
                        "completed_at": module_completed_at,
                        "duration_ms": duration_ms,
                        "command": shlex.join(cmd),
                        "returncode": process.returncode,
                        "artifacts": {},
                    }

                    update_manifest(
                        manifest_path,
                        manifest,
                        module_name=module_name,
                        module_record=module_record,
                        status="FAILED",
                        error=error,
                        finalize=True,
                    )

                    print_summary(
                        ok=False,
                        stage=args.stage,
                        run_id=run_id,
                        status="FAILED",
                        completed_modules=stage_completed,
                        artifacts=stage_artifacts,
                        error=error,
                    )
                    return 1

                primary_out_path = module_out_path(run_dir, module_name)
                aux_artifacts = {module_name: to_rel(primary_out_path)}
                if module_name == "report":
                    report_summary_path = run_dir / REPORT_SUMMARY_FILENAME
                    aux_artifacts = {"report": to_rel(primary_out_path)}
                    if report_summary_path.exists():
                        aux_artifacts["report_summary"] = to_rel(report_summary_path)

                module_record = {
                    "stage": args.stage,
                    "status": "COMPLETED",
                    "started_at": module_started_at,
                    "completed_at": module_completed_at,
                    "duration_ms": duration_ms,
                    "command": shlex.join(cmd),
                    "returncode": process.returncode,
                    "artifacts": aux_artifacts,
                }

                stage_artifacts.update(aux_artifacts)
                update_manifest(
                    manifest_path,
                    manifest,
                    completed_module=module_name,
                    module_name=module_name,
                    module_record=module_record,
                    artifacts=aux_artifacts,
                )
                stage_completed.append(module_name)
                continue

            out_path = module_out_path(run_dir, module_name)
            input_path = None
            if module_name != "iam_user_scan":
                input_path = workspace_path
                require_workspace(input_path, args.stage)

            cmd = build_run_scan_command(module_name, out_path, input_path)

            module_started_at = now_iso_utc()
            t0 = time.perf_counter()
            process = run_subprocess(cmd, debug=args.debug)
            duration_ms = int((time.perf_counter() - t0) * 1000)
            module_completed_at = now_iso_utc()

            if process.returncode != 0:
                error = {
                    "step": module_name,
                    "command": shlex.join(cmd),
                    **summarize_process_result(process),
                }

                module_record = {
                    "stage": args.stage,
                    "status": "FAILED",
                    "started_at": module_started_at,
                    "completed_at": module_completed_at,
                    "duration_ms": duration_ms,
                    "command": shlex.join(cmd),
                    "returncode": process.returncode,
                    "artifacts": {},
                }

                update_manifest(
                    manifest_path,
                    manifest,
                    module_name=module_name,
                    module_record=module_record,
                    status="FAILED",
                    error=error,
                    finalize=True,
                )

                print_summary(
                    ok=False,
                    stage=args.stage,
                    run_id=run_id,
                    status="FAILED",
                    completed_modules=stage_completed,
                    artifacts=stage_artifacts,
                    error=error,
                )
                return 1

            module_artifacts = {
                module_name: to_rel(out_path),
                "workspace": to_rel(workspace_path),
            }

            module_record = {
                "stage": args.stage,
                "status": "COMPLETED",
                "started_at": module_started_at,
                "completed_at": module_completed_at,
                "duration_ms": duration_ms,
                "command": shlex.join(cmd),
                "returncode": process.returncode,
                "artifacts": module_artifacts,
            }

            stage_artifacts.update(module_artifacts)
            update_manifest(
                manifest_path,
                manifest,
                completed_module=module_name,
                module_name=module_name,
                module_record=module_record,
                artifacts=module_artifacts,
            )
            stage_completed.append(module_name)

        final_status = "COMPLETED"
        update_manifest(
            manifest_path,
            manifest,
            status=final_status,
            error=None,
            finalize=True,
        )

        print_summary(
            ok=True,
            stage=args.stage,
            run_id=run_id,
            status=final_status,
            completed_modules=stage_completed,
            artifacts=stage_artifacts,
        )
        return 0

    except Exception as exc:
        error = {
            "step": "pipeline",
            "message": str(exc),
        }
        update_manifest(
            manifest_path,
            manifest,
            status="FAILED",
            error=error,
            finalize=True,
        )
        print_summary(
            ok=False,
            stage=args.stage,
            run_id=run_id,
            status="FAILED",
            completed_modules=stage_completed,
            artifacts=stage_artifacts,
            error=error,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
