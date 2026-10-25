from __future__ import annotations

import argparse
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUN_SCAN = ROOT / "tools" / "run_scan.py"
RUN_PIPELINE = ROOT / "tools" / "run_pipeline.py"
BUILD_REPORT = ROOT / "tools" / "build_report.py"


def run_cmd(cmd: list[str]) -> int:
    print(f"\n[RUN] {shlex.join(cmd)}\n", file=sys.stderr)
    completed = subprocess.run(cmd)
    return completed.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="CloudScanner-AI runner")
    parser.add_argument(
        "action",
        choices=["scan1", "scan2", "services", "scan3", "scan4", "report", "full"],
        help=(
            "scan1 = IAM user scan, "
            "scan2 = policy resource follow-up, "
            "scan3 = permission summary, "
            "scan4 = IAM role audit, "
            "report = run pipeline stage 'report' when available (build report + report_summary), "
            "full = run pipeline stage 'full' (collect -> service_collect -> analyze -> report)"
        ),
    )
    parser.add_argument(
        "--run-id",
        help="Existing or custom run ID. If omitted, a new one is created automatically.",
    )
    parser.add_argument(
        "--in",
        dest="input_path",
        help="Optional input workspace path for scan2/scan3/scan4. Default: runs/<run_id>/workspace.json",
    )
    args = parser.parse_args()

    run_id = args.run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = ROOT / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    py = sys.executable

    if args.action == "scan1":
        return run_cmd([
            py,
            str(RUN_SCAN),
            "--module",
            "iam_user_scan",
            "--out",
            str(run_dir / "01_iam_user_scan.json"),
        ])

    if args.action == "scan2":
        input_path = args.input_path or str(run_dir / "workspace.json")
        return run_cmd([
            py,
            str(RUN_SCAN),
            "--module",
            "policy_resource_followup",
            "--in",
            input_path,
            "--out",
            str(run_dir / "02_policy_resource_followup.json"),
        ])

    
    if args.action == "services":
        if not RUN_PIPELINE.exists():
            print(f"[ERROR] Pipeline runner not found: {RUN_PIPELINE}.", file=sys.stderr)
            return 1
        return run_cmd([
            py,
            str(RUN_PIPELINE),
            "--stage",
            "service_collect",
            "--run-id",
            run_id,
        ])

    if args.action == "scan3":
        input_path = args.input_path or str(run_dir / "workspace.json")
        return run_cmd([
            py,
            str(RUN_SCAN),
            "--module",
            "permission_summary",
            "--in",
            input_path,
            "--out",
            str(run_dir / "03_permission_summary.json"),
        ])

    if args.action == "scan4":
        input_path = args.input_path or str(run_dir / "workspace.json")
        return run_cmd([
            py,
            str(RUN_SCAN),
            "--module",
            "iam_role_audit",
            "--in",
            input_path,
            "--out",
            str(run_dir / "04_iam_role_audit.json"),
        ])

    if args.action == "report":
        if RUN_PIPELINE.exists():
            return run_cmd([
                py,
                str(RUN_PIPELINE),
                "--stage",
                "report",
                "--run-id",
                run_id,
            ])

        return run_cmd([
            py,
            str(BUILD_REPORT),
            "--run-id",
            run_id,
        ])

    if not RUN_PIPELINE.exists():
        print(
            f"[ERROR] Pipeline runner not found: {RUN_PIPELINE}. Add tools/run_pipeline.py first.",
            file=sys.stderr,
        )
        return 1

    return run_cmd([
        py,
        str(RUN_PIPELINE),
        "--stage",
        "full",
        "--run-id",
        run_id,
    ])


if __name__ == "__main__":
    raise SystemExit(main())
