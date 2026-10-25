from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class PreflightResult:
    ok: bool
    timestamp: str
    account_id: Optional[str] = None
    arn: Optional[str] = None
    user_id: Optional[str] = None
    region: Optional[str] = None
    error: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def run_preflight(*, region: Optional[str] = None) -> PreflightResult:
    ts = now_iso_utc()
    try:
        session = boto3.session.Session(region_name=region)
        effective_region = session.region_name or region

        sts = session.client("sts", region_name=effective_region)
        ident = sts.get_caller_identity()

        return PreflightResult(
            ok=True,
            timestamp=ts,
            account_id=ident.get("Account"),
            arn=ident.get("Arn"),
            user_id=ident.get("UserId"),
            region=effective_region,
            error=None,
        )

    except (ClientError, BotoCoreError) as e:
        err = {"type": type(e).__name__, "message": str(e)}
        if isinstance(e, ClientError):
            err["aws_error_code"] = e.response.get("Error", {}).get("Code")
            err["aws_error_message"] = e.response.get("Error", {}).get("Message")
        return PreflightResult(ok=False, timestamp=ts, region=region, error=err)
