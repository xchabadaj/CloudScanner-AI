from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import boto3
from botocore.exceptions import ClientError


def now_iso_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def env_int(name: str, default: int) -> int:
    try:
        raw = os.getenv(name)
        if raw is None or raw == '':
            return default
        return int(raw)
    except Exception:
        return default


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw == '':
        return default
    return raw.strip().lower() in {'1', 'true', 'yes', 'y', 'on'}


def env_csv(name: str) -> List[str]:
    raw = os.getenv(name, '').strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(',') if x.strip()]


def safe_aws_error(err: Exception) -> Dict[str, Any]:
    payload: Dict[str, Any] = {'type': type(err).__name__, 'message': str(err)}
    if isinstance(err, ClientError):
        payload['aws_error_code'] = err.response.get('Error', {}).get('Code')
        payload['aws_error_message'] = err.response.get('Error', {}).get('Message')
        payload['http_status'] = err.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
        payload['request_id'] = err.response.get('ResponseMetadata', {}).get('RequestId')
    return payload


def get_account_id_from_workspace(workspace: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(workspace, dict):
        return None
    caller = workspace.get('caller_identity') or {}
    if isinstance(caller, dict) and isinstance(caller.get('Account'), str):
        return caller.get('Account')
    return None


def resolve_regions(ctx, service_hint: str = 'ec2') -> List[str]:
    override = env_csv('CLOUDSCANNER_REGIONS')
    if override:
        return override

    region = getattr(ctx, 'region', None) or os.getenv('AWS_DEFAULT_REGION') or os.getenv('AWS_REGION') or 'us-east-1'

    if env_bool('CLOUDSCANNER_SINGLE_REGION', default=False):
        return [region]

    try:
        session = getattr(ctx, 'session', None) or boto3.Session(region_name=region)
        ec2 = session.client('ec2', region_name=region)
        resp = ec2.describe_regions(AllRegions=False)
        regions = [r.get('RegionName') for r in resp.get('Regions', []) if isinstance(r, dict) and r.get('RegionName')]
        regions = [r for r in regions if isinstance(r, str)]
        if regions:
            return sorted(set(regions))
    except Exception:
        pass

    return [region]


def dedupe_keep_order(items: Sequence[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x not in seen:
            out.append(x)
            seen.add(x)
    return out


def parse_json_maybe(value: Any) -> Optional[Dict[str, Any]]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return None
    return None


def policy_allows_public(policy_doc: Any) -> Tuple[bool, List[str]]:
    doc = parse_json_maybe(policy_doc)
    if not doc:
        return (False, ['no_policy'])
    statements = doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]
    reasons: List[str] = []
    public = False

    for st in statements:
        if not isinstance(st, dict):
            continue
        if str(st.get('Effect') or '').upper() != 'ALLOW':
            continue
        principal = st.get('Principal')
        if principal == '*' or principal == {'AWS': '*'}:
            public = True
            reasons.append('principal_wildcard')
            continue
        if isinstance(principal, dict):
            aws_pr = principal.get('AWS')
            if aws_pr == '*' or aws_pr == ['*']:
                public = True
                reasons.append('principal_aws_wildcard')
                continue
    return (public, reasons or ['no_wildcard_principal'])


def score_risk(*, high: bool = False, medium: bool = False, low: bool = False) -> str:
    if high:
        return 'HIGH'
    if medium:
        return 'MEDIUM'
    if low:
        return 'LOW'
    return 'INFO'
