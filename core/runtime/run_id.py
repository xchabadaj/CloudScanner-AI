from __future__ import annotations

import secrets
from datetime import datetime
from typing import Optional


def build_run_id(*, account_id: Optional[str], prefix: str = "") -> str:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    acct = f"acct{account_id}" if account_id else "acct_unknown"
    rand = secrets.token_hex(2)  
    p = f"{prefix}_" if prefix else ""
    return f"{p}{ts}_{acct}_{rand}"
