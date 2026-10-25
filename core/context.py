from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class AppContext:
    """
    Spoločný kontext pre všetky moduly.
    Drží AWS session, región a aj posledný výsledok.
    """
    aws_access_key: str
    aws_secret_key: str
    aws_session_token: Optional[str]
    region: str
   
    session: Any = None

    last_result: Optional[dict] = None

