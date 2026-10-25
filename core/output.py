import json
from typing import Any, Dict, Optional

def print_header(title: str) -> None:
    line = "=" * (len(title) + 10)
    print(f"\n{line}\n===  {title}  ===\n{line}")

def print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, default=str, ensure_ascii=False))

def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str, ensure_ascii=False)

def safe_get_last_result(ctx) -> Optional[Dict[str, Any]]:
    return getattr(ctx, "last_result", None)
