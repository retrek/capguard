from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Sequence


def append_audit_entry(
    audit_path: Path,
    capability: str,
    arguments: Dict[str, str],
    caller: str,
    command: Sequence[str],
    requires_confirmation: bool,
    approved: bool,
    exit_code: Optional[int],
    duration_ms: Optional[int],
    cwd: str,
    error: Optional[str] = None,
) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "capability": capability,
        "args": arguments,
        "caller": caller,
        "command": list(command),
        "requires_confirmation": requires_confirmation,
        "approved": approved,
        "exit_code": exit_code,
        "duration_ms": duration_ms,
        "cwd": cwd,
    }
    if error is not None:
        entry["error"] = error
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def tail_audit_entries(audit_path: Path, lines: int = 10) -> str:
    if not audit_path.exists():
        return ""
    with audit_path.open("r", encoding="utf-8") as handle:
        entries = handle.readlines()[-lines:]
    return "".join(entries)
