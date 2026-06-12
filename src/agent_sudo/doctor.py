from __future__ import annotations

from pathlib import Path
from typing import List

from .policy import Policy


def check_policy_health(policy: Policy) -> List[str]:
    issues: List[str] = []
    policy_path = policy.path
    try:
        mode = policy_path.stat().st_mode
        if mode & 0o022:
            issues.append(f"Policy file is group/world-writable: {policy_path}")
    except FileNotFoundError:
        issues.append(f"Policy file is missing: {policy_path}")
    audit_path = policy.audit_log_path()
    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)
        test_file = audit_path.parent / ".write-test"
        with test_file.open("w", encoding="utf-8") as handle:
            handle.write("ok")
        test_file.unlink(missing_ok=True)
    except OSError as exc:
        issues.append(f"Audit log directory is not writable: {audit_path.parent} ({exc})")
    return issues
