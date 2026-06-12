from __future__ import annotations

import sys
from typing import Sequence

from .errors import ApprovalDenied


def prompt_for_approval(capability_name: str, description: str, command: Sequence[str]) -> bool:
    prompt = (
        "Privileged capability requested:\n"
        f"  Capability: {capability_name}\n"
        f"  Description: {description}\n"
        f"  Command: {' '.join(command)}\n"
        "Approve? [y/N] "
    )
    if not sys.stdin.isatty():
        raise ApprovalDenied("Confirmation required, but stdin is not interactive.")
    response = input(prompt).strip().lower()
    if response in {"y", "yes"}:
        return True
    raise ApprovalDenied("User denied the request.")
