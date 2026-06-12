from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Sequence

from .errors import ExecutionError, TimeoutError


@dataclass(frozen=True)
class ExecutionResult:
    command: Sequence[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    cwd: str


def sanitize_environment() -> Dict[str, str]:
    keep = {"HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "SHELL", "TERM", "USER"}
    env = {key: value for key, value in os.environ.items() if key in keep}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    env.setdefault("TERM", "dumb")
    env["AGENT_SUDO"] = "1"
    env["NO_COLOR"] = "1"
    return env


def run_command(command: Sequence[str], cwd: Optional[Path], timeout_seconds: int) -> ExecutionResult:
    cwd_value = str(cwd) if cwd is not None else os.getcwd()
    start = time.monotonic()
    try:
        completed = subprocess.run(
            list(command),
            cwd=cwd_value,
            env=sanitize_environment(),
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - start) * 1000)
        raise TimeoutError(f"Command timed out after {timeout_seconds} seconds.") from exc
    except OSError as exc:
        raise ExecutionError(str(exc)) from exc
    duration_ms = int((time.monotonic() - start) * 1000)
    return ExecutionResult(
        command=list(command),
        stdout=completed.stdout,
        stderr=completed.stderr,
        exit_code=completed.returncode,
        duration_ms=duration_ms,
        cwd=cwd_value,
    )
