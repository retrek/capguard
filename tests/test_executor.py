from pathlib import Path

import pytest

from agent_sudo.audit import append_audit_entry, tail_audit_entries
from agent_sudo.executor import run_command


def test_run_command_executes(tmp_path: Path):
    result = run_command(["/bin/echo", "hello"], cwd=tmp_path, timeout_seconds=10)
    assert result.exit_code == 0
    assert result.stdout.strip() == "hello"


def test_run_command_timeout(tmp_path: Path):
    with pytest.raises(Exception):
        run_command(["/bin/sh", "-c", "sleep 2"], cwd=tmp_path, timeout_seconds=1)


def test_audit_write_and_tail(tmp_path: Path):
    audit_path = tmp_path / ".agent-sudo" / "audit.jsonl"
    append_audit_entry(
        audit_path,
        capability="example",
        arguments={"value": "jq"},
        caller="tester",
        command=["/bin/echo", "jq"],
        requires_confirmation=True,
        approved=True,
        exit_code=0,
        duration_ms=12,
        cwd=str(tmp_path),
    )
    tail = tail_audit_entries(audit_path, lines=1)
    assert '"capability": "example"' in tail
