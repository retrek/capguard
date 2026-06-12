from pathlib import Path

from agent_sudo.cli import main


def test_cli_list_and_explain(tmp_path: Path, capsys):
    policy_path = tmp_path / "agent-sudo.yml"
    policy_path.write_text(
        """version: 1
capabilities:
  example:
    description: Example capability.
    command:
      - /bin/echo
      - "hello"
""",
        encoding="utf-8",
    )
    assert main(["--policy", str(policy_path), "list"]) == 0
    out = capsys.readouterr().out
    assert "example: Example capability." in out
    assert main(["--policy", str(policy_path), "explain", "example"]) == 0


def test_cli_run_writes_audit_log(tmp_path: Path, capsys):
    policy_path = tmp_path / "agent-sudo.yml"
    policy_path.write_text(
        """version: 1
settings:
  audit_log: .agent-sudo/audit.jsonl
capabilities:
  hello:
    description: Say hello.
    command:
      - /bin/echo
      - hello
    requires_confirmation: false
""",
        encoding="utf-8",
    )
    assert main(["--policy", str(policy_path), "run", "hello"]) == 0
    assert capsys.readouterr().out.strip() == "hello"
    audit_log = tmp_path / ".agent-sudo" / "audit.jsonl"
    assert audit_log.exists()
    assert '"capability": "hello"' in audit_log.read_text(encoding="utf-8")


def test_cli_run_logs_failed_execution(tmp_path: Path):
    policy_path = tmp_path / "agent-sudo.yml"
    policy_path.write_text(
        """version: 1
capabilities:
  fail:
    description: Fail.
    command:
      - /usr/bin/false
    requires_confirmation: false
""",
        encoding="utf-8",
    )
    assert main(["--policy", str(policy_path), "run", "fail"]) == 1
    audit_log = tmp_path / ".agent-sudo" / "audit.jsonl"
    contents = audit_log.read_text(encoding="utf-8")
    assert '"capability": "fail"' in contents
    assert '"exit_code": 1' in contents
