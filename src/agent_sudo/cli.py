from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence

from .approvals import prompt_for_approval
from .audit import append_audit_entry, tail_audit_entries
from .doctor import check_policy_health
from .errors import ApprovalDenied, ArgumentError, BrokerError, ExecutionError, PolicyError, TimeoutError
from .executor import run_command
from .policy import describe_capability, load_policy, resolve_command, validate_arguments


DEFAULT_POLICY_FILE = "agent-sudo.yml"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agent-sudo")
    parser.add_argument("--policy", default=DEFAULT_POLICY_FILE, help="Path to the policy file.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="Validate the policy file.")

    init_parser = subparsers.add_parser("init", help="Create a starter policy file.")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing files.")

    subparsers.add_parser("list", help="List capabilities.")

    explain_parser = subparsers.add_parser("explain", help="Explain a capability.")
    explain_parser.add_argument("capability")

    run_parser = subparsers.add_parser("run", help="Run a capability.")
    run_parser.add_argument("capability")
    run_parser.add_argument("--dry-run", action="store_true", help="Show the resolved command without running it.")
    run_parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts.")
    run_parser.add_argument("args", nargs=argparse.REMAINDER)

    audit_parser = subparsers.add_parser("audit", help="Audit log helpers.")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command", required=True)
    tail_parser = audit_subparsers.add_parser("tail", help="Print recent audit entries.")
    tail_parser.add_argument("--lines", type=int, default=10)

    subparsers.add_parser("doctor", help="Check policy health.")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    try:
        return dispatch(ns)
    except BrokerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def dispatch(ns: argparse.Namespace) -> int:
    policy = None
    if ns.command != "init":
        policy = load_policy(ns.policy)
    if ns.command == "validate":
        print(f"Policy OK: {policy.path}")
        return 0
    if ns.command == "init":
        return command_init(Path(ns.policy), ns.force)
    if ns.command == "list":
        for capability in policy.list_capabilities():
            print(f"{capability.name}: {capability.description}")
        return 0
    if ns.command == "explain":
        capability = _get_capability(policy, ns.capability)
        print(describe_capability(capability))
        return 0
    if ns.command == "run":
        return command_run(policy, ns.capability, ns.args, ns.dry_run, ns.yes)
    if ns.command == "audit":
        if ns.audit_command == "tail":
            print(tail_audit_entries(policy.audit_log_path(), ns.lines), end="")
            return 0
    if ns.command == "doctor":
        return command_doctor(policy)
    raise BrokerError(f"Unknown command: {ns.command}")


def command_init(policy_path: Path, force: bool) -> int:
    if policy_path.exists() and not force:
        raise PolicyError(f"Policy file already exists: {policy_path}")
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        """version: 1
settings:
  audit_log: .agent-sudo/audit.jsonl
  default_timeout_seconds: 60
  require_absolute_commands: true
  deny_shell_by_default: true
capabilities:
  restart-dev-service:
    description: Restart the local development service.
    command:
      - /bin/echo
      - restart-dev-service
    requires_confirmation: true
    timeout_seconds: 20
""",
        encoding="utf-8",
    )
    (policy_path.parent / ".agent-sudo").mkdir(parents=True, exist_ok=True)
    print(f"Created {policy_path}")
    return 0


def command_run(policy, capability_name: str, raw_args: Sequence[str], dry_run: bool, yes: bool) -> int:
    capability = _get_capability(policy, capability_name)
    parsed_args = parse_run_args(raw_args)
    arguments = validate_arguments(capability, parsed_args)
    command = resolve_command(capability, arguments)
    timeout_seconds = capability.timeout_seconds or policy.settings.default_timeout_seconds
    cwd = _resolve_working_directory(policy, capability.working_directory)
    approved = not capability.requires_confirmation
    exit_code = None
    duration_ms = None
    error = None
    if capability.requires_confirmation and not yes:
        prompt_for_approval(capability.name, capability.description, command)
        approved = True
    elif capability.requires_confirmation and yes:
        approved = True
    try:
        if dry_run:
            print("DRY RUN:", " ".join(command))
            exit_code = 0
            return 0
        result = run_command(command, cwd=cwd, timeout_seconds=timeout_seconds)
        exit_code = result.exit_code
        duration_ms = result.duration_ms
        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        return result.exit_code
    except BrokerError as exc:
        error = str(exc)
        raise
    finally:
        append_audit_entry(
            policy.audit_log_path(),
            capability.name,
            arguments,
            caller=os.environ.get("USER", "unknown"),
            command=command,
            requires_confirmation=capability.requires_confirmation,
            approved=approved,
            exit_code=exit_code,
            duration_ms=duration_ms,
            cwd=str(cwd) if cwd is not None else os.getcwd(),
            error=error,
        )


def command_doctor(policy) -> int:
    issues = check_policy_health(policy)
    if issues:
        for issue in issues:
            print(issue, file=sys.stderr)
        return 1
    print("Policy health OK")
    return 0


def parse_run_args(raw_args: Sequence[str]) -> Dict[str, str]:
    args: Dict[str, str] = {}
    tokens = list(raw_args)
    while tokens and tokens[0] == "--":
        tokens.pop(0)
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            raise ArgumentError(f"Unexpected positional argument: {token}")
        key_value = token[2:]
        if "=" in key_value:
            key, value = key_value.split("=", 1)
        else:
            if index + 1 >= len(tokens):
                raise ArgumentError(f"Missing value for argument {token}")
            value = tokens[index + 1]
            if value.startswith("--"):
                raise ArgumentError(f"Missing value for argument {token}")
            key = key_value
            index += 1
        args[key.replace("-", "_")] = value
        index += 1
    return args


def _get_capability(policy, capability_name: str):
    try:
        return policy.capabilities[capability_name]
    except KeyError as exc:
        raise PolicyError(f"Unknown capability: {capability_name}") from exc


def _resolve_working_directory(policy, working_directory: Optional[str]):
    if working_directory is None:
        return None
    path = Path(working_directory)
    if not path.is_absolute():
        path = policy.base_dir / path
    if not path.exists():
        raise PolicyError(f"Working directory does not exist: {path}")
    if not path.is_dir():
        raise PolicyError(f"Working directory is not a directory: {path}")
    return path


if __name__ == "__main__":
    raise SystemExit(main())
