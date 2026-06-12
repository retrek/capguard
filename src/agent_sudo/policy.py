from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

import yaml

from .errors import ArgumentError, PolicyError


PLACEHOLDER_RE = re.compile(r"{{\s*([A-Za-z_][A-Za-z0-9_]*)\s*}}")
SHELL_BASENAMES = {"sh", "bash", "zsh", "dash", "fish"}


@dataclass(frozen=True)
class ArgumentSpec:
    name: str
    type: str = "string"
    allowlist: Optional[List[str]] = None
    regex: Optional[str] = None


@dataclass(frozen=True)
class Capability:
    name: str
    description: str
    command: List[str]
    requires_confirmation: bool = True
    timeout_seconds: Optional[int] = None
    working_directory: Optional[str] = None
    args: Dict[str, ArgumentSpec] = field(default_factory=dict)

    def placeholders(self) -> List[str]:
        found = []
        for token in self.command:
            for placeholder in PLACEHOLDER_RE.findall(token):
                if placeholder not in found:
                    found.append(placeholder)
        return found


@dataclass(frozen=True)
class Settings:
    audit_log: str = ".agent-sudo/audit.jsonl"
    default_timeout_seconds: int = 60
    require_absolute_commands: bool = True
    deny_shell_by_default: bool = True


@dataclass(frozen=True)
class Policy:
    version: int
    capabilities: Dict[str, Capability]
    settings: Settings
    path: Path

    @property
    def base_dir(self) -> Path:
        return self.path.parent

    def audit_log_path(self) -> Path:
        audit_log = Path(self.settings.audit_log)
        if audit_log.is_absolute():
            return audit_log
        return self.base_dir / audit_log

    def list_capabilities(self) -> Sequence[Capability]:
        return [self.capabilities[name] for name in sorted(self.capabilities)]


def load_policy(path: Union[os.PathLike, str]) -> Policy:
    policy_path = Path(path).expanduser().resolve()
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {policy_path}")
    _validate_policy_permissions(policy_path)
    with policy_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise PolicyError("Policy file must contain a YAML mapping.")
    version = raw.get("version")
    if version != 1:
        raise PolicyError("Policy version must be 1.")
    settings = _parse_settings(raw.get("settings") or {})
    capabilities = _parse_capabilities(raw.get("capabilities") or {}, settings)
    if not capabilities:
        raise PolicyError("Policy must define at least one capability.")
    return Policy(version=1, capabilities=capabilities, settings=settings, path=policy_path)


def _parse_settings(raw: Any) -> Settings:
    if not isinstance(raw, dict):
        raise PolicyError("settings must be a mapping.")
    return Settings(
        audit_log=str(raw.get("audit_log", ".agent-sudo/audit.jsonl")),
        default_timeout_seconds=int(raw.get("default_timeout_seconds", 60)),
        require_absolute_commands=bool(raw.get("require_absolute_commands", True)),
        deny_shell_by_default=bool(raw.get("deny_shell_by_default", True)),
    )


def _parse_capabilities(raw: Any, settings: Settings) -> Dict[str, Capability]:
    if not isinstance(raw, dict):
        raise PolicyError("capabilities must be a mapping.")
    capabilities: Dict[str, Capability] = {}
    for name, spec in raw.items():
        if not isinstance(name, str) or not name.strip():
            raise PolicyError("Capability names must be non-empty strings.")
        if not isinstance(spec, dict):
            raise PolicyError(f"Capability {name!r} must be a mapping.")
        description = str(spec.get("description", "")).strip()
        if not description:
            raise PolicyError(f"Capability {name!r} must include a description.")
        command = _parse_command(spec.get("command"), name)
        args = _parse_args(spec.get("args") or {}, name)
        timeout_seconds = spec.get("timeout_seconds")
        working_directory = spec.get("working_directory")
        capability = Capability(
            name=name,
            description=description,
            command=command,
            requires_confirmation=bool(spec.get("requires_confirmation", True)),
            timeout_seconds=int(timeout_seconds) if timeout_seconds is not None else None,
            working_directory=str(working_directory) if working_directory is not None else None,
            args=args,
        )
        _validate_capability(capability, settings)
        capabilities[name] = capability
    return capabilities


def _parse_command(raw: Any, name: str) -> List[str]:
    if not isinstance(raw, list) or not raw:
        raise PolicyError(f"Capability {name!r} must define a non-empty command list.")
    command = []
    for item in raw:
        if not isinstance(item, str) or not item:
            raise PolicyError(f"Capability {name!r} command entries must be non-empty strings.")
        command.append(item)
    return command


def _parse_args(raw: Any, capability_name: str) -> Dict[str, ArgumentSpec]:
    if not isinstance(raw, dict):
        raise PolicyError(f"Capability {capability_name!r} args must be a mapping.")
    result: Dict[str, ArgumentSpec] = {}
    for arg_name, arg_spec in raw.items():
        if not isinstance(arg_name, str) or not arg_name.strip():
            raise PolicyError(f"Capability {capability_name!r} arg names must be non-empty strings.")
        if not isinstance(arg_spec, dict):
            raise PolicyError(f"Capability {capability_name!r} arg {arg_name!r} must be a mapping.")
        allowlist = arg_spec.get("allowlist")
        if allowlist is not None:
            if not isinstance(allowlist, list) or not all(isinstance(item, str) for item in allowlist):
                raise PolicyError(f"Capability {capability_name!r} arg {arg_name!r} allowlist must be a list of strings.")
            allowlist = [str(item) for item in allowlist]
        regex = arg_spec.get("regex")
        if regex is not None and not isinstance(regex, str):
            raise PolicyError(f"Capability {capability_name!r} arg {arg_name!r} regex must be a string.")
        result[arg_name] = ArgumentSpec(
            name=arg_name,
            type=str(arg_spec.get("type", "string")),
            allowlist=allowlist,
            regex=regex,
        )
    return result


def _validate_capability(capability: Capability, settings: Settings) -> None:
    placeholders = capability.placeholders()
    for placeholder in placeholders:
        if placeholder not in capability.args:
            raise PolicyError(
                f"Capability {capability.name!r} references unknown argument {placeholder!r} in its command."
            )
    for arg_name in capability.args:
        if arg_name not in placeholders:
            raise PolicyError(f"Capability {capability.name!r} defines unused argument {arg_name!r}.")
    if settings.require_absolute_commands:
        executable = capability.command[0]
        if not executable.startswith("/"):
            raise PolicyError(f"Capability {capability.name!r} must use an absolute executable path.")
    if settings.deny_shell_by_default:
        if _looks_like_shell_command(capability.command):
            raise PolicyError(f"Capability {capability.name!r} cannot use shell executables when shell mode is disabled.")


def _validate_policy_permissions(policy_path: Path) -> None:
    mode = policy_path.stat().st_mode
    if mode & 0o022:
        raise PolicyError(f"Policy file is group/world-writable: {policy_path}")


def _looks_like_shell_command(command: Sequence[str]) -> bool:
    if not command:
        return False
    executable_name = Path(command[0]).name
    if executable_name in SHELL_BASENAMES:
        return True
    if executable_name == "env" and len(command) > 1 and Path(command[1]).name in SHELL_BASENAMES:
        return True
    return any(Path(token).name in SHELL_BASENAMES for token in command[1:])


def validate_arguments(capability: Capability, arguments: Dict[str, str]) -> Dict[str, str]:
    normalized = {name.replace("-", "_"): value for name, value in arguments.items()}
    missing = [name for name in capability.args if name not in normalized]
    if missing:
        raise ArgumentError(f"Missing required arguments: {', '.join(sorted(missing))}.")
    unexpected = [name for name in normalized if name not in capability.args]
    if unexpected:
        raise ArgumentError(f"Unexpected arguments: {', '.join(sorted(unexpected))}.")
    for name, spec in capability.args.items():
        value = normalized[name]
        if spec.type != "string":
            raise ArgumentError(f"Unsupported type for {name!r}: {spec.type}.")
        if spec.allowlist is not None and value not in spec.allowlist:
            raise ArgumentError(f"Argument {name!r} must be one of: {', '.join(spec.allowlist)}.")
        if spec.regex is not None and re.fullmatch(spec.regex, value) is None:
            raise ArgumentError(f"Argument {name!r} does not match the required pattern.")
    return normalized


def resolve_command(capability: Capability, arguments: Dict[str, str]) -> List[str]:
    resolved = []
    for token in capability.command:
        resolved.append(PLACEHOLDER_RE.sub(lambda match: arguments[match.group(1)], token))
    return resolved


def describe_capability(capability: Capability) -> str:
    lines = [
        f"Capability: {capability.name}",
        f"Description: {capability.description}",
        f"Command: {' '.join(capability.command)}",
        f"Requires confirmation: {'yes' if capability.requires_confirmation else 'no'}",
        f"Timeout seconds: {capability.timeout_seconds if capability.timeout_seconds is not None else 'policy default'}",
    ]
    if capability.working_directory:
        lines.append(f"Working directory: {capability.working_directory}")
    if capability.args:
        lines.append("Arguments:")
        for name in sorted(capability.args):
            spec = capability.args[name]
            details = [f"type={spec.type}"]
            if spec.allowlist is not None:
                details.append(f"allowlist={', '.join(spec.allowlist)}")
            if spec.regex is not None:
                details.append(f"regex={spec.regex}")
            lines.append(f"  - {name}: {', '.join(details)}")
    return "\n".join(lines)
