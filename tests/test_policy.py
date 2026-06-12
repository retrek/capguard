from pathlib import Path

import pytest

from agent_sudo.errors import ArgumentError, PolicyError
from agent_sudo.policy import load_policy, resolve_command, validate_arguments


def write_policy(tmp_path: Path, body: str) -> Path:
    policy_path = tmp_path / "agent-sudo.yml"
    policy_path.write_text(body, encoding="utf-8")
    return policy_path


def test_load_and_validate_policy(tmp_path):
    policy_path = write_policy(
        tmp_path,
        """version: 1
settings:
  audit_log: .agent-sudo/audit.jsonl
capabilities:
  install-dev-package:
    description: Install package.
    command:
      - /usr/bin/apt-get
      - install
      - -y
      - "{{ package }}"
    requires_confirmation: true
    args:
      package:
        type: string
        allowlist:
          - jq
          - ripgrep
""",
    )
    policy = load_policy(policy_path)
    capability = policy.capabilities["install-dev-package"]
    assert resolve_command(capability, {"package": "jq"}) == ["/usr/bin/apt-get", "install", "-y", "jq"]


def test_rejects_unknown_argument(tmp_path):
    policy_path = write_policy(
        tmp_path,
        """version: 1
capabilities:
  example:
    description: Example.
    command:
      - /bin/echo
      - "{{ value }}"
    args:
      value:
        type: string
""",
    )
    policy = load_policy(policy_path)
    capability = policy.capabilities["example"]
    with pytest.raises(ArgumentError):
        validate_arguments(capability, {"other": "x"})


def test_rejects_unused_argument_definition(tmp_path):
    policy_path = write_policy(
        tmp_path,
        """version: 1
capabilities:
  example:
    description: Example.
    command:
      - /bin/echo
    args:
      value:
        type: string
""",
    )
    with pytest.raises(PolicyError):
        load_policy(policy_path)


def test_rejects_group_world_writable_policy(tmp_path):
    policy_path = write_policy(
        tmp_path,
        """version: 1
capabilities:
  example:
    description: Example.
    command:
      - /bin/echo
      - hello
""",
    )
    policy_path.chmod(0o666)
    with pytest.raises(PolicyError):
        load_policy(policy_path)
