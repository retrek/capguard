# Agent Sudo Broker

Agent Sudo Broker is a small local CLI for least-privilege privileged execution in AI-assisted workflows.

It lets you define named capabilities in a YAML policy file, then run only those reviewed capabilities with typed arguments, confirmation prompts, timeouts, and JSONL audit logs.

## What it does

- Lists named privileged capabilities
- Validates YAML policy files
- Runs static command vectors without shell expansion
- Enforces simple string argument rules with allowlists or regexes
- Prompts for confirmation when a capability requires it
- Writes structured JSONL audit records

## Quick start

```bash
agent-sudo init
agent-sudo validate
agent-sudo list
agent-sudo explain install-dev-package
agent-sudo run install-dev-package --package jq
```

## Policy file

Create an `agent-sudo.yml` file in your project root. A minimal example:

```yaml
version: 1
settings:
  audit_log: .agent-sudo/audit.jsonl
  default_timeout_seconds: 60
  require_absolute_commands: true
  deny_shell_by_default: true
capabilities:
  install-dev-package:
    description: Install an allowlisted development package.
    command:
      - /usr/bin/apt-get
      - install
      - -y
      - "{{ package }}"
    requires_confirmation: true
    timeout_seconds: 180
    args:
      package:
        type: string
        allowlist:
          - jq
          - ripgrep
```

## Safety model

This tool is designed to avoid ambient sudo. The broker validates the policy first, then only executes the named capability the policy describes.

It does not attempt to solve malicious policy files, a compromised host, or a malicious command explicitly allowlisted by the maintainer.

## Commands

- `agent-sudo init`
- `agent-sudo validate`
- `agent-sudo list`
- `agent-sudo explain <capability>`
- `agent-sudo run <capability> [--arg value]`
- `agent-sudo audit tail`
- `agent-sudo doctor`
