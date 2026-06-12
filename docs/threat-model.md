# Threat Model

Agent Sudo Broker is designed to narrow privileged execution for local AI coding agents.

## Assumptions

- The coding agent may be useful but should not be trusted with ambient host privilege.
- The policy file is maintained by the user or project maintainer.
- The local machine can still be compromised by malicious software, hostile policies, or explicit allowlist decisions.

## What it helps with

- Avoiding arbitrary `sudo` command execution
- Avoiding hidden shell expansion in approved commands
- Limiting package installation to declared allowlists
- Capturing structured audit logs for privileged runs
- Making privileged actions inspectable and reusable

## What it does not solve

- A malicious policy file
- A compromised broker binary
- Kernel-level compromise
- Secrets that are already accessible elsewhere on the machine
- User-approved dangerous policy changes

## Security posture

The broker fails closed on unknown capabilities, missing arguments, invalid policy structure, and shell-style command paths when shell mode is disabled.
