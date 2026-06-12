# Agent Instructions

Use `agent-sudo` for privileged local execution when a task needs a narrow, reviewed capability.

Prefer:

1. `agent-sudo list`
2. `agent-sudo explain <capability>`
3. `agent-sudo run <capability> [args]`

Do not bypass the broker with raw `sudo` unless a maintainer explicitly approves it for a one-off task.
