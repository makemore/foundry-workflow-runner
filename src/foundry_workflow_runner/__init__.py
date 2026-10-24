"""foundry-workflow-runner: runs one workflow (a Claude Code project or any command, described by studio.yaml).

Two ways to use it:

- ``foundry-workflow-runner run ./project``: on your own computer (or in the image), with your own model key and
  no host at all (local.py).
- ``python -m foundry_workflow_runner`` with ``STUDIO_RUN_URL`` and ``STUDIO_RUN_TOKEN`` set: one run for a host
  that implements the runner protocol (docs/PROTOCOL.md), such as Studio's runner job.

Standard library only, Python 3.10 or later. What reaches the host (events, notes, errors, the build log tail) is
sanitised: agent text and tool names, titles and statuses only, never raw tool input or output, with known
credential shapes and every secret value replaced by ``[REDACTED]``. The run token stays in the runner: the
workflow runs as another user (isolation.py) and reaches the host's MCP server and model relay through a loopback
relay (relay.py). docs/SECURITY.md has the threat model.
"""

RUNNER_VERSION = "1"
