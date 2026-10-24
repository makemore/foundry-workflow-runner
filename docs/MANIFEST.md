# studio.yaml (version 1)

A workflow is a directory (usually a git repository) with `studio.yaml` at its root:

```yaml
version: 1
name: receipts                 # ^[a-z][a-z0-9-]{1,48}$
description: File receipts from the finance inbox to Drive
entry:
  claude: "/file-receipts"     # a prompt or slash command, run as `claude -p`
  # OR command: ["python", "main.py"]   (an Agent SDK script, or any program)
model: claude-opus-5-5         # optional; default: the host's (or your) default model
triggers:                      # manual runs always work
  - cron: "0 7 * * *"          # five numeric fields
    tz: Europe/London
  - webhook: {}
connections: [google.gmail, google.drive, github]   # a host's connection names
google_account: personal       # personal | workspace
secrets: [XERO_TOKEN]          # names only
egress: [api.xero.com, "*.xero.com"]                 # hosts the workflow may reach
approvals:
  ask: ["Bash(git push:*)", "mcp__studio__gmail_send"]   # Claude Code permission rules
limits: { timeout: 30m, max_turns: 50 }
state: state/                  # a directory kept between runs
```

Leave out what you don't need: defaults apply. The rules, and the exact messages, are in
`src/foundry_workflow_runner/manifest.py`; each message starts with the key path, such as
`triggers[0].cron: must be a five-field cron expression such as "0 7 * * *".`

| Key | Rule |
| --- | --- |
| `version` | `1`. |
| `name` | `^[a-z][a-z0-9-]{1,48}$`. |
| `description` | Text, at most 500 characters. |
| `entry` | Exactly one of `claude` (1–4000 characters) or `command` (1–64 non-empty strings). |
| `model` | A model id, `^[A-Za-z0-9._:@/-]{1,100}$`. A host may allow only some. |
| `triggers` | A list of `{cron, tz?}` (at most 10; numeric fields, lists, ranges and steps; 0 and 7 are Sunday; Vixie day semantics; `tz` an IANA zone, default UTC) and at most one `{webhook: {}}`. |
| `connections` | Names such as `google.gmail` (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`); what they mean is the host's. Ignored by a standalone run. |
| `google_account` | `personal` (default) or `workspace`. |
| `secrets` | Unique `UPPER_SNAKE_CASE` names (≤ 64 chars), not `STUDIO_*`, `ANTHROPIC_*`, `CLAUDE_*`, `HTTP(S)_PROXY`, `NO_PROXY`, `PATH`, `HOME`. Values never go in the file. |
| `egress` | Host names or `*.suffix` wildcards, no IP addresses or ports. Refused: names under `run.app`, `googleapis.com`, `googleusercontent.com`, `goog`, `internal`, `local`, `cloudfunctions.net`, `appspot.com`, names starting `metadata`, wildcards over a public suffix, and the host's own names. |
| `approvals.ask` | Up to 100 Claude Code permission rules: `Tool`, `Tool(spec)`, `mcp__server`, `mcp__server__tool`, `Bash(git push:*)`, `Edit(src/**)`, `WebFetch(domain:example.com)`. |
| `limits.timeout` | `<n>s`, `<n>m` or `<n>h` (or seconds), from 1m to 60m. Default 30m. |
| `limits.max_turns` | 1–500. Default 50. |
| `state` | A relative directory inside the project, not under `.git` or `.claude`. |

Unknown keys are errors. A host may add limits of its own (shorter timeouts, a cron floor across all cron
triggers together, which models are allowed) and says so in the same form.

## The YAML subset

The runner reads `studio.yaml` with a small, strict parser (no dependencies): block mappings and sequences, flow
`[...]` and `{...}`, plain, single- and double-quoted scalars, `|` and `>` block scalars, and comments. Scalars
follow YAML 1.2's core schema: `true`/`false`, `null`/`~`, integers and floats; everything else is text (`yes` and
`on` are text). Anchors, aliases, tags and duplicate keys are errors, so quote a value that starts with `*`, as
in `"*.xero.com"`.

## Permissions in a run

Nobody is at Claude Code's prompt, so the runner's `permission` tool decides each call that the project's own
settings don't already allow:

1. tools of the host's own MCP server (`mcp__studio__*`) are allowed: the host applies `approvals.ask` to them
   itself;
2. a call matching `approvals.ask` waits for a person's approval (the host's, or the terminal's in a standalone
   run);
3. a call allowed by the project's `.claude/settings.json` `permissions.allow` runs;
4. anything else is denied: "not allowed in cloud runs; add it to permissions.allow or approvals.ask".

`approvals.ask` rules are also passed to Claude Code as `permissions.ask`, which wins over allow rules, so a
matching call always reaches the tool. `.claude/settings.local.json` is ignored.
