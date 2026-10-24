# The runner protocol (version 1)

How a **host** (anything that stores workflows and decides when they run, such as Foundry Studio) drives the
runner for one run. Implement the endpoints below and you have a host. `foundry-workflow-runner run` is a
small host of its own, inside the runner's process (`src/foundry_workflow_runner/local.py`).

All bodies are JSON (`Content-Type: application/json`). The runner never follows redirects and treats every
non-2xx answer except the ones named here as a refusal. It retries connection failures, 429 and 5xx (except 501)
with capped, jittered exponential backoff, and never other 4xx.

## Starting a run

The host starts one runner process per run (a container, a job execution, a local process) with:

| Variable | Value |
| --- | --- |
| `STUDIO_RUN_URL` | The run's base URL, ending in `/`, for example `https://host.example.com/api/runner/runs/<run id>/`. `https` (plain `http` only to `127.0.0.1`/`localhost`). |
| `STUDIO_RUN_TOKEN` | The run's bearer token. Store only its hash; it must stop working after `finish`, after a cancel and at its expiry (the run's timeout plus some slack). |
| `HTTPS_PROXY` | Optional: the runner's own egress proxy (for the host and signed URLs). Never handed to the workflow. |

The runner reads the token, removes it from its environment and keeps it in memory only. Every call below
carries `Authorization: Bearer <token>`, to `<STUDIO_RUN_URL><name>`.

## `POST start/`

Body `{"runner_version": "1"}`. Answer (only to the first `start` of an attempt; a repeat gets **409**, and the
runner stops without finishing):

```json
{
  "mode": "run",
  "attempt": 1,
  "run_id": "…",
  "dev": false,
  "workflow": {"name": "receipts", "version": 3},
  "entry": {"claude": "/file-receipts"},
  "model": {"relay": true, "protocol": "anthropic", "model": "claude-opus-5-5", "base_url": "<run url>llm"},
  "trigger": {"kind": "cron", "payload": null, "untrusted": false},
  "limits": {"timeout": 1800, "max_turns": 50},
  "approvals": {"ask": ["Bash(git push:*)"]},
  "state": "state/",
  "package_url": "https://storage.example.com/…signed…",
  "package_sha256": "<hex>",
  "state_get_url": "https://storage.example.com/…signed…",
  "state_sha256": "<hex>",
  "upload_url": "<run url>upload-url/",
  "env": {"XERO_TOKEN": "…"},
  "mcp": {"url": "<run url>mcp/", "headers": {}},
  "workload_proxy": "http://run:<token>@proxy.internal.example:3128"
}
```

| Field | Meaning |
| --- | --- |
| `mode` | `run` (run the entry) or `build` (install the source's dependencies and upload the bundle). |
| `entry` | Exactly one of `claude` (a prompt or slash command) or `command` (an argv list). |
| `model` | `null`, or the model through the host's relay: `protocol` `anthropic` (the relay at `<run url>llm/`, Anthropic's Messages API) or `openai` (`<run url>llm/openai/v1/`, OpenAI-compatible). Never a key. |
| `trigger` | What started the run. `payload` is untrusted data; the runner hands it to the workflow as a file. |
| `limits` | `timeout` (seconds, or `30m`-style) and `max_turns` for Claude Code. |
| `state` | The manifest's state directory, or `null`. |
| `package_url` + `package_sha256` | The source tar.gz (build mode) or built bundle (run mode), and its SHA-256. The runner refuses to unpack anything that doesn't match, finishing with `error_code: "integrity"`; `null` for a run that uses the directory as it is (a dev run). |
| `state_get_url` + `state_sha256` | The latest saved state (tar.gz), checked the same way when a digest is given. A 404 means no state yet. |
| `upload_url` | Present when the host takes uploads (state, bundles). Without it state stays where it is. |
| `env` | The workflow's secrets as environment variables. Model credentials never go here. |
| `mcp` | The host's MCP server for the run's connections (streamable HTTP). The runner reaches it only through its loopback relay, which adds the run token; `headers` is unused. |
| `workload_proxy` | The workflow's own egress proxy (a token limited to the manifest's `egress`, plus package registries in build mode), or `null` for none. |

## `POST events/`

`{"events": [...]}`, at most 64 KB and 500 events per batch. Events are numbered from 1 per attempt (`seq`) and
the host must be idempotent on (run, attempt, seq): a failed batch is resent with the same numbers. Exactly these
shapes:

| Type | Fields |
| --- | --- |
| `text` | `{seq, type, text}`: the agent's text (≤ 16 000 chars). |
| `tool` | `{seq, type, id, name, title, status}`: `status` `started`, `ok` or `error`; `title` is a short, value-free description (≤ 300). Never the tool's input or output. |
| `note` | `{seq, type, text}`: the runner's own notes (≤ 2000). |
| `log` | `{seq, type, text}`: one line of the end of the entry's stderr after a failure (≤ 2000), redacted. |

Every string is redacted first: each secret value from `env`, the run token, signed URLs, proxy URLs and known
credential shapes become `[REDACTED]`. Answer with anything 2xx (Studio answers `{accepted, duplicates, last_seq}`).

## `POST heartbeat/`

Body `{}`, sent straight after `start` and then every 30 s. Answer `{"cancel": bool}`. On `true`, or when the
host stops accepting the token (401, 403, 404, 410), the runner stops the entry and finishes `cancelled`.

## Approvals

`POST approvals/` `{"tool": "Bash", "input_summary": "command: git push origin main", "input_sha256": "<hex>"}`
→ 201 `{"approval_id": "…", "state": "pending"}`. The runner asks for calls matching `approvals.ask`, except
tools of the host's own MCP server (`mcp__studio__*`), which the host gates itself when they're called; a host
should refuse those names here (400). `input_summary` is short and redacted; `input_sha256` is the SHA-256 of the
tool input as canonical JSON (sorted keys, no spaces).

`GET approvals/<id>/` → `{"state": "pending" | "approved" | "denied" | "expired"}`. The runner polls every 3 s
until the state changes, the run is cancelled or its time runs out. Tell people while it's pending.

## Uploads

Right before each upload the runner asks for a link: `POST upload-url/`
`{"kind": "state" | "bundle", "size": N, "sha256": "<hex>", "md5": "<base64 of the 16-byte digest>"}` → 201
`{"url", "method": "PUT", "headers", "expires_in"}`. The runner PUTs the file with **exactly** the headers given
(and no `Authorization`). Bind the link to the declared size and MD5 (for Google Cloud Storage: signed
`Content-MD5`, `x-goog-content-length-range: N,N` and `x-goog-if-generation-match: 0`), so the store refuses
other bytes, and compare the stored object's own size and MD5 with what was declared before you use it. A bundle
is uploaded only in build mode, state only in run mode with a state directory.

## `POST finish/`

Run mode: `{"status": "succeeded" | "failed" | "cancelled", "summary"?, "error_code"?, "exit_code"?}`. Build mode:
`{"status", "bundle_sha256", "bundle_size", "build_log_tail"}` (and `error_code` on failure). `error_code` is
`[a-z0-9_]{0,64}`: `timeout` (the runner stopped the entry at its time limit; record it as timed out),
`max_turns`, `exit_code`, `integrity`, `bad_archive`, `download_failed`, `upload_failed`, `build_failed`,
`npm_missing`, `entry_not_found`, `bad_entry`, `no_package`, `runner_error`. The token should stop working after
it.

## The relay paths

The runner's loopback relay forwards exactly two kinds of path to the host, adding `Authorization: Bearer
<run token>` and dropping the workflow's own `Authorization`, `X-Api-Key` and cookies:

- `<run url>mcp/`: the host's MCP server (streamable HTTP: POST, GET for SSE, DELETE).
- `<run url>llm/<path>`: the model. With `protocol: anthropic`, `llm/v1/messages` and
  `llm/v1/messages/count_tokens` (Anthropic's API, streaming); with `openai`, `llm/openai/v1/<path>`
  (`chat/completions`, `responses`, `embeddings`). The host adds the real credentials, checks the model is
  allowed and the run is live, and should rebuild requests from an allowlist of fields.

Responses stream through as they arrive (SSE included).

## Egress tokens

When a host runs workflows behind `egress-proxy/`, both `HTTPS_PROXY` (the runner's) and `workload_proxy` (the
workflow's) are `http://run:<token>@proxy:3128`, where:

```
token   = base64url(payload) + "." + base64url(HMAC-SHA256(key, base64url(payload)))
payload = {"r": "<run id>", "h": ["api.example.com", "*.example.net"], "x": <expiry, unix seconds>}
```

base64url without `=` padding; the MAC is over the encoded segment's ASCII bytes; `key` is the proxy's
`WORKFLOW_EGRESS_KEY`. Give the runner's token only the host and the storage host for signed URLs, and the
workload's token (`r` = `<run id>:workload`) only the manifest's `egress` (plus the package registries in build
mode). `egress-proxy/tests/token_vectors.json` has fixed vectors.

## What the workflow sees

The entry runs as another user in the working directory, with: `STUDIO_RUN_ID`, `STUDIO_ATTEMPT`,
`STUDIO_WORKDIR`, `STUDIO_STATE_DIR` (when `state` is set), `STUDIO_TRIGGER_KIND`, `STUDIO_TRIGGER_FILE` (JSON:
`{kind, payload, untrusted: true}`), `STUDIO_MODEL`, `STUDIO_MCP_CONFIG` and `STUDIO_MCP_URL` (the relay), the
secrets from `env`, the model relay (`ANTHROPIC_BASE_URL` + a dummy `ANTHROPIC_AUTH_TOKEN`, or `OPENAI_BASE_URL`
+ a dummy `OPENAI_API_KEY` for an OpenAI-protocol `command` entry), `HTTPS_PROXY`/`HTTP_PROXY` set to
`workload_proxy` (nothing when it's `null`), and `NO_PROXY=127.0.0.1,localhost`. Never `STUDIO_RUN_TOKEN` or
the runner's proxy.

Claude Code is started as:

```
claude -p <prompt> --output-format stream-json --verbose --max-turns N --mcp-config <file> --strict-mcp-config
       --permission-prompt-tool mcp__studio_runner__permission --settings <file with permissions.ask>
       --setting-sources project --no-session-persistence [--model M] [--append-system-prompt <trigger note>]
```

The `studio_runner` stdio MCP server's `permission` tool receives `{tool_name, input, tool_use_id}` and answers
one text block holding `{"behavior": "allow", "updatedInput": …}` or `{"behavior": "deny", "message": …}`
(checked against Claude Code 2.1.310). Never `bypassPermissions`.
