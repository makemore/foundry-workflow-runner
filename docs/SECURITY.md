# Security model

The workflow is untrusted: its code is the author's, and an agent in it can be prompt-injected by anything it
reads (email, web pages, trigger payloads). The runner is the trusted part. It holds the run's token, talks to
the host and decides what the workflow may do. The design keeps everything the runner holds away from the
workflow, and keeps the workflow inside what its manifest declared.

## What the workflow must never get

| Asset | How it's kept out |
| --- | --- |
| The run token (`STUDIO_RUN_TOKEN`), which can post events, ask for approvals, upload state and finish the run | Read once, removed from the runner's environment, kept in memory. The workflow runs as another user, so it can't read `/proc/<runner>/environ` or the runner's memory. It reaches the host only through the loopback relay, which adds the token. |
| The model key | Never in the run: the host's relay (or, standalone, this process) adds it. The workflow gets `ANTHROPIC_BASE_URL`/`OPENAI_BASE_URL` pointing at the loopback relay and a dummy key. |
| The runner's egress | The runner's `HTTPS_PROXY` token may reach the host and the storage host for signed URLs. It is never inherited: the workflow gets only `workload_proxy`, whose token allows its manifest's `egress`, or no proxy at all. |
| Signed URLs | Download URLs are used by the runner only. Upload links are asked for right before each upload, bound to size and MD5, create-only. |
| Other runs' data | One process (or container) per run. Each token is scoped to one run, and the host checks it on every call. |

## Users

The runner image (`image/start.py`) starts as root under tini only to set up directories, then becomes the
**runner** (uid 10001). The runner keeps exactly CAP_SETUID and CAP_SETGID, with nothing inheritable or ambient,
and sets `no_new_privs`. It starts every child as the **workload**, uid 10002 in group 10010, with
`subprocess`'s `user=`/`group=`, `extra_groups=[]` and umask 007. The child's `execve` drops every capability.
The workload can't:
- read the runner's or PID 1's `/proc/*/environ` or `/proc/*/mem` (another uid, and the runner is not dumpable
  after its uid change);
- signal the runner or set its uid back;
- read `/home/runner` or the runner's 0600 files.

What the workload writes in `/workspace` (setgid 10010, 2770) stays readable by the runner. `privcheck.py`
checks all of this in the image, and the isolation tests run it.

Everything that touches the workflow's files runs as the workload too: unpacking the source, bundle and state,
installing dependencies (`uv`, `npm ci`, whose install scripts are the author's code), and packing the bundle
and state. The runner reads project files only through a link-refusing reader, so a bundle can't point it at
its own files. After each step the runner stops every process of the workload user. A process that left its
session is stopped too, through a helper started as the workload user: the runner has no CAP_KILL.

Started as root without `start.py`, the runner does the same with a saved uid of 0. On your own computer
(`foundry-workflow-runner run`) everything is one user, which only `STUDIO_RUNNER_SHARED_UID=1` (set by `run`)
allows. That user is you, with your own files.

## The loopback relay

The relay listens on `127.0.0.1` under an unguessable per-run path secret. It forwards exactly
`/<secret>/mcp` and `/<secret>/llm/<path>`, and refuses `..` segments, `//` and anything else. It adds the run
token and drops `Authorization`, `X-Api-Key` and cookies from the workflow's requests. The secret is in the
workflow's MCP config and environment. That is deliberate: it grants only those two paths, for this run, while
it runs.

The `permission` tool reaches the runner over a second loopback socket with a per-run key. All it can do is ask
for a decision, which is the runner's.

## Egress

On a host that uses `egress-proxy/`, the runner network's only way out is the proxy. A connection is let through
only if all of these hold:
- it's `CONNECT host:443` with a valid, unexpired token for the run;
- the host is a DNS name the token allows (never an IP literal), and not on the deny list (Google's front ends
  and internal names, metadata, `.internal`/`.local`);
- every address the name resolves to is public, and the proxy dials the address it checked;
- the TLS ClientHello's SNI is that same name.

Logs are value-free (run id, host, decision, byte counts).

Residual risks:
- **HTTP inside TLS.** The proxy can't see a `Host` header inside TLS. A workflow could reach another virtual
  host on an allowed name's front end.
- **DNS.** If the runner network can resolve names, lookups are a low-bandwidth channel. Block DNS there, or
  accept that it can leak only what the workflow already holds.
- **Allowed hosts are trusted.** What a workflow sends to a host in its own `egress` list is up to it. Keep
  `egress` small.

## Events and output

The runner sends agent text and tool names, short titles and statuses. It never sends raw tool input or output.
Every string is redacted: secret values, the run token, signed and proxy URLs, private keys, `sk-ant-`,
`ghp_`/`github_pat_`, AWS, Slack, Google and Stripe keys, JWTs, bearer tokens and `password=`-style assignments.
Errors are fixed sentences and codes, never values. Agent text can still contain what the agent chose to say;
treat a run's events like its output.

## Approvals

Calls matching `approvals.ask` wait for a person. The approval carries a short, redacted summary and the SHA-256
of the exact input; the runner allows only that call. Tools of the host's MCP server are gated by the host
itself, so they can't be approved here. Anything not allowed by the project's own settings, or asked for, is
denied. The runner never uses `bypassPermissions`.

## Reporting

Report security issues privately to the repository's owners (GitHub's "Report a vulnerability"), not in public
issues.
