# foundry-workflow-runner

Runs a **workflow**: a directory with a `studio.yaml` at its root, whose entry is a Claude Code prompt or slash
command (`claude -p`) or any command (an Agent SDK script, a Python or Node program). The same `studio.yaml`
runs:

- **on your own computer**, with your own model key and no host at all: `foundry-workflow-runner run ./project`;
- **in the runner image**, on your own machine, cron or cloud (build the image yourself, see below);
- **for a host** that implements the runner protocol ([docs/PROTOCOL.md](docs/PROTOCOL.md)), such as
  Foundry Studio, which starts one runner per run and streams its events into a thread.

You can always leave: nothing here depends on a hosted service. Apache-2.0 ([LICENSE](LICENSE)).

## Run a workflow here

```sh
uv tool install git+https://github.com/makemore/foundry-workflow-runner@<commit>   # or: pip install the same URL
export ANTHROPIC_API_KEY=...        # your own key; the workflow itself never sees it
foundry-workflow-runner validate ./project
foundry-workflow-runner run ./project [--trigger manual|cron|webhook] [--payload payload.json] \
    [--env-file .env] [--non-interactive] [--proxy http://user:pass@proxy:3128] [--model MODEL]
```

- **The model.** Claude Code runs with `ANTHROPIC_BASE_URL` pointed at a loopback relay and a dummy
  `ANTHROPIC_AUTH_TOKEN`; the relay adds your `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`, to
  `ANTHROPIC_BASE_URL` if you set one) on the way out. A `command` entry gets the same relay, or, with only
  `OPENAI_API_KEY` set, an OpenAI-compatible one (`OPENAI_BASE_URL`).
- **Secrets** are the names `studio.yaml` declares, with values from `--env-file` or this shell. Nothing else
  from the file is read, and values are redacted from everything printed.
- **Approvals.** Tool calls matching `approvals.ask` are asked at this terminal (`--non-interactive` refuses them
  all). Anything else not allowed by the project's own `.claude/settings.json` is denied: there is nobody at
  Claude Code's prompt.
- **Trust.** Claude Code applies the project's own `.claude/settings.json` only in a directory you have trusted
  in it. The runner never changes your `~/.claude.json`: if the project isn't trusted, the run says so; open it
  once in Claude Code and accept the trust prompt. In the image (and on a host) the runner trusts `/workspace`
  for the workload user itself ([docs/SECURITY.md](docs/SECURITY.md#claude-codes-workspace-trust)).
- **State** (`state:` in studio.yaml) stays where it is in the project; the project runs in place.
- **Egress.** No proxy unless you pass `--proxy`; then it is the workflow's only way out.
- **Triggers.** There's no scheduler here: run it from your own cron, CI or webhook handler, with `--trigger`
  and `--payload` saying what started it (the payload is handed over as untrusted data).

Exit status: 0 succeeded, 1 failed, 2 refused before starting, 130 cancelled (Ctrl-C).

## The runner image

No built image is published: it contains Claude Code (under Anthropic's commercial terms) and Debian's GPL
programs, which we don't redistribute ([LICENCES.md](LICENCES.md)). Build it yourself; the build installs Claude
Code from npm under your own acceptance of Anthropic's terms:

```sh
docker build -f image/Dockerfile -t foundry-workflow-runner .
docker run --rm -it -e ANTHROPIC_API_KEY -v "$PWD/project:/workspace" foundry-workflow-runner \
    /opt/workflow-runner/bin/python -I /opt/workflow-runner/start.py run /workspace
scripts/check-image.sh            # the pinned tools, the privilege drop (privcheck.py), and the real Claude
                                  # Code applying the project's settings (fake model), with no network
```

Inside, `start.py` drops from root to the runner (uid 10001, keeping only CAP_SETUID/CAP_SETGID), which runs
Claude Code and the workflow's command as the workload (uid 10002) with no capabilities: the workflow can't read
the runner's environment, memory or files ([docs/SECURITY.md](docs/SECURITY.md)). With no arguments the image
runs one hosted run from `STUDIO_RUN_URL` and `STUDIO_RUN_TOKEN`.

## What's here

| Path | What |
| --- | --- |
| `src/foundry_workflow_runner/` | The runner (standard library only, Python 3.10+): protocol client, build and run modes, the `permission` MCP tool, sanitised events, the loopback relay, user separation, studio.yaml, standalone mode. |
| `image/` | The runner image: `Dockerfile`, `start.py` (root → runner → workload), `privcheck.py`, `egress_probe.py`. |
| `egress-proxy/` | An HTTPS-only CONNECT proxy for runner networks: signed per-run tokens, host rules, no private addresses, SNI checks. |
| `claude-plugin/` | A Claude Code plugin whose `studio-workflows` skill teaches studio.yaml and the deploy loop. |
| `docs/` | [PROTOCOL.md](docs/PROTOCOL.md) (implement a host), [MANIFEST.md](docs/MANIFEST.md) (studio.yaml v1), [SECURITY.md](docs/SECURITY.md) (threat model). |

## Tests

Everything runs in local Docker, offline, with the checkout read-only (CI runs the same):

```sh
scripts/test-docker.sh pytest 3.10     # runner, manifest and standalone tests (also 3.11, 3.12)
scripts/test-docker.sh isolation       # the uid split as root, through image/start.py and privcheck.py
scripts/test-docker.sh proxy           # the egress proxy
scripts/test-docker.sh all
```

The tests use a strict fake host and a fake `claude` that speaks MCP to the real permission server. The flags
and the permission tool's shape were checked against Claude Code 2.1.310.

## Using it from another project

Pin a commit. Install with `pip install git+https://github.com/makemore/foundry-workflow-runner@<commit>`, or
copy `src/foundry_workflow_runner/` into your tree with the commit recorded. There is no PyPI package.
