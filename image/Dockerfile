# The workflow runner image. Build it yourself; no built image is published (LICENCES.md says why):
#
#   docker build -f image/Dockerfile -t foundry-workflow-runner .
#
# The build installs Claude Code from npm: you accept Anthropic's terms for it by building. A host's job
# runs one container per run (STUDIO_RUN_URL, STUDIO_RUN_TOKEN, HTTPS_PROXY in the environment); a
# standalone run is `docker run --rm -it -e ANTHROPIC_API_KEY -v "$PWD:/workspace" foundry-workflow-runner
# /opt/workflow-runner/bin/python -I /opt/workflow-runner/start.py run /workspace`.
#
# Contents, all pinned: Node.js 22 (Debian bookworm slim, by digest), Debian's git, uv, CPython 3.12
# (uv's python-build-standalone build: libedit instead of GNU readline, no gdbm, so no GPL-3.0 library is
# linked into the interpreter), Claude Code (exact npm version), and this repository's runner. start.py
# (the command) drops from root to the runner, uid 10001, which starts Claude Code and the workflow's
# command as uid 10002 (docs/SECURITY.md). Checks: scripts/check-image.sh.
FROM ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff AS uv

FROM node:22-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS runner

ARG CLAUDE_CODE_VERSION=2.1.308
ARG PYTHON_VERSION=3.12.15

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Claude Code: no auto-update, telemetry or error reporting (an egress proxy would refuse them anyway).
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    DISABLE_AUTOUPDATER=1 \
    # uv: real copies in /workspace/.venv so a version bundle carries them.
    UV_PYTHON_INSTALL_DIR=/opt/python \
    UV_LINK_MODE=copy \
    UV_CACHE_DIR=/tmp/uv-cache \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_CACHE=/tmp/npm-cache

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /uvx /usr/local/bin/

# The one Python: `python`/`python3` on PATH, and what uv uses for every project.
RUN uv python install "${PYTHON_VERSION}" \
    && ln -s "$(uv python find --managed-python "${PYTHON_VERSION}")" /usr/local/bin/python3 \
    && ln -s python3 /usr/local/bin/python \
    && rm -rf /tmp/uv-cache
ENV UV_PYTHON=${PYTHON_VERSION} \
    UV_PYTHON_PREFERENCE=only-managed \
    UV_PYTHON_DOWNLOADS=never

RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
    && npm cache clean --force \
    && rm -rf /tmp/npm-cache \
    && claude --version

# The runner (this repository, standard library only) in its own virtualenv on the image's Python.
COPY pyproject.toml README.md LICENSE /tmp/runner-src/
COPY src/ /tmp/runner-src/src/
RUN uv venv /opt/workflow-runner \
    && uv pip install --python /opt/workflow-runner/bin/python --no-deps /tmp/runner-src \
    && rm -rf /tmp/runner-src /tmp/uv-cache

# Two identities (start.py has the details):
#   runner   10001 (group runner 10001, supplementary workspace 10010): the runner process, which keeps
#            only CAP_SETUID/CAP_SETGID so it can start children as the workload;
#   workload 10002 (group workspace 10010): Claude Code and the workflow's own command, no capabilities.
# /workspace is 10001:10010 2770 (setgid): both can work in it, the runner reads what the workload saved.
RUN groupadd --gid 10010 workspace \
    && groupadd --gid 10001 runner \
    && useradd --uid 10001 --gid runner --groups workspace --home-dir /home/runner --create-home \
         --shell /usr/sbin/nologin runner \
    && useradd --uid 10002 --gid workspace --home-dir /home/workload --create-home --shell /bin/bash workload \
    && chmod 0700 /home/runner \
    && chown workload:workspace /home/workload && chmod 2770 /home/workload \
    && mkdir -p /workspace && chown runner:workspace /workspace && chmod 2770 /workspace

COPY image/start.py image/egress_probe.py image/privcheck.py /opt/workflow-runner/

WORKDIR /workspace
# The container starts as root only so that start.py can become the runner with exactly
# CAP_SETUID/CAP_SETGID; nothing else runs as root but tini, which reaps what Claude Code and the
# workflow start.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/workflow-runner/bin/python", "-I", "/opt/workflow-runner/start.py"]
