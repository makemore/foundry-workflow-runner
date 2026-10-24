#!/usr/bin/env bash
# Inside the built runner image, as root, offline (scripts/check-image.sh mounts image/checks/ at /checks): a
# standalone run of the real Claude Code through start.py (runner 10001, Claude Code 10002) against a fake
# model (fake_model.py) that asks for one Write. Only the project's own .claude/settings.json allows it. Passes
# only if Claude Code didn't log "not been trusted", the Write was allowed (no error result) and the file is
# there, written by the workload user, and the runner's own home has no .claude.json.
set -u
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }

cat > /workspace/studio.yaml <<'YAML'
version: 1
name: trust-check
entry:
  claude: Write the file the check asks for.
limits:
  max_turns: 4
YAML
mkdir -p /workspace/.claude
cat > /workspace/.claude/settings.json <<'JSON'
{"permissions": {"allow": ["Write", "Edit", "Read"]}}
JSON
chown -R 10001:10010 /workspace && chmod -R g+rwX /workspace
# The settings are the workload's own (0600), so the runner's permission tool can't read them and has nothing
# to allow the Write with: only Claude Code applying the project's settings itself can allow it.
chown 10002:10010 /workspace/.claude/settings.json && chmod 0600 /workspace/.claude/settings.json

# Claude Code's stderr, which the runner keeps to itself unless the run fails.
cat > /usr/local/bin/claude-check <<'SH'
#!/bin/sh
exec claude "$@" 2>>/tmp/claude-stderr.log
SH
chmod 0755 /usr/local/bin/claude-check
touch /tmp/claude-stderr.log && chown 10002:10010 /tmp/claude-stderr.log

python -I /checks/fake_model.py --port 8765 --file /workspace/hello.txt --log /tmp/model.log &
for _ in $(seq 50); do python -c 'import socket; socket.create_connection(("127.0.0.1", 8765), 1)' 2>/dev/null && break; sleep 0.1; done

STUDIO_CLAUDE=/usr/local/bin/claude-check ANTHROPIC_API_KEY=check-dummy-key ANTHROPIC_BASE_URL=http://127.0.0.1:8765 \
    timeout 240 /opt/workflow-runner/bin/python -I /opt/workflow-runner/start.py run /workspace --non-interactive \
    > /tmp/run.log 2>&1
code=$?
echo "--- runner (exit $code)"; sed 's/^/  /' /tmp/run.log | tail -n 20
echo "--- Claude Code's stderr"; sed 's/^/  /' /tmp/claude-stderr.log | tail -n 20
echo "--- model requests"; sed 's/^/  /' /tmp/model.log

check "the run succeeded"                       "test $code = 0"
check "no 'not been trusted' warning"           "! grep -q 'not been trusted' /tmp/claude-stderr.log /tmp/run.log"
check "no permissions.allow entries ignored"    "! grep -q 'Ignoring .* permissions' /tmp/claude-stderr.log /tmp/run.log"
check "the model got a tool result"             "grep -q '\"tool_results\": 1' /tmp/model.log"
check "the Write was allowed (no error result)" "grep -q '\"tool_results\": 1, \"errors\": 0' /tmp/model.log"
check "the file was written"                    "grep -q 'Written by Claude Code' /workspace/hello.txt"
check "by the workload user"                    "test \"\$(stat -c %u /workspace/hello.txt)\" = 10002"
check "the workload's config trusts /workspace" "python -c \"import json; c=json.load(open('/home/workload/.claude.json')); assert c['projects']['/workspace']['hasTrustDialogAccepted'] is True\""
check "and is the workload's own (0600)"        "test \"\$(stat -c %u:%a /home/workload/.claude.json)\" = 10002:600"
check "the runner's home has no .claude.json"   "test ! -e /home/runner/.claude.json"
exit $fail
