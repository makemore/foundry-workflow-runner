#!/usr/bin/env bash
# Builds the runner image (image/Dockerfile; this installs Claude Code from npm under your acceptance of
# Anthropic's terms) and checks it in local Docker with no network: the pinned tools answer, the
# directories and users are right, foundry_workflow_runner imports, and the privilege drop (privcheck.py).
# Then the real Claude Code, run through start.py against a fake model, must apply the project's own
# .claude/settings.json (the runner trusts /workspace for the workload user): image/checks/trust_check.sh.
# The runner's own behaviour is tested by scripts/test-docker.sh. Usage (from anywhere):
#   scripts/check-image.sh             # the checks
#   scripts/check-image.sh trust       # only the Claude Code trust check
#   scripts/check-image.sh licences    # installed Debian, npm and Python packages + licences
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image=${WORKFLOW_RUNNER_TEST_IMAGE:-foundry-workflow-runner:check}
name="workflow-runner-test-$(date +%s)-$$"

docker build -q -f "$root/image/Dockerfile" -t "$image" "$root" >/dev/null
# Docker's default capabilities for root; start.py keeps only CAP_SETUID/CAP_SETGID of them.
run=(docker run --rm --name "$name" --network none --security-opt no-new-privileges
     --entrypoint /bin/bash "$image")

trust_check() {
    echo "--- Claude Code in the image applies the project's settings (real Claude Code, fake model, offline)"
    docker run --rm --name "$name-trust" --network none --security-opt no-new-privileges \
        -v "$root/image/checks:/checks:ro" --entrypoint /bin/bash "$image" /checks/trust_check.sh
}

if [[ "${1:-}" == trust ]]; then
    trust_check
    exit
fi

if [[ "${1:-}" == licences ]]; then
    exec "${run[@]}" -c '
echo "## Debian packages (dpkg; licence from /usr/share/doc/<pkg>/copyright, DEP-5 License: fields)"
for p in $(dpkg-query -W -f="\${Package}\n" | sort); do
  f=/usr/share/doc/$p/copyright
  l=$( [ -f "$f" ] && grep -h "^License:" "$f" | sed "s/^License: *//" | sort -u | tr "\n" ";" )
  echo "$p $(dpkg-query -W -f="\${Version}" "$p")	${l:-see /usr/share/doc/$p/copyright}"
done
echo; echo "## npm (global)"
cd /usr/local/lib/node_modules && for d in npm corepack @anthropic-ai/*; do
  [ -f "$d/package.json" ] && node -e "const p=require(\"./$d/package.json\"); console.log(p.name+\"@\"+p.version+\"\t\"+(p.license||\"?\"))"
done
node -e "console.log(\"node@\"+process.version+\"\tMIT (bundles: see node LICENSE)\")"
echo; echo "## npm (bundled in npm)"
cd /usr/local/lib/node_modules/npm/node_modules && for d in $(ls -d */ @*/* 2>/dev/null | sed "s#/\$##" | grep -v "^@[^/]*\$"); do
  [ -f "$d/package.json" ] && node -e "const p=require(\"./$d/package.json\"); console.log(p.name+\"@\"+p.version+\"\t\"+(typeof p.license===\"string\"?p.license:JSON.stringify(p.license||p.licenses)))"
done | sort -t"	" -k2 | awk -F"\t" "{print \$2}" | sort | uniq -c
echo; echo "## Python (runner venv)"
/opt/workflow-runner/bin/python -c "
from importlib.metadata import distributions
for d in distributions(): print(d.metadata[\"Name\"]+\"==\"+d.version+\"\t\"+(d.metadata.get(\"License-Expression\") or d.metadata.get(\"License\") or \"\"))"
echo; echo "## uv"; uv --version'
fi

printf 'Container: %s\n' "$name"
"${run[@]}" -c '
set -u
fail=0
check() { if eval "$2" >/dev/null 2>&1; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
check "claude is the pinned version"   "claude --version | grep -q \"^2\.1\.308\""
check "uv answers"                     "uv --version"
check "git answers"                    "git --version"
check "python is 3.12"                 "python -c \"import sys; assert sys.version_info[:2] == (3, 12)\""
check "no GNU readline or gdbm"        "! (ldd /opt/python/*/lib/python3.12/lib-dynload/*.so 2>/dev/null | grep -E -q \"libreadline|libgdbm\") && ! python -c \"import _gdbm\""
check "uv uses the image Python"       "uv venv /tmp/probe-venv && /tmp/probe-venv/bin/python -c \"import sys; assert sys.version_info[:2] == (3, 12)\""
check "node is 22"                     "node --version | grep -q ^v22\."
check "npm answers"                    "npm --version"
check "starts as root (start.py drops)" "test \"\$(id -u)\" = 0"
check "/workspace is 10001:10010 2770"  "test \"\$(stat -c %u:%g:%a /workspace)\" = 10001:10010:2770"
check "workload home is 10002:10010"    "test \"\$(stat -c %u:%g:%a /home/workload)\" = 10002:10010:2770"
check "runner home is private"          "test \"\$(stat -c %u:%a /home/runner)\" = 10001:700"
check "egress probe runs"              "python /opt/workflow-runner/egress_probe.py --help"
check "tini is there"                  "test -x /usr/bin/tini"
check "foundry_workflow_runner imports" "/opt/workflow-runner/bin/python -c \"import foundry_workflow_runner.runner\""
claude --help > /tmp/claude-help.txt
# Flags the runner uses (docs/PROTOCOL.md). --max-turns is accepted but not listed in --help.
check "claude accepts --max-turns"     "claude --max-turns 2>&1 | grep -q \"max-turns <turns>\""
for flag in -p --output-format --verbose --mcp-config --permission-prompt-tool --model; do
  if grep -q -- "$flag" /tmp/claude-help.txt; then echo "ok   claude --help lists $flag"; else echo "FAIL claude --help lists $flag"; fail=1; fi
done
/opt/workflow-runner/bin/python -I /opt/workflow-runner/privcheck.py || fail=1
exit $fail'
status=$?
# The least a root container needs for start.py: CHOWN, FOWNER (the directories), SETUID, SETGID.
echo "--- privcheck with only CHOWN, FOWNER, SETUID, SETGID"
docker run --rm --network none --cap-drop ALL --cap-add CHOWN --cap-add FOWNER --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges "$image" /opt/workflow-runner/bin/python -I /opt/workflow-runner/privcheck.py || status=1
trust_check || status=1
exit $status
