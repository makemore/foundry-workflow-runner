"""Standalone mode (``foundry-workflow-runner run DIR``): no host at all, your own model key (which never reaches
the workflow), approvals asked at the terminal, state kept in place, no egress proxy unless given one."""

import json
import os
import pty
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SRC = str(Path(__file__).resolve().parent.parent / "src")
FAKE_CLAUDE = str(Path(__file__).resolve().parent / "fake_claude.py")
USER_KEY = "sk-ant-api03-the-users-own-key-0000000000"


class FakeAnthropic:
    """The model API upstream: streams a short reply and records the credentials and paths it got."""

    def __init__(self):
        self.seen = []
        upstream = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                upstream.seen.append((self.path, {key.lower(): value for key, value in self.headers.items()}, body))
                frames = [{"type": "message_start", "message": {"id": "m", "type": "message", "role": "assistant",
                                                                "content": [], "model": "x", "usage": {}}},
                          {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Hi"}},
                          {"type": "content_block_delta", "index": 0,
                           "delta": {"type": "text_delta", "text": " there."}},
                          {"type": "message_stop"}]
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                for frame in frames:
                    chunk = f"event: {frame['type']}\ndata: {json.dumps(frame)}\n\n".encode()
                    self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.flush()
                self.wfile.write(b"0\r\n\r\n")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def upstream():
    fake = FakeAnthropic()
    yield fake
    fake.close()


@pytest.fixture
def claude_bin(tmp_path):
    directory = tmp_path / "bin"
    directory.mkdir()
    script = directory / "claude"
    script.write_text(f"#!/bin/sh\nexec {sys.executable} {FAKE_CLAUDE} \"$@\"\n")
    script.chmod(0o755)
    return directory


def workflow(tmp_path, text, files=None):
    root = tmp_path / "project"
    (root / ".claude").mkdir(parents=True)
    (root / "studio.yaml").write_text(text)
    (root / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(ls:*)"]}}))
    for name, content in (files or {}).items():
        (root / name).write_text(content)
    return root


def environment(tmp_path, claude_bin, upstream=None, **extra):
    env = {"PATH": f"{claude_bin}:{os.environ['PATH']}", "PYTHONPATH": SRC, "HOME": str(tmp_path),
           "STUDIO_RUNNER_INTERVALS": "heartbeat=0.2,poll=0.05,events=0.1,grace=2",
           "FAKE_CLAUDE_LOG": str(tmp_path / "claude.log")}
    if upstream is not None:
        env.update({"ANTHROPIC_API_KEY": USER_KEY, "ANTHROPIC_BASE_URL": upstream.url})
    env.update(extra)
    return env


def runner(*args, env, stdin=subprocess.DEVNULL):
    return subprocess.run([sys.executable, "-m", "foundry_workflow_runner", *map(str, args)], env=env,
                          capture_output=True, text=True, timeout=60, stdin=stdin)


def test_a_claude_code_workflow_runs_here_with_your_key_kept_from_it(tmp_path, claude_bin, upstream):
    root = workflow(tmp_path, "version: 1\nname: receipts\nentry:\n  claude: basic\nsecrets: [XERO_TOKEN]\n")
    env_file = tmp_path / "local.env"
    env_file.write_text("XERO_TOKEN=xero-local-value-789\n")
    done = runner("run", root, "--env-file", env_file, env=environment(tmp_path, claude_bin, upstream))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "Running receipts here (secrets: XERO_TOKEN)." in done.stdout
    assert "Filing 3 receipts." in done.stdout and "[ok] Bash: List receipts" in done.stdout
    assert "Filed 3 receipts (allow). llm=200:Hi there.:streamed" in done.stdout
    # The upstream got your key from this process; the workflow only ever had the relay and a dummy key.
    path, headers, _ = upstream.seen[0]
    assert path.startswith("/v1/messages") and headers["x-api-key"] == USER_KEY and "authorization" not in headers
    call = json.loads((tmp_path / "claude.log").read_text().splitlines()[0])
    assert "ANTHROPIC_API_KEY" not in call["env"] and USER_KEY not in json.dumps(call)
    assert call["relay"]["ANTHROPIC_AUTH_TOKEN"] == "studio-relay"
    assert call["relay"]["ANTHROPIC_BASE_URL"].startswith("http://127.0.0.1:")
    assert call["relay"]["XERO_TOKEN"] == "xero-local-value-789"
    assert USER_KEY not in done.stdout + done.stderr and "xero-local-value-789" not in done.stdout


def test_approvals_are_refused_when_non_interactive(tmp_path, claude_bin, upstream):
    root = workflow(tmp_path, 'version: 1\nname: pusher\nentry:\n  claude: approval\n'
                              'approvals:\n  ask: ["Bash(git push:*)"]\n')
    done = runner("run", root, "--non-interactive", env=environment(tmp_path, claude_bin, upstream))
    assert done.returncode == 0, done.stdout + done.stderr
    assert "[approval] Bash: refused (--non-interactive)." in done.stdout
    assert "push: deny: A person denied Bash." in done.stdout


def test_approvals_are_asked_at_the_terminal(tmp_path, claude_bin, upstream):
    root = workflow(tmp_path, 'version: 1\nname: pusher\nentry:\n  claude: approval\n'
                              'approvals:\n  ask: ["Bash(git push:*)"]\n')
    controller, terminal = pty.openpty()
    process = subprocess.Popen([sys.executable, "-m", "foundry_workflow_runner", "run", str(root)],
                               env=environment(tmp_path, claude_bin, upstream), stdin=terminal,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    os.close(terminal)
    try:
        os.write(controller, b"y\n")  # The terminal holds the answer until the prompt reads it.
        out, err = process.communicate(timeout=60)
    finally:
        os.close(controller)
    assert process.returncode == 0, out + err
    assert "The workflow wants to run Bash:\n  command: git push origin main" in out
    assert "push: allow: " in out


def test_command_entries_keep_state_in_place_and_get_no_proxy_unless_given_one(tmp_path, claude_bin):
    script = ("import json, os\n"
              "p = os.path.join(os.environ['STUDIO_STATE_DIR'], 'count')\n"
              "os.makedirs(os.environ['STUDIO_STATE_DIR'], exist_ok=True)\n"
              "n = int(open(p).read()) if os.path.exists(p) else 0\n"
              "open(p, 'w').write(str(n + 1))\n"
              "print('count', n + 1, 'proxy', os.environ.get('HTTPS_PROXY'), 'model', "
              "os.environ.get('ANTHROPIC_BASE_URL'))\n")
    root = workflow(tmp_path, 'version: 1\nname: counter\nentry:\n  command: ["python3", "main.py"]\nstate: state/\n',
                    {"main.py": script})
    env = environment(tmp_path, claude_bin)
    assert runner("run", root, env=env).returncode == 0
    second = runner("run", root, env=env)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "count 2 proxy None model None" in second.stdout  # No key: no model; no proxy given: none.
    assert (root / "state" / "count").read_text() == "2"
    proxied = runner("run", root, "--proxy", "http://run:tok@127.0.0.1:3128", env=env)
    assert "proxy http://run:tok@127.0.0.1:3128" not in proxied.stdout  # Redacted in events and output...
    assert "count 3 proxy [REDACTED]" in proxied.stdout  # ...but it's the workflow's proxy.


def test_claude_entries_need_a_model_key_and_studio_yaml_must_be_valid(tmp_path, claude_bin):
    root = workflow(tmp_path, "version: 1\nname: receipts\nentry:\n  claude: basic\n")
    done = runner("run", root, env=environment(tmp_path, claude_bin))
    assert done.returncode == 2 and "need ANTHROPIC_API_KEY" in done.stderr
    (root / "studio.yaml").write_text("version: 1\nname: Bad\nentry: {}\n")
    done = runner("validate", root, env=environment(tmp_path, claude_bin))
    assert done.returncode == 2 and "name: must match" in done.stderr
    (root / "studio.yaml").write_text("version: 1\nname: good\nentry:\n  claude: go\n")
    assert runner("validate", root, env=environment(tmp_path, claude_bin)).stdout.strip() == \
        "studio.yaml is valid: good"
