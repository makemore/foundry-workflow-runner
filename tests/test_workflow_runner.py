"""The workflow runner against a strict fake host (tests/workflow_fakes.py) and a fake ``claude``: build mode,
run mode, approvals (approve, deny, expire), cancel, timeout, value-free events, and secrets never leaving the runner."""

import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest

from workflow_fakes import FakeHost

SRC = str(Path(__file__).resolve().parent.parent / "src")
FAKE_CLAUDE = str(Path(__file__).resolve().parent / "fake_claude.py")
SECRET = "xero-secret-value-123"
FAST = "heartbeat=0.2,poll=0.05,events=0.1,grace=2"

sys.path.insert(0, SRC)
from foundry_workflow_runner.permissions import input_sha256, rule_matches  # noqa: E402
from foundry_workflow_runner.protocol import ProtocolError, RunClient, Transport  # noqa: E402
from foundry_workflow_runner.redact import Redactor  # noqa: E402


@pytest.fixture
def studio():
    fake = FakeHost()
    yield fake
    fake.close()


@pytest.fixture
def claude_bin(tmp_path):
    """A directory with a `claude` on PATH that is the fake."""
    directory = tmp_path / "bin"
    directory.mkdir()
    script = directory / "claude"
    script.write_text(f"#!/bin/sh\nexec {sys.executable} {FAKE_CLAUDE} \"$@\"\n")
    script.chmod(0o755)
    return directory


def spec(prompt="basic", **extra):
    value = {"mode": "run", "attempt": 1, "entry": {"claude": prompt}, "upload_url": "<run url>upload-url/",
             "trigger": {"kind": "manual", "payload": None}, "limits": {"timeout": 60, "max_turns": 7},
             "approvals": {"ask": ["Bash(git push:*)", "mcp__studio__gmail_send"]},
             "model": {"relay": True, "protocol": "anthropic", "model": "claude-opus-5-5",
                       "base_url": "https://studio.example.test/studio/api/workflow-runner/runs/x/llm"},
             # A Studio that still sent a model key: with the relay the workflow never gets it.
             "env": {"XERO_TOKEN": SECRET, "ANTHROPIC_API_KEY": "sk-ant-api03-model-key-for-tests-0000"},
             "mcp": {"url": "https://studio.example.test/studio/api/workflow-runner/runs/x/mcp/",
                     "headers": {"Authorization": "Bearer mcp-header-token-abcdef"}}}
    value.update(extra)
    return value


def run_runner(url, run, workdir, claude_bin, tmp_path, *, extra_env=None, wait=True):
    env = {"PATH": f"{claude_bin}:{os.environ['PATH']}", "PYTHONPATH": SRC, "STUDIO_RUN_URL": url,
           "STUDIO_RUNNER_SHARED_UID": "1",
           "STUDIO_RUN_TOKEN": run.token, "STUDIO_WORKDIR": str(workdir), "STUDIO_RUNNER_INTERVALS": FAST,
           "FAKE_CLAUDE_LOG": str(tmp_path / "claude.log"), "HOME": str(tmp_path), **(extra_env or {})}
    process = subprocess.Popen([sys.executable, "-m", "foundry_workflow_runner"], env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    if not wait:
        return process
    out, err = process.communicate(timeout=60)
    return process.returncode, out, err


def all_text(run, out="", err=""):
    return json.dumps(run.ordered_events()) + json.dumps(run.finished) + out + err


def claude_calls(tmp_path):
    return [json.loads(line) for line in (tmp_path / "claude.log").read_text().splitlines()]


def project(tmp_path, settings=None):
    workdir = tmp_path / "work"
    (workdir / ".claude").mkdir(parents=True)
    (workdir / "studio.yaml").write_text("version: 1\nname: receipts\nentry:\n  claude: basic\n")
    if settings is not None:
        (workdir / ".claude" / "settings.json").write_text(json.dumps(settings))
    return workdir


def test_run_mode_streams_sanitised_events_and_finishes(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("basic"))
    workdir = project(tmp_path, {"permissions": {"allow": ["Bash(ls:*)"]}})
    code, out, err = run_runner(url, run, workdir, claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished == {"status": "succeeded", "exit_code": 0, "summary":
                            "Filed 3 receipts (allow). llm=200:Hello from the relay.:streamed mcp=200:tools/list"}
    # Studio saw the run token on both relayed calls, and none of the workflow's own (dummy) credentials.
    assert [path.split("?")[0] for path, _ in run.relayed] == ["llm/v1/messages", "mcp/"]
    assert run.relayed[0][0] == "llm/v1/messages"
    for _, headers in run.relayed:
        assert headers["authorization"] == f"Bearer {run.token}" and "x-api-key" not in headers
    events = run.ordered_events()
    assert [event["seq"] for event in events] == list(range(1, len(events) + 1))
    kinds = [(event["type"], event.get("status")) for event in events]
    assert ("text", None) in kinds and ("tool", "started") in kinds and ("tool", "ok") in kinds
    tool = next(event for event in events if event["type"] == "tool")
    assert tool == {"seq": tool["seq"], "type": "tool", "id": "toolu_1", "name": "Bash",
                    "title": "Bash: List receipts", "status": "started"}
    text = all_text(run)
    assert "a.pdf" not in text and "ls receipts" not in text  # Never raw tool input or output.
    assert "private" not in text  # Thinking stays out.
    assert run.heartbeats >= 1

    call = claude_calls(tmp_path)[0]
    argv = call["argv"]
    assert argv[:3] == ["-p", "basic", "--output-format"]
    for flag, value in (("--output-format", "stream-json"), ("--max-turns", "7"),
                        ("--permission-prompt-tool", "mcp__studio_runner__permission"),
                        ("--setting-sources", "project"), ("--model", "claude-opus-5-5")):
        assert argv[argv.index(flag) + 1] == value
    assert "--verbose" in argv and "--strict-mcp-config" in argv
    assert "bypassPermissions" not in json.dumps(argv) and "--dangerously-skip-permissions" not in argv
    assert call["settings"] == {"permissions": {"ask": ["Bash(git push:*)", "mcp__studio__gmail_send"]}}
    assert "STUDIO_RUN_TOKEN" not in call["env"] and "STUDIO_RUN_URL" not in call["env"]
    assert "ANTHROPIC_API_KEY" not in call["env"]
    assert {"XERO_TOKEN", "STUDIO_RUN_ID", "STUDIO_TRIGGER_FILE", "STUDIO_MCP_CONFIG"} <= set(call["env"])
    relay = call["relay"]
    assert re.fullmatch(r"http://127\.0\.0\.1:[0-9]+/[A-Za-z0-9_-]{40,}/llm", relay["ANTHROPIC_BASE_URL"])
    assert relay["ANTHROPIC_AUTH_TOKEN"] == "studio-relay" and run.token not in json.dumps(call)
    assert "127.0.0.1" in relay["NO_PROXY"].split(",") and "localhost" in relay["NO_PROXY"].split(",")
    assert relay["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
    assert "--append-system-prompt" not in argv  # No payload, no note.


def test_approval_approved_after_waiting(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("approval"))
    run.approval_script["Bash"] = ["pending", "pending", "approved"]
    code, _, err = run_runner(url, run, project(tmp_path, {"permissions": {"allow": ["Bash(git:*)"]}}),
                              claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == "push: allow: "
    request = run.approval_requests[0]
    assert request["tool"] == "Bash" and request["input_summary"] == "command: git push origin main"
    assert request["input_sha256"] == input_sha256({"command": "git push origin main",
                                                    "description": "Push the changes"})
    assert run.approval_polls["ap1"] == 3
    notes = [event["text"] for event in run.ordered_events() if event["type"] == "note"]
    assert "Waiting for a person to approve Bash." in notes and "Approved: Bash." in notes


@pytest.mark.parametrize("state, message", [("denied", "A person denied Bash."),
                                            ("expired", "Nobody approved Bash in time; it expired.")])
def test_approval_denied_or_expired_denies_the_call(studio, claude_bin, tmp_path, state, message):
    run, url = studio.add_run(spec("approval"))
    run.approval_script["Bash"] = ["pending", state]
    code, _, err = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == f"push: deny: {message}"
    assert any(event["type"] == "tool" and event["status"] == "error" for event in run.ordered_events())


def test_calls_not_allowed_are_denied_with_the_fixed_message(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("deny"))
    code, _, err = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == ("write: deny: Write is not allowed in cloud runs; add it to "
                                       "permissions.allow or approvals.ask.")
    assert not run.approval_requests


def test_studio_tools_pass_through_because_studio_asks_for_them_itself(studio, claude_bin, tmp_path):
    """mcp__studio__gmail_send is in approvals.ask, but Studio enforces that in its MCP server (and refuses it
    at approvals/), so the permission tool lets it through rather than asking twice."""
    run, url = studio.add_run(spec("denied_by_person"))
    code, _, err = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == "send: allow" and run.approval_requests == []


def test_secrets_never_reach_events_finish_or_stdout(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("secrets"))
    code, out, err = run_runner(url, run, project(tmp_path, {"permissions": {"allow": ["Bash(curl:*)"]}}),
                                claude_bin, tmp_path)
    assert code == 1
    text = all_text(run, out, err)
    assert SECRET not in text
    assert "sk-ant-api03-abcdefghijklmnopqrstuv" not in text and "ghp_abcdefghijklmnopqrstuvwx" not in text
    assert "sk-ant-api03-model-key-for-tests" not in text and "mcp-header-token-abcdef" not in text
    assert run.token not in text
    assert "[REDACTED]" in text
    assert run.finished["status"] == "failed" and run.finished["error_code"] == "exit_code"
    assert run.finished["exit_code"] == 1
    logs = [event["text"] for event in run.ordered_events() if event["type"] == "log"]
    assert "debug: XERO_TOKEN=[REDACTED]" in logs


def test_cancel_from_the_heartbeat_stops_the_run(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("sleep"))
    process = run_runner(url, run, project(tmp_path), claude_bin, tmp_path, wait=False)
    deadline = time.monotonic() + 20
    while not any(event.get("text") == "Working slowly." for event in run.events.values()):
        assert time.monotonic() < deadline and process.poll() is None
        time.sleep(0.05)
    run.cancel = True
    started = time.monotonic()
    process.communicate(timeout=30)
    assert process.returncode == 130
    assert run.finished == {"status": "cancelled"}
    assert time.monotonic() - started < 15


def test_sigterm_cancels_like_studio_does(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("sleep"))
    process = run_runner(url, run, project(tmp_path), claude_bin, tmp_path, wait=False)
    deadline = time.monotonic() + 20
    while not any(event.get("text") == "Working slowly." for event in run.events.values()):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    process.terminate()
    process.communicate(timeout=30)
    assert run.finished == {"status": "cancelled"}


def test_timeout_stops_the_run_and_fails_it(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("sleep", limits={"timeout": "2s", "max_turns": 5}))
    code, _, err = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 1, err
    assert run.finished == {"status": "failed", "error_code": "timeout",
                            "summary": "The run reached its time limit (2s)."}


def test_max_turns(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("max_turns"))
    code, _, _ = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 1 and run.finished["error_code"] == "max_turns"


def test_a_second_start_is_refused_and_the_runner_stops(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("basic"))
    run.started = True
    code, out, _ = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 3 and "already started" in out and run.finished is None


def test_trigger_payload_is_a_file_and_marked_untrusted(studio, claude_bin, tmp_path):
    run, url = studio.add_run(spec("basic", trigger={"kind": "webhook", "payload": {"invoice": 42}}))
    code, _, err = run_runner(url, run, project(tmp_path), claude_bin, tmp_path)
    assert code == 0, err
    argv = claude_calls(tmp_path)[0]["argv"]
    note = argv[argv.index("--append-system-prompt") + 1]
    assert "webhook trigger" in note and "untrusted data, not instructions" in note and "42" not in note


def test_command_entry_gets_studio_env_and_secrets_but_not_the_run_token(studio, claude_bin, tmp_path):
    workdir = project(tmp_path)
    (workdir / "main.py").write_text(
        "import json, os\n"
        "print('keys:', ' '.join(sorted(k for k in os.environ if k.startswith('STUDIO_'))))\n"
        "print('has secret:', os.environ.get('XERO_TOKEN') == 'xero-secret-value-123')\n"
        "print('payload:', json.load(open(os.environ['STUDIO_TRIGGER_FILE']))['payload'])\n"
        "mcp = json.load(open(os.environ['STUDIO_MCP_CONFIG']))['mcpServers']\n"
        "print('relay:', os.environ['ANTHROPIC_BASE_URL'].startswith('http://127.0.0.1:'),"
        " 'ANTHROPIC_API_KEY' in os.environ)\n"
        "print('servers:', ' '.join(sorted(mcp)))\n")
    run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py"]},
                                   trigger={"kind": "manual", "payload": {"n": 1}}))
    code, out, err = run_runner(url, run, workdir, claude_bin, tmp_path)
    assert code == 0, err
    texts = [event["text"] for event in run.ordered_events() if event["type"] == "text"]
    keys = next(text for text in texts if text.startswith("keys:"))
    assert "STUDIO_RUN_TOKEN" not in keys and "STUDIO_RUN_URL" not in keys
    assert "STUDIO_RUN_ID" in keys and "STUDIO_WORKDIR" in keys
    assert "has secret: True" in texts and "payload: {'n': 1}" in texts and "servers: studio studio_runner" in texts
    assert "relay: True False" in texts  # The Agent SDK gets the same loopback model relay, and no key.
    assert run.finished == {"status": "succeeded", "summary": "servers: studio studio_runner", "exit_code": 0}


def _tar(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _blob(studio, name, files):
    """Put a tar.gz in the fake bucket; returns (signed GET url, its sha256)."""
    studio.blobs[name] = _tar(files)
    return studio.blob_url(name), hashlib.sha256(studio.blobs[name]).hexdigest()


def test_build_mode_installs_nothing_and_uploads_the_bundle(studio, claude_bin, tmp_path):
    source, digest = _blob(studio, "src1", {"studio.yaml": b"version: 1\n", "main.py": b"print('hi')\n"})
    run, url = studio.add_run({"mode": "build", "attempt": 1, "package_url": source, "package_sha256": digest,
                               # Start's upload URL is never used: the runner asks upload-url/ for a fresh one.
                               "bundle_put_url": studio.blob_url("stale"), "limits": {"timeout": 600}})
    code, _, err = run_runner(url, run, tmp_path / "build", claude_bin, tmp_path)
    assert code == 0, err
    bundle = studio.blobs[run.uploaded_blob]
    assert run.uploaded_blob.startswith("bundle-") and "stale" not in studio.blobs
    assert run.upload_requests == [{"kind": "bundle", "size": len(bundle), "sha256": hashlib.sha256(bundle).hexdigest(),
                                    "md5": base64.b64encode(hashlib.md5(bundle).digest()).decode()}]
    assert run.finished["status"] == "succeeded"
    assert run.finished["bundle_sha256"] == hashlib.sha256(bundle).hexdigest()
    assert run.finished["bundle_size"] == len(bundle)
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tar:
        assert sorted(tar.getnames()) == ["main.py", "studio.yaml"]
    notes = [event["text"] for event in run.ordered_events() if event["type"] == "note"]
    assert "No dependencies to install." in notes


def test_build_mode_failure_reports_the_redacted_log_tail(studio, claude_bin, tmp_path):
    source, digest = _blob(studio, "src2", {"package-lock.json": b"{}", "package.json": b"{}"})
    run, url = studio.add_run({"mode": "build", "attempt": 1, "package_url": source, "package_sha256": digest,
                               "env": {"NPM_TOKEN": "npm-secret-xyz"}})
    npm = claude_bin / "npm"
    npm.write_text("#!/bin/sh\necho 'npm ERR! auth npm-secret-xyz failed' >&2\nexit 1\n")
    npm.chmod(0o755)
    code, _, _ = run_runner(url, run, tmp_path / "build2", claude_bin, tmp_path)
    assert code == 1
    assert run.finished["status"] == "failed" and run.finished["error_code"] == "build_failed"
    assert "npm ERR! auth [REDACTED] failed" in run.finished["build_log_tail"]
    assert "npm-secret-xyz" not in all_text(run)
    assert not run.upload_requests


@pytest.mark.parametrize("mode", ["build", "run"])
@pytest.mark.parametrize("digest", ["0" * 64, None, "not-a-digest"])
def test_a_download_that_doesnt_match_its_sha256_is_never_unpacked(studio, claude_bin, tmp_path, mode, digest):
    source, _ = _blob(studio, "tampered", {"studio.yaml": b"version: 1\n", "planted.txt": b"x"})
    run, url = studio.add_run({**spec(), "mode": mode, "package_url": source,
                               **({"package_sha256": digest} if digest else {})})
    code, _, _ = run_runner(url, run, tmp_path / "work", claude_bin, tmp_path)
    assert code == 1 and run.finished["error_code"] == "integrity"
    assert not (tmp_path / "work" / "planted.txt").exists() and not run.upload_requests


def test_run_mode_unpacks_the_bundle_and_restores_and_saves_state(studio, claude_bin, tmp_path):
    bundle, digest = _blob(studio, "bundle3", {
        "studio.yaml": b"version: 1\nstate: state/\n",
        "main.py": b"import os\np = os.path.join(os.environ['STUDIO_STATE_DIR'], 'count')\n"
                   b"n = int(open(p).read()) if os.path.exists(p) else 0\n"
                   b"open(p, 'w').write(str(n + 1))\nprint('count', n + 1)\n"})
    saved, _ = _blob(studio, "state3", {"count": b"41"})
    run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py"]}, package_url=bundle,
                                   package_sha256=digest, state="state/", state_get_url=saved,
                                   state_put_url=studio.blob_url("stale")))
    code, _, err = run_runner(url, run, tmp_path / "cloud", claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == "count 42"
    assert "stale" not in studio.blobs and [row["kind"] for row in run.upload_requests] == ["state"]
    with tarfile.open(fileobj=io.BytesIO(studio.blobs[run.uploaded_blob]), mode="r:gz") as tar:
        assert tar.extractfile("count").read() == b"42"


def test_saved_state_is_checked_against_its_sha256(studio, claude_bin, tmp_path):
    bundle, digest = _blob(studio, "bundle4", {"studio.yaml": b"version: 1\n", "main.py": b"print(1)\n"})
    saved, _ = _blob(studio, "state4", {"count": b"1"})
    run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py"]}, package_url=bundle,
                                   package_sha256=digest, state="state/", state_get_url=saved,
                                   state_sha256="f" * 64))
    code, _, _ = run_runner(url, run, tmp_path / "cloud", claude_bin, tmp_path)
    assert code == 1 and run.finished["error_code"] == "integrity"
    assert not (tmp_path / "cloud" / "state").exists()


def test_an_openai_protocol_workspace_gives_command_entries_the_openai_relay(studio, claude_bin, tmp_path):
    workdir = project(tmp_path)
    (workdir / "main.py").write_text(
        "import os\n"
        "print('openai:', os.environ['OPENAI_BASE_URL'].startswith('http://127.0.0.1:'),"
        " os.environ['OPENAI_BASE_URL'].endswith('/llm/openai/v1'), os.environ['OPENAI_API_KEY'],"
        " 'ANTHROPIC_BASE_URL' in os.environ)\n")
    run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py"]}, env={"OPENAI_API_KEY": "sk-real"},
                                   model={"relay": True, "protocol": "openai", "model": "gpt-5",
                                          "base_url": "https://studio.example.test/x/llm/openai/v1"}))
    code, _, err = run_runner(url, run, workdir, claude_bin, tmp_path)
    assert code == 0, err
    assert run.finished["summary"] == "openai: True True studio-relay False"


def test_unsafe_archives_are_refused(studio, claude_bin, tmp_path):
    evil, digest = _blob(studio, "evil", {"../escape.txt": b"x"})
    run, url = studio.add_run(spec(package_url=evil, package_sha256=digest))
    code, _, _ = run_runner(url, run, tmp_path / "cloud", claude_bin, tmp_path)
    assert code == 1 and run.finished["error_code"] == "bad_archive"
    assert run.finished["summary"] == "The archive has a path outside its directory."
    assert not (tmp_path / "escape.txt").exists()


def test_the_runner_refuses_to_share_its_user_unless_told_to(studio, claude_bin, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("as root the runner isolates the workflow instead")
    run, url = studio.add_run(spec())
    code, out, _ = run_runner(url, run, project(tmp_path), claude_bin, tmp_path,
                              extra_env={"STUDIO_RUNNER_SHARED_UID": "0"})
    assert code == 2 and "must start as root" in out and not run.started


def test_the_relay_forwards_only_its_two_paths(studio):
    from foundry_workflow_runner.relay import Relay
    import http.client

    run, url = studio.add_run(spec())
    run.started = True
    relay = Relay(url, run.token, Transport(environ={}))
    try:
        def post(path):
            connection = http.client.HTTPConnection("127.0.0.1", relay.port, timeout=5)
            connection.request("POST", path, body=b"{}", headers={"Content-Type": "application/json",
                                                                  "Authorization": "Bearer guess"})
            response = connection.getresponse()
            return response.status, response.read()
        for path in ("/wrong-secret/mcp", f"/{relay.secret}/start/", f"/{relay.secret}/finish/",
                     f"/{relay.secret}/llm/../finish/", f"/{relay.secret}/mcpx", f"/{relay.secret}//llm/v1/messages"):
            assert post(path)[0] == 404, path
        assert run.relayed == [] and run.finished is None
        status, body = post(f"/{relay.secret}/mcp")
        assert status == 200 and json.loads(body)["result"] == {"echo": None}
        assert run.relayed[0][1]["authorization"] == f"Bearer {run.token}"
    finally:
        relay.close()


class RecordingProxy:
    """A CONNECT proxy like the egress proxy: records (host, Proxy-Authorization) and allows only ``allowed``."""

    def __init__(self, allowed=()):
        import socket
        import threading

        self.allowed, self.seen = set(allowed), []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(20)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            with connection:
                head = connection.recv(65536).decode(errors="replace").split("\r\n")
                host = head[0].split(" ")[1] if " " in head[0] else ""
                auth = next((line.split(":", 1)[1].strip() for line in head
                             if line.lower().startswith("proxy-authorization:")), "")
                self.seen.append((host, auth))
                allowed = host.rsplit(":", 1)[0] in self.allowed
                connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" if allowed
                                   else b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")

    def url(self, user, password):
        return f"http://{user}:{password}@127.0.0.1:{self.port}"

    def close(self):
        self.server.close()


EGRESS_CHILD = """\
import base64, json, os, socket, sys
from urllib.parse import urlsplit
json.dump(dict(os.environ), open(sys.argv[1], "w"))
proxy = os.environ.get("HTTPS_PROXY")
if not proxy:
    print("connect: no proxy")
else:
    parts = urlsplit(proxy)
    sock = socket.create_connection((parts.hostname, parts.port), timeout=5)
    auth = base64.b64encode(f"{parts.username}:{parts.password}".encode()).decode()
    sock.sendall(("CONNECT storage.googleapis.com:443 HTTP/1.1\\r\\nHost: storage.googleapis.com:443\\r\\n"
                  f"Proxy-Authorization: Basic {auth}\\r\\n\\r\\n").encode())
    print("connect:", sock.recv(200).split(b"\\r\\n")[0].decode())
"""


@pytest.mark.parametrize("mode", ["run", "build"])
def test_the_workflow_gets_only_the_workload_proxy(studio, claude_bin, tmp_path, mode):
    """The runner's own proxy token allows Studio and signed URLs (storage.googleapis.com); the workflow must
    only ever hold start's workload_proxy, limited to its egress hosts."""

    runner_proxy, workload = RecordingProxy(), RecordingProxy(allowed={"api.xero.com"})
    try:
        dump = tmp_path / "child-env.json"
        if mode == "run":
            workdir = project(tmp_path)
            (workdir / "main.py").write_text(EGRESS_CHILD)
            run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py", str(dump)]},
                                           workload_proxy=workload.url("run", "workload-token-xyz")))
        else:  # A build's dependency install: the child is npm.
            workdir = tmp_path / "build"
            source, digest = _blob(studio, "src-egress", {"package-lock.json": b"{}", "main.py": EGRESS_CHILD.encode()})
            npm = claude_bin / "npm"
            npm.write_text(f"#!/bin/sh\nexec {sys.executable} main.py {dump}\n")
            npm.chmod(0o755)
            run, url = studio.add_run({"mode": "build", "attempt": 1, "package_url": source, "package_sha256": digest,
                                       "workload_proxy": workload.url("run", "workload-token-xyz")})
        code, out, err = run_runner(url, run, workdir, claude_bin, tmp_path, extra_env={
            "HTTPS_PROXY": runner_proxy.url("run", "runner-egress-token"),
            "HTTP_PROXY": runner_proxy.url("run", "runner-egress-token"),
            "https_proxy": runner_proxy.url("run", "runner-egress-token")})
        assert code == 0, out + err
        child = json.loads(dump.read_text())
        assert "STUDIO_RUN_TOKEN" not in child and run.token not in json.dumps(child)
        assert "runner-egress-token" not in json.dumps(child)
        for key in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
            assert child[key] == workload.url("run", "workload-token-xyz")
        assert child["NO_PROXY"] == child["no_proxy"] == "127.0.0.1,localhost"
        # The child tried a bucket; the egress proxy saw only the workload token, and refused it.
        assert workload.seen == [("storage.googleapis.com:443",
                                  "Basic " + base64.b64encode(b"run:workload-token-xyz").decode())]
        assert runner_proxy.seen == []
        texts = [event.get("text", "") for event in run.ordered_events()]
        if mode == "run":
            assert "connect: HTTP/1.1 403 Forbidden" in texts
        assert "workload-token-xyz" not in json.dumps(run.ordered_events()) + out
    finally:
        runner_proxy.close()
        workload.close()


def test_without_a_workload_proxy_the_workflow_has_no_egress(studio, claude_bin, tmp_path):
    runner_proxy = RecordingProxy()
    try:
        dump = tmp_path / "child-env.json"
        workdir = project(tmp_path)
        (workdir / "main.py").write_text(EGRESS_CHILD)
        run, url = studio.add_run(spec(entry={"command": [sys.executable, "main.py", str(dump)]}))
        code, out, err = run_runner(url, run, workdir, claude_bin, tmp_path,
                                    extra_env={"HTTPS_PROXY": runner_proxy.url("run", "runner-egress-token"),
                                               "ALL_PROXY": runner_proxy.url("run", "runner-egress-token")})
        assert code == 0, out + err
        child = json.loads(dump.read_text())
        assert not {"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"} & set(child)
        assert child["NO_PROXY"] == "127.0.0.1,localhost" and "runner-egress-token" not in json.dumps(child)
        assert "connect: no proxy" in [event.get("text") for event in run.ordered_events()]
        assert runner_proxy.seen == []
    finally:
        runner_proxy.close()


ISOLATED = pytest.mark.skipif(os.geteuid() != 0, reason="needs root (scripts/test-docker.sh isolation)")


@ISOLATED
def test_isolated_the_workflow_runs_as_its_own_user_and_cant_read_the_runner(studio):
    """As root (the runner image): the runner drops to 10001, Claude Code runs as 10002 and can't read the
    runner's environment, and still reaches the model through the relay."""
    import tempfile

    base = tempfile.mkdtemp(prefix="iso-", dir="/tmp")
    os.chmod(base, 0o777)
    claude = os.path.join(base, "claude")
    with open(claude, "w") as handle:
        handle.write(f"#!/bin/sh\nexec {sys.executable} {FAKE_CLAUDE} \"$@\"\n")
    os.chmod(claude, 0o755)
    bundle, digest = _blob(studio, "iso", {"studio.yaml": b"version: 1\n"})
    run, url = studio.add_run(spec("isolation", package_url=bundle, package_sha256=digest))
    env = {"PATH": f"{base}:{os.environ['PATH']}", "PYTHONPATH": SRC, "STUDIO_RUN_URL": url,
           "STUDIO_RUN_TOKEN": run.token, "STUDIO_WORKDIR": os.path.join(base, "workspace"),
           "STUDIO_RUNNER_INTERVALS": FAST, "HOME": base}
    process = subprocess.run([sys.executable, "-m", "foundry_workflow_runner"], env=env, capture_output=True,
                             text=True, timeout=60)
    assert process.returncode == 0, process.stdout + process.stderr
    summary = run.finished["summary"]
    assert "uid=10002 gid=10002" in summary and "runner_environ=unreadable" in summary
    assert "token_in_env=False" in summary and "llm=200:Hello from the relay." in summary
    assert os.stat(os.path.join(base, "workspace")).st_uid == 10002
    assert run.token not in process.stdout + process.stderr


# ---------------------------------------------------------------------- units


def test_event_batches_stay_under_64_kb_and_resend_with_the_same_seq(studio):
    from foundry_workflow_runner.events import EventSink

    run, url = studio.add_run(spec())
    client = RunClient(url, run.token, transport=Transport(environ={}))
    client.start("1")
    sink = EventSink(client, Redactor(), interval=60, echo=io.StringIO())
    for index in range(40):
        sink.emit("text", text=f"{index} " + "x" * 7000)
    assert sink.close()
    assert sorted(run.events) == list(range(1, 41)) and run.event_posts >= 5
    # A resend of the same batch changes nothing (Studio is idempotent on seq).
    client.events([{"seq": 1, "type": "note", "text": "again"}])
    assert run.events[1]["type"] == "text"


def test_refusals_are_not_retried_and_errors_are_value_free(studio):
    run, url = studio.add_run(spec())
    slept = []
    client = RunClient(url, "wrong-token", transport=Transport(environ={}, sleep=slept.append))
    with pytest.raises(ProtocolError) as caught:
        client.start("1")
    assert caught.value.status == 401 and not slept
    assert "wrong-token" not in str(caught.value) and "127.0.0.1" not in str(caught.value)


def test_transient_failures_are_retried_with_backoff():
    slept = []
    transport = Transport(environ={}, sleep=slept.append, retries=3)
    with pytest.raises(ProtocolError) as caught:
        transport.exchange("GET", "http://127.0.0.1:9/nothing/")
    assert len(slept) == 2 and slept[0] <= slept[1] * 2 and "no connection" in str(caught.value)


def test_run_url_must_be_https_or_loopback():
    with pytest.raises(ProtocolError):
        RunClient("http://studio.example.test/studio/api/workflow-runner/runs/1/", "t")
    RunClient("https://studio.example.test/studio/api/workflow-runner/runs/1/", "t")


def test_proxy_authorization_comes_from_https_proxy():
    transport = Transport(environ={"HTTPS_PROXY": "http://run:tok.en%2Fx@10.0.0.5:3128"})
    assert (transport.proxy.host, transport.proxy.port) == ("10.0.0.5", 3128)
    assert base64.b64decode(transport.proxy.authorization.split()[1]) == b"run:tok.en/x"


@pytest.mark.parametrize("rule, tool, tool_input, expected", [
    ("Bash(git push:*)", "Bash", {"command": "git push origin main"}, True),
    ("Bash(git push:*)", "Bash", {"command": "git status && git push"}, True),
    ("Bash(git push:*)", "Bash", {"command": "git pushx"}, False),
    ("Bash(npm run *)", "Bash", {"command": "npm run build"}, True),
    ("Bash(ls)", "Bash", {"command": "ls"}, True),
    ("Bash", "Bash", {"command": "anything"}, True),
    ("mcp__studio__gmail_send", "mcp__studio__gmail_send", {}, True),
    ("mcp__studio", "mcp__studio__drive_list", {}, True),
    ("mcp__studio__*", "mcp__studio__drive_list", {}, True),
    ("mcp__studio", "mcp__studio_runner__permission", {}, False),
    ("Edit(src/**)", "Write", {"file_path": "/w/src/a/b.py"}, True),
    ("Edit(src/**)", "Write", {"file_path": "/w/docs/a.md"}, False),
    ("Read(*.env)", "Read", {"file_path": "/w/config/.env"}, True),
    ("Read(*.env)", "Read", {"file_path": "/w/config/app.toml"}, False),
    ("Read(*.md)", "Read", {"file_path": "/w/docs/a.md"}, True),
    ("WebFetch(domain:api.xero.com)", "WebFetch", {"url": "https://api.xero.com/x"}, True),
    ("WebFetch(domain:api.xero.com)", "WebFetch", {"url": "https://evil.com/api.xero.com"}, False),
])
def test_permission_rules(rule, tool, tool_input, expected):
    assert rule_matches(rule, tool, tool_input, "/w") is expected


def test_redactor_shapes_and_values():
    redact = Redactor(["supersecretvalue"])
    text = redact("a supersecretvalue b sk-ant-api03-xxxxxxxxxxxx c AKIAABCDEFGHIJKLMNOP password=hunter22! "
                  "https://user:pw@example.com/ eyJabcdefghij.eyJabcdefghij.abcdefghijk")
    for leaked in ("supersecretvalue", "sk-ant-api03", "AKIAABCDEFGHIJKLMNOP", "hunter22!", "user:pw", "eyJabc"):
        assert leaked not in text
    assert "password=[REDACTED]" in text


START = "/opt/workflow-runner/start.py"
CAPABILITIES = pytest.mark.skipif(os.geteuid() != 0 or not os.path.exists(START),
                                  reason="needs root in the isolation test image (scripts/test-docker.sh isolation)")


@CAPABILITIES
def test_through_the_images_start_py_the_workflow_is_the_workload_user(studio):
    """The runner image's way: start.py (root) becomes 10001 with only CAP_SETUID/CAP_SETGID and runs the runner,
    which starts Claude Code as 10002 (group 10010): no run token, no runner proxy, the runner's environment
    unreadable, and the model through the relay."""
    import tempfile

    base = tempfile.mkdtemp(prefix="caps-", dir="/tmp")
    os.chmod(base, 0o755)
    claude = os.path.join(base, "claude")
    with open(claude, "w") as handle:
        handle.write(f"#!/bin/sh\nexec {sys.executable} {FAKE_CLAUDE} \"$@\"\n")
    os.chmod(claude, 0o755)
    runner_proxy, workload = RecordingProxy(), RecordingProxy()
    try:
        bundle, digest = _blob(studio, "caps", {"studio.yaml": b"version: 1\n"})
        run, url = studio.add_run(spec("isolation", package_url=bundle, package_sha256=digest,
                                       workload_proxy=workload.url("run", "workload-token-caps")))
        env = {"PATH": f"{base}:/usr/local/bin:/usr/bin:/bin", "STUDIO_RUN_URL": url, "STUDIO_RUN_TOKEN": run.token,
               "STUDIO_RUNNER_INTERVALS": FAST, "HTTPS_PROXY": runner_proxy.url("run", "runner-egress-token")}
        process = subprocess.run(["/opt/workflow-runner/bin/python", "-I", START], env=env, capture_output=True,
                                 text=True, timeout=60)
        assert process.returncode == 0, process.stdout + process.stderr
        summary = run.finished["summary"]
        assert "uid=10002 gid=10010" in summary and "runner_environ=unreadable" in summary
        assert "token_in_env=False" in summary and "llm=200:Hello from the relay." in summary
        assert os.stat("/workspace/studio.yaml").st_uid == 10002  # Unpacked by the workload, not the runner.
        assert run.token not in process.stdout + process.stderr and runner_proxy.seen == []
    finally:
        runner_proxy.close()
        workload.close()


@CAPABILITIES
def test_the_images_privilege_check_passes():
    process = subprocess.run(["/opt/workflow-runner/bin/python", "-I", "/opt/workflow-runner/privcheck.py"],
                             capture_output=True, text=True, timeout=60)
    assert process.returncode == 0 and "PRIVCHECK PASSED" in process.stdout, process.stdout + process.stderr
