#!/usr/bin/env python3
"""A fake ``claude`` for the runner tests: refuses flags the real Claude Code doesn't take, writes its argv to
``$FAKE_CLAUDE_LOG``, emits stream-json like ``claude -p --output-format stream-json --verbose`` and asks the
real ``studio_runner`` MCP server (from ``--mcp-config``) for permission over stdio, as Claude Code does.

The prompt picks the scenario: ``basic``, ``approval``, ``deny``, ``secrets``, ``sleep``, ``max_turns``.
"""

import json
import os
import subprocess
import sys
import time

# Flags the runner may pass, as listed by `claude --help` (2.1.310) plus the documented hidden ones
# (--max-turns, --permission-prompt-tool). Any other flag fails like an unknown option.
VALUE_FLAGS = {"--output-format", "--max-turns", "--mcp-config", "--permission-prompt-tool", "--settings",
               "--setting-sources", "--model", "--append-system-prompt"}
BARE_FLAGS = {"-p", "--print", "--verbose", "--strict-mcp-config", "--no-session-persistence"}


def emit(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def parse(argv):
    options, prompt, index = {}, None, 0
    while index < len(argv):
        arg = argv[index]
        if arg in BARE_FLAGS:
            options[arg] = True
            if arg in ("-p", "--print") and index + 1 < len(argv) and not argv[index + 1].startswith("--"):
                prompt = argv[index + 1]
                index += 1
        elif arg in VALUE_FLAGS:
            options[arg] = argv[index + 1]
            index += 1
        else:
            sys.stderr.write(f"error: unknown option '{arg}'\n")
            sys.exit(2)
        index += 1
    return options, prompt


class Permission:
    def __init__(self, config_path):
        with open(config_path) as handle:
            server = json.load(handle)["mcpServers"]["studio_runner"]
        env = {**os.environ, **server.get("env", {})}
        self.process = subprocess.Popen([server["command"], *server["args"]], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, env=env, text=True)
        self.next_id = 0
        # Claude Code 2.1.310 probes with server/discover first, then initializes.
        probe = self.rpc("server/discover", {})
        assert "error" in probe, probe
        init = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                       "clientInfo": {"name": "fake-claude", "version": "0"}})
        assert init["result"]["capabilities"]["tools"] == {}, init
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.process.stdin.flush()
        tools = self.rpc("tools/list", {})["result"]["tools"]
        assert [tool["name"] for tool in tools] == ["permission"], tools

    def rpc(self, method, params):
        self.next_id += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.next_id, "method": method,
                                             "params": params}) + "\n")
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def ask(self, tool_name, tool_input, tool_use_id):
        answer = self.rpc("tools/call", {"name": "permission", "arguments": {
            "tool_name": tool_name, "input": tool_input, "tool_use_id": tool_use_id}})
        return json.loads(answer["result"]["content"][0]["text"])


def http(url, body, headers):
    """One request the way Claude Code makes it: no proxy for loopback, our own (dummy) credentials."""
    import http.client
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    connection.request("POST", parts.path + ("?" + parts.query if parts.query else ""),
                       body=json.dumps(body).encode(), headers={"Content-Type": "application/json", **headers})
    response = connection.getresponse()
    chunks = []
    while True:
        chunk = response.read1(65536)
        if not chunk:
            break
        chunks.append(chunk)
    return response.status, chunks


def model_call():
    """A streamed Messages call to ANTHROPIC_BASE_URL with ANTHROPIC_AUTH_TOKEN; the text it streamed back."""
    base, token = os.environ["ANTHROPIC_BASE_URL"], os.environ["ANTHROPIC_AUTH_TOKEN"]
    status, chunks = http(base + "/v1/messages?beta=true", {"model": os.environ.get("ANTHROPIC_MODEL", "x"),
                                                             "max_tokens": 10, "stream": True,
                                                             "messages": [{"role": "user", "content": "hi"}]},
                          {"Authorization": f"Bearer {token}", "x-api-key": token, "anthropic-version": "2023-06-01",
                           "Accept": "text/event-stream"})
    text = ""
    for line in b"".join(chunks).decode().splitlines():
        if line.startswith("data: "):
            data = json.loads(line[6:])
            if data.get("type") == "content_block_delta":
                text += data["delta"]["text"]
    return status, len(chunks), text


def mcp_call(config_path):
    with open(config_path) as handle:
        server = json.load(handle)["mcpServers"]["studio"]
    assert server["type"] == "http" and "headers" not in server, server
    status, chunks = http(server["url"], {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                          {"Accept": "application/json, text/event-stream"})
    body = b"".join(chunks).decode()
    return status, json.loads(body.split("data: ", 1)[1]) if "data: " in body else json.loads(body)


def tool_call(permission, tool_id, name, tool_input, output):
    emit({"type": "assistant", "message": {"content": [{"type": "tool_use", "id": tool_id, "name": name,
                                                        "input": tool_input}]}})
    decision = permission.ask(name, tool_input, tool_id)
    allowed = decision["behavior"] == "allow"
    if allowed:
        assert decision["updatedInput"] == tool_input
    emit({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": tool_id,
                                                   "content": output if allowed else decision["message"],
                                                   "is_error": not allowed}]},
          "tool_use_result": {"stdout": output}})
    return decision


def main():
    options, prompt = parse(sys.argv[1:])
    log = os.environ.get("FAKE_CLAUDE_LOG")
    if log:
        with open(log, "a") as handle:
            handle.write(json.dumps({"argv": sys.argv[1:], "env": sorted(os.environ),
                                     "relay": {key: os.environ.get(key) for key in (
                                         "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "NO_PROXY",
                                         "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "XERO_TOKEN")},
                                     "trigger_file": os.environ.get("STUDIO_TRIGGER_FILE"),
                                     "settings": json.load(open(options["--settings"]))}) + "\n")
    if options.get("--output-format") != "stream-json" or "--verbose" not in options or prompt is None:
        sys.stderr.write("Error: stream-json output needs --verbose and a prompt\n")
        return 1
    emit({"type": "system", "subtype": "init", "claude_code_version": "2.1.310-fake",
          "model": options.get("--model", "claude-opus-5-5"), "permissionMode": "default"})
    permission = Permission(options["--mcp-config"])
    scenario = prompt.split()[0].lstrip("/")
    result, subtype, code = "Done.", "success", 0
    if scenario == "basic":
        emit({"type": "assistant", "message": {"content": [{"type": "thinking", "thinking": "private"},
                                                           {"type": "text", "text": "Filing 3 receipts."}]}})
        decision = tool_call(permission, "toolu_1", "Bash", {"command": "ls receipts", "description": "List receipts"},
                             "a.pdf\nb.pdf")
        result = f"Filed 3 receipts ({decision['behavior']})."
        if os.environ.get("ANTHROPIC_BASE_URL"):
            status, chunks, text = model_call()
            result += f" llm={status}:{text}:{'streamed' if chunks > 1 else 'whole'}"
            with open(options["--mcp-config"]) as handle:
                has_studio = "studio" in json.load(handle)["mcpServers"]
            if has_studio:
                mcp_status, answer = mcp_call(options["--mcp-config"])
                result += f" mcp={mcp_status}:{answer['result']['echo']}"
    elif scenario == "approval":
        decision = tool_call(permission, "toolu_2", "Bash",
                             {"command": "git push origin main", "description": "Push the changes"}, "pushed")
        result = f"push: {decision['behavior']}: {decision.get('message', '')}"
    elif scenario == "deny":
        decision = tool_call(permission, "toolu_3", "Write", {"file_path": "/etc/hosts", "content": "x"}, "")
        result = f"write: {decision['behavior']}: {decision.get('message', '')}"
    elif scenario == "secrets":
        secret = os.environ.get("XERO_TOKEN", "")
        emit({"type": "assistant", "message": {"content": [
            {"type": "text", "text": f"The token is {secret} and the key is sk-ant-api03-abcdefghijklmnopqrstuv"}]}})
        tool_call(permission, "toolu_4", "Bash", {"command": f"curl -H 'Authorization: Bearer {secret}' x",
                                                  "description": f"Call Xero with {secret}"}, secret)
        sys.stderr.write(f"debug: XERO_TOKEN={secret}\n")
        sys.stderr.write("debug: header ghp_abcdefghijklmnopqrstuvwx\n")
        result, subtype, code = f"Leaked {secret}?", "error_during_execution", 1
    elif scenario == "sleep":
        emit({"type": "assistant", "message": {"content": [{"type": "text", "text": "Working slowly."}]}})
        time.sleep(120)
    elif scenario == "max_turns":
        result, subtype, code = "", "error_max_turns", 1
    elif scenario == "isolation":
        try:
            with open(f"/proc/{os.getppid()}/environ", "rb") as handle:
                runner_env = "readable" if handle.read() else "empty"
        except OSError:
            runner_env = "unreadable"
        token_here = any(key == "STUDIO_RUN_TOKEN" for key in os.environ)
        status, _, text = model_call()
        # Claude Code's workspace trust for this directory, from its global config in this user's home.
        trust = "none"
        try:
            config = os.path.join(os.environ["HOME"], ".claude.json")
            info = os.lstat(config)
            with open(config) as handle:
                entry = json.load(handle)["projects"][os.getcwd()]
            trust = f"{entry['hasTrustDialogAccepted']}:{info.st_uid}:{info.st_mode & 0o777:o}"
        except (OSError, KeyError, ValueError, TypeError):
            pass
        result = f"uid={os.getuid()} gid={os.getgid()} runner_environ={runner_env} token_in_env={token_here} " \
                 f"llm={status}:{text} trust={trust}"
    elif scenario == "denied_by_person":
        decision = tool_call(permission, "toolu_5", "mcp__studio__gmail_send", {"to": "a@example.com"}, "sent")
        result = f"send: {decision['behavior']}"
    emit({"type": "result", "subtype": subtype, "is_error": subtype != "success", "num_turns": 2, "result": result})
    permission.process.stdin.close()
    permission.process.wait(timeout=5)
    return code


if __name__ == "__main__":
    sys.exit(main())
