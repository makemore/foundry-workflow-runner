"""The ``studio_runner`` stdio MCP server: one tool, ``permission``, for ``--permission-prompt-tool``.

Claude Code calls it with ``{"tool_name", "input", "tool_use_id"}`` and expects one text content block holding
``{"behavior": "allow", "updatedInput": {...}}`` or ``{"behavior": "deny", "message": "..."}`` (checked against
Claude Code 2.1.310). Each request is forwarded to the runner's loopback bridge (``STUDIO_RUNNER_BRIDGE`` =
port, ``STUDIO_RUNNER_KEY``), which decides; any failure here denies.

Self-contained on purpose: it's started as ``python -I <this file>`` from the workflow's directory, so nothing in
that directory can shadow an import.
"""

import json
import os
import socket
import sys
import threading

PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
TOOL = {
    "name": "permission",
    "description": "Decides whether a tool call may run in this workflow run.",
    "inputSchema": {
        "type": "object",
        "properties": {"tool_name": {"type": "string"}, "input": {"type": "object"},
                       "tool_use_id": {"type": "string"}},
        "required": ["tool_name", "input"],
    },
}
_write = threading.Lock()


def send(message):
    with _write:
        sys.stdout.write(json.dumps(message, ensure_ascii=True) + "\n")
        sys.stdout.flush()


def decide(arguments):
    try:
        port = int(os.environ.get("STUDIO_RUNNER_BRIDGE", ""))
        request = {"key": os.environ.get("STUDIO_RUNNER_KEY", ""), "tool_name": arguments.get("tool_name"),
                   "input": arguments.get("input") if isinstance(arguments.get("input"), dict) else {}}
        with socket.create_connection(("127.0.0.1", port)) as connection:
            connection.sendall(json.dumps(request).encode() + b"\n")
            answer = json.loads(connection.makefile("rb").readline(4 * 1024 * 1024).decode("utf-8"))
        if isinstance(answer, dict) and answer.get("behavior") == "allow":
            return {"behavior": "allow", "updatedInput": answer.get("updatedInput", request["input"])}
        if isinstance(answer, dict) and answer.get("behavior") == "deny":
            return {"behavior": "deny", "message": str(answer.get("message") or "Denied.")}
    except (OSError, ValueError, UnicodeError, TypeError):
        pass
    return {"behavior": "deny", "message": "The workflow runner couldn't be asked, so this was not run."}


def call(message_id, params):
    if params.get("name") != "permission":
        send({"jsonrpc": "2.0", "id": message_id, "error": {"code": -32602, "message": "Unknown tool."}})
        return
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    result = decide(arguments)
    send({"jsonrpc": "2.0", "id": message_id,
          "result": {"content": [{"type": "text", "text": json.dumps(result)}], "isError": False}})


def handle(message):
    if not isinstance(message, dict):
        return
    method, message_id = message.get("method"), message.get("id")
    params = message.get("params") if isinstance(message.get("params"), dict) else {}
    if message_id is None:
        return  # Notifications (initialized, cancelled) need no answer.
    if method == "initialize":
        asked = params.get("protocolVersion")
        send({"jsonrpc": "2.0", "id": message_id, "result": {
            "protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
            "capabilities": {"tools": {}}, "serverInfo": {"name": "studio_runner", "version": "1"}}})
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": message_id, "result": {"tools": [TOOL]}})
    elif method == "tools/call":
        threading.Thread(target=call, args=(message_id, params), daemon=True).start()
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": message_id, "result": {}})
    else:
        send({"jsonrpc": "2.0", "id": message_id, "error": {"code": -32601, "message": "Method not found."}})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            handle(json.loads(line))
        except ValueError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error."}})


if __name__ == "__main__":
    main()
