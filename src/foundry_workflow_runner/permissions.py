"""Claude Code permission rules, and the decisions behind the ``studio_runner`` ``permission`` tool.

Claude Code asks the permission tool only about a call its own settings don't already allow or deny. The runner
also hands Claude Code the manifest's ``approvals.ask`` rules as ``permissions.ask`` (``--settings``), and ask
rules win over allow rules, so every call matching one reaches the tool even when the project allows it. Then:

1. a tool of the run's ``studio`` MCP server → allowed: Studio enforces ``approvals.ask`` (and its own rules)
   for those itself, and refuses them at ``approvals/``;
2. matches ``approvals.ask`` → the host's approval (stored as ``runner:<tool>``); allowed once a person approves;
3. allowed by the project's own ``.claude/settings.json`` ``permissions.allow`` → allowed;
4. anything else → denied: "not allowed in cloud runs; add it to permissions.allow or approvals.ask".

Rule syntax (the subset Claude Code documents): ``Tool``, ``mcp__server`` / ``mcp__server__*`` /
``mcp__server__tool``, ``Bash(prefix:*)``, ``Bash(glob with *)``, ``Bash(exact)``, ``Read|Edit|Write(path glob)``
and ``WebFetch(domain:host)``.
"""

import fnmatch
import hashlib
import hmac
import json
import os
import re
import socket
import threading
import time
from urllib.parse import urlsplit

from .protocol import ProtocolError

EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
DENY_SUFFIX = "is not allowed in cloud runs; add it to permissions.allow or approvals.ask."
_RULE = re.compile(r"^([A-Za-z0-9_.*-]+)(?:\((.*)\))?$", re.S)
_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")


def parse_rule(rule):
    match = _RULE.match(rule.strip()) if isinstance(rule, str) else None
    return (match.group(1), match.group(2)) if match else (None, None)


def _name_matches(rule_name, tool_name):
    if rule_name == tool_name:
        return True
    if rule_name.startswith("mcp__"):
        server = rule_name[:-3] if rule_name.endswith("__*") else rule_name
        return "__" not in server[5:] and tool_name.startswith(server + "__")
    if rule_name == "Edit":
        return tool_name in EDIT_TOOLS
    return False


def _glob(pattern, text):
    regex = "".join(".*" if part == "*" else re.escape(part) for part in re.split(r"(\*)", pattern))
    return re.fullmatch(regex, text, re.S) is not None


def _bash_matches(spec, command):
    parts = [part for part in _SPLIT.split(command.strip()) if part]
    for part in parts or [command.strip()]:
        if spec.endswith(":*"):
            prefix = spec[:-2]
            if part == prefix or part.startswith(prefix + " ") or (prefix.endswith(" ") and part.startswith(prefix)):
                return True
        elif "*" in spec:
            if _glob(spec, part):
                return True
        elif part == spec:
            return True
    return False


def _path_matches(spec, path, workdir):
    if not isinstance(path, str) or not path:
        return False
    if spec.startswith("//"):
        pattern = spec[1:]
    elif spec.startswith("~/"):
        pattern = os.path.expanduser(spec)
    elif spec.startswith("/"):
        pattern = os.path.join(workdir, spec[1:])
    else:
        pattern = os.path.join(workdir, spec[2:] if spec.startswith("./") else spec)
        if "/" not in spec.rstrip("/"):
            pattern = os.path.join(workdir, "**", spec)
    absolute = os.path.normpath(os.path.join(workdir, path))
    regex = ""
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index):
            regex += "(?:.*/)?"
            index += 3
        elif pattern.startswith("**", index):
            regex += ".*"
            index += 2
        elif pattern[index] == "*":
            regex += "[^/]*"
            index += 1
        elif pattern[index] == "?":
            regex += "[^/]"
            index += 1
        else:
            regex += re.escape(pattern[index])
            index += 1
    return re.fullmatch(regex, absolute) is not None or fnmatch.fnmatchcase(absolute, pattern)


def rule_matches(rule, tool_name, tool_input, workdir="."):
    name, spec = parse_rule(rule)
    if name is None or not _name_matches(name, tool_name):
        return False
    if spec is None or spec in ("", "*"):
        return True
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash":
        command = tool_input.get("command")
        return isinstance(command, str) and _bash_matches(spec, command)
    if tool_name in ("Read",) + EDIT_TOOLS:
        return _path_matches(spec, tool_input.get("file_path") or tool_input.get("notebook_path"), workdir)
    if tool_name == "WebFetch" and spec.startswith("domain:"):
        host = (urlsplit(str(tool_input.get("url") or "")).hostname or "").lower()
        wanted = spec[len("domain:"):].lower()
        return host == wanted or (wanted.startswith("*.") and host.endswith(wanted[1:]))
    return False


def input_sha256(tool_input):
    canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def input_summary(tool_name, tool_input, redact, workdir="."):
    """What the approver needs to decide, redacted and short: a command, a file, a host, or argument names with
    short values."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    if tool_name == "Bash" and isinstance(tool_input.get("command"), str):
        text = "command: " + tool_input["command"]
    elif tool_name in ("Read",) + EDIT_TOOLS:
        path = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        try:
            path = os.path.relpath(path, workdir) if os.path.isabs(path) else path
        except ValueError:
            pass
        text = "file: " + path
    elif tool_name == "WebFetch":
        text = "url host: " + (urlsplit(str(tool_input.get("url") or "")).hostname or "")
    else:
        pairs = []
        for key, value in list(tool_input.items())[:12]:
            shown = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            pairs.append(f"{key}: {shown[:160]}")
        text = "\n".join(pairs) or "(no arguments)"
    text = redact(text)
    return text if len(text) <= 1000 else text[:999] + "…"


def project_allow_rules(workdir, read_project=None):
    """``permissions.allow`` from the project's own ``.claude/settings.json`` (not settings.local.json).
    ``read_project(*parts)``: the runner's link-safe reader of project files."""
    try:
        if read_project is not None:
            settings = json.loads(read_project(".claude", "settings.json") or "{}")
        else:
            with open(os.path.join(workdir, ".claude", "settings.json"), encoding="utf-8") as handle:
                settings = json.load(handle)
    except (OSError, ValueError):
        return []
    allow = (settings.get("permissions") or {}).get("allow") if isinstance(settings, dict) else None
    return [rule for rule in allow if isinstance(rule, str)] if isinstance(allow, list) else []


class Broker:
    """Decides each permission request (see the module docstring)."""

    def __init__(self, client, sink, redact, *, ask_rules, workdir, cancelled, deadline, poll=3.0,
                 read_project=None):
        self.client, self.sink, self.redact = client, sink, redact
        self.ask_rules, self.workdir = list(ask_rules or []), workdir
        self.allow_rules = project_allow_rules(workdir, read_project)
        self.cancelled, self.deadline, self.poll = cancelled, deadline, poll

    def decide(self, tool_name, tool_input):
        if not isinstance(tool_name, str) or not tool_name:
            return {"behavior": "deny", "message": "The permission request named no tool."}
        if tool_name == "mcp__studio" or tool_name.startswith("mcp__studio__"):
            # Studio's own tools: Studio applies approvals.ask (and its own rules) when they're called, and
            # refuses them at approvals/. Asking here too would ask twice.
            return {"behavior": "allow", "updatedInput": tool_input}
        if any(rule_matches(rule, tool_name, tool_input, self.workdir) for rule in self.ask_rules):
            return self._approval(tool_name, tool_input)
        if any(rule_matches(rule, tool_name, tool_input, self.workdir) for rule in self.allow_rules):
            return {"behavior": "allow", "updatedInput": tool_input}
        self.sink.emit("note", text=f"Denied {tool_name}: not allowed in cloud runs.")
        return {"behavior": "deny", "message": f"{tool_name} {DENY_SUFFIX}"}

    def _approval(self, tool_name, tool_input):
        try:
            approval = self.client.request_approval(tool_name, input_summary(tool_name, tool_input, self.redact,
                                                                              self.workdir),
                                                    input_sha256(tool_input))
        except ProtocolError:
            self.sink.emit("note", text=f"Couldn't ask for approval of {tool_name}; denied it.")
            return {"behavior": "deny", "message": f"The host couldn't ask a person to approve {tool_name}, so it "
                                                   "was not run."}
        self.sink.emit("note", text=f"Waiting for a person to approve {tool_name}.")
        while True:
            if self.cancelled.is_set():
                return {"behavior": "deny", "message": "The run was cancelled."}
            if time.monotonic() >= self.deadline:
                return {"behavior": "deny", "message": "The run reached its time limit while waiting for approval."}
            try:
                state = self.client.approval_state(approval)
            except ProtocolError:
                state = "pending"
            if state == "approved":
                self.sink.emit("note", text=f"Approved: {tool_name}.")
                return {"behavior": "allow", "updatedInput": tool_input}
            if state in ("denied", "expired"):
                self.sink.emit("note", text=f"{'Denied' if state == 'denied' else 'Expired'}: {tool_name}.")
                return {"behavior": "deny", "message": (f"A person denied {tool_name}." if state == "denied"
                                                        else f"Nobody approved {tool_name} in time; it expired.")}
            self.cancelled.wait(min(self.poll, max(0.0, self.deadline - time.monotonic())))


class LocalBridge:
    """A loopback socket the stdio ``studio_runner`` MCP server forwards permission requests to, so the run's
    run token never leaves the runner process. One JSON line in, one out; a per-run key guards it."""

    def __init__(self, broker):
        self.broker = broker
        self.key = os.urandom(24).hex()
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(16)
        self.port = self.server.getsockname()[1]
        self.closed = False
        threading.Thread(target=self._accept, name="studio-permission", daemon=True).start()

    def _accept(self):
        while not self.closed:
            try:
                connection, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(connection,), daemon=True).start()

    def _serve(self, connection):
        with connection:
            try:
                reader = connection.makefile("rb")
                request = json.loads(reader.readline(4 * 1024 * 1024).decode("utf-8"))
                if not isinstance(request, dict) or not hmac.compare_digest(str(request.get("key", "")), self.key):
                    answer = {"behavior": "deny", "message": "Unauthorised permission request."}
                else:
                    answer = self.broker.decide(request.get("tool_name"), request.get("input"))
            except (OSError, ValueError, UnicodeError):
                answer = {"behavior": "deny", "message": "The permission request was malformed."}
            except Exception:  # noqa: BLE001 - a broken decision denies, never allows.
                answer = {"behavior": "deny", "message": "The runner couldn't decide this permission request."}
            try:
                connection.sendall(json.dumps(answer).encode() + b"\n")
            except OSError:
                pass

    def close(self):
        self.closed = True
        try:
            self.server.close()
        except OSError:
            pass
