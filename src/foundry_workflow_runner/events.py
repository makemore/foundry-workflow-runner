"""Batched, sequenced run events, and Claude Code's stream-json turned into sanitised events.

Events are numbered from 1 and sent in batches of at most 60 KB (hosts take 64 KB); a batch that fails is
resent with the same numbers, so the host drops what it already has. Every string is redacted and cut short
before it is queued. Only these fields ever leave the runner:

- ``text``: ``{seq, type, text}`` (agent text)
- ``tool``: ``{seq, type, id, name, title, status}`` (status started | ok | error)
- ``note``: ``{seq, type, text}`` (the runner's own notes)
- ``log``: ``{seq, type, text}`` (one stderr line from the tail, redacted)
"""

import json
import os
import sys
import threading
from urllib.parse import urlsplit

from .protocol import ProtocolError

BATCH_BYTES = 60 * 1024
LIMITS = {"text": 8000, "title": 300, "name": 200, "id": 100}
BATCH_EVENTS = 500
MAX_QUEUED = 5000


def _cut(text, limit):
    text = "".join(ch if ch.isprintable() or ch in "\n\t" else " " for ch in text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


class EventSink:
    def __init__(self, client, redactor, *, interval=1.0, echo=None):
        self.client, self.redact, self.interval = client, redactor, interval
        self.echo = sys.stdout if echo is None else echo
        self.seq, self.queue, self.lock = 0, [], threading.Lock()
        self.wake, self.stopped = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self._loop, name="studio-events", daemon=True)
        self.thread.start()

    def emit(self, kind, **fields):
        event = {"type": kind}
        for key, value in fields.items():
            if isinstance(value, str):
                value = _cut(self.redact(value), LIMITS.get(key, 2000))
            event[key] = value
        with self.lock:
            self.seq += 1
            event = {"seq": self.seq, **event}
            self.queue.append(event)
            if len(self.queue) > MAX_QUEUED:  # The host unreachable for a long time: keep the newest.
                del self.queue[0]
        self._print(event)
        if sum(len(json.dumps(item)) for item in self.queue[-50:]) > BATCH_BYTES:
            self.wake.set()
        return event

    def _print(self, event):
        try:
            kind = event["type"]
            if kind == "text":
                line = event["text"]
            elif kind == "tool":
                mark = {"started": ">", "ok": "ok", "error": "x"}.get(event.get("status"), "-")
                line = f"  [{mark}] {event.get('title') or event.get('name')}"
            else:
                line = f"[{kind}] {event.get('text', '')}"
            print(line, file=self.echo, flush=True)
        except (OSError, ValueError):
            pass

    def _batches(self, events):
        batch, size = [], 20
        for event in events:
            length = len(json.dumps(event, ensure_ascii=True)) + 1
            if batch and (size + length > BATCH_BYTES or len(batch) >= BATCH_EVENTS):
                yield batch
                batch, size = [], 20
            batch.append(event)
            size += length
        if batch:
            yield batch

    def flush(self, *, retries=None):
        """Send everything queued; returns False when the host couldn't be reached (the events stay queued)."""
        with self.lock:
            pending = list(self.queue)
        for batch in self._batches(pending):
            try:
                self.client.events(batch, retries=retries)
            except ProtocolError:
                return False
            with self.lock:
                sent = {event["seq"] for event in batch}
                self.queue = [event for event in self.queue if event["seq"] not in sent]
        return True

    def _loop(self):
        while not self.stopped.is_set():
            self.wake.wait(self.interval)
            self.wake.clear()
            if self.queue:
                self.flush(retries=3)

    def close(self):
        self.stopped.set()
        self.wake.set()
        self.thread.join(timeout=10)
        return self.flush(retries=8)


def tool_title(name, tool_input, workdir=""):
    """A short, human title for a tool call, without its raw input: the model's own description of a command,
    a file's name, a web host. Redacted by the sink like every other string."""
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    description = tool_input.get("description")
    if name == "Bash":
        return f"Bash: {description}" if isinstance(description, str) and description.strip() else "Run a command"
    if name in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        return f"{name} {os.path.basename(path)}" if isinstance(path, str) and path else name
    if name in ("Glob", "Grep"):
        return "Search files"
    if name == "WebFetch":
        host = urlsplit(str(tool_input.get("url") or "")).hostname
        return f"Fetch {host}" if host else "Fetch a page"
    if name == "WebSearch":
        return "Search the web"
    if name in ("Task", "Agent"):
        return f"Agent: {description}" if isinstance(description, str) and description.strip() else "Run an agent"
    if name == "TodoWrite":
        return "Update the to-do list"
    if name.startswith("mcp__"):
        server, _, tool = name[5:].partition("__")
        return f"{server}: {tool.replace('_', ' ')}" if tool else server
    return name


class StreamJson:
    """Feeds Claude Code ``--output-format stream-json`` lines to an EventSink; remembers the result."""

    def __init__(self, sink):
        self.sink, self.names, self.titles = sink, {}, {}
        self.result = None
        self.version = None

    def line(self, raw):
        try:
            message = json.loads(raw)
        except ValueError:
            return
        if not isinstance(message, dict):
            return
        kind = message.get("type")
        if kind == "system" and message.get("subtype") == "init":
            self.version = message.get("claude_code_version")
            model = message.get("model")
            self.sink.emit("note", text="Claude Code" + (f" {self.version}" if isinstance(self.version, str) else "")
                           + (f" started with {model}." if isinstance(model, str) else " started."))
        elif kind == "assistant":
            for block in _blocks(message):
                if block.get("type") == "text" and isinstance(block.get("text"), str) and block["text"].strip():
                    self.sink.emit("text", text=block["text"])
                elif block.get("type") == "tool_use":
                    tool_id, name = str(block.get("id") or ""), str(block.get("name") or "tool")
                    title = tool_title(name, block.get("input"))
                    self.names[tool_id], self.titles[tool_id] = name, title
                    self.sink.emit("tool", id=tool_id, name=name, title=title, status="started")
        elif kind == "user":
            for block in _blocks(message):
                if block.get("type") == "tool_result":
                    tool_id = str(block.get("tool_use_id") or "")
                    name = self.names.get(tool_id, "tool")
                    self.sink.emit("tool", id=tool_id, name=name, title=self.titles.get(tool_id, name),
                                   status="error" if block.get("is_error") else "ok")
        elif kind == "result":
            self.result = {"subtype": message.get("subtype"), "is_error": bool(message.get("is_error")),
                           "num_turns": message.get("num_turns"),
                           "text": message.get("result") if isinstance(message.get("result"), str) else ""}


def _blocks(message):
    content = (message.get("message") or {}).get("content") if isinstance(message.get("message"), dict) else None
    return [block for block in content if isinstance(block, dict)] if isinstance(content, list) else []


class Heartbeat:
    """Posts heartbeat/ every ``interval`` seconds; sets ``cancel`` when the host says so, or when it no longer
    accepts the run's token (finished, cancelled or expired elsewhere)."""

    def __init__(self, client, interval=30.0, on_cancel=None):
        self.client, self.interval, self.on_cancel = client, interval, on_cancel
        self.cancel, self.stopped = threading.Event(), threading.Event()
        self.thread = threading.Thread(target=self._loop, name="studio-heartbeat", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def beat(self):
        try:
            if self.client.heartbeat():
                self._cancelled()
        except ProtocolError as error:
            if error.status in (401, 403, 404, 410):
                self._cancelled()

    def _cancelled(self):
        if not self.cancel.is_set():
            self.cancel.set()
            if self.on_cancel:
                self.on_cancel()

    def _loop(self):
        while True:  # The first beat goes straight after start.
            self.beat()
            if self.cancel.is_set() or self.stopped.wait(self.interval):
                return

    def stop(self):
        self.stopped.set()
