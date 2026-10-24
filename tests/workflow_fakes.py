"""A fake host for the runner tests: the runner protocol (docs/PROTOCOL.md), the MCP and model relay endpoints
and a signed-URL blob store, on one loopback HTTP server.

It is strict on purpose (a lenient fake once hid a broken CLI command): wrong auth, unknown fields, unknown
event types, oversized batches, a second ``start``, query strings on API paths and the wrong content type are
all refused the way a strict host refuses them.
"""

import base64
import hashlib
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

EVENT_FIELDS = {"text": {"seq", "type", "text"}, "note": {"seq", "type", "text"}, "log": {"seq", "type", "text"},
                "tool": {"seq", "type", "id", "name", "title", "status"}}
FINISH_FIELDS = {"status", "summary", "error_code", "exit_code", "bundle_sha256", "bundle_size", "build_log_tail"}


class Refused(Exception):
    def __init__(self, status, message="refused"):
        super().__init__(message)
        self.status, self.message = status, message


class Run:
    def __init__(self, run_id, token, spec):
        self.id, self.token, self.spec = run_id, token, spec
        self.started = False
        self.finished = None
        self.events = {}
        self.event_posts = 0
        self.heartbeats = 0
        self.cancel = False
        self.approval_requests = []
        self.approval_polls = {}
        # tool name -> list of states returned on successive polls (the last one repeats).
        self.approval_script = {}
        self.dev = False
        self.trigger = {"kind": "manual", "payload": None}
        self.upload_requests = []
        self.uploaded_blob = None
        self.relayed = []  # (path, headers as the relay sent them) for mcp/ and llm/ calls.

    def ordered_events(self):
        return [self.events[seq] for seq in sorted(self.events)]


class FakeHost:
    def __init__(self, *, build_polls=2, build_result="ready"):
        self.runs, self.workflows, self.blobs, self.signed = {}, {}, {}, {}
        self.lock = threading.Lock()
        self.requests = []
        self.build_polls, self.build_result = build_polls, build_result
        studio = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _go(self, method):
                try:
                    status, body, kind = studio.handle(self, method)
                except Refused as refusal:
                    status, body, kind = refusal.status, json.dumps({"error": {"message": refusal.message}}).encode(), \
                        "application/json"
                self.send_response(status)
                self.send_header("Content-Type", kind)
                if isinstance(body, list):  # Streamed (SSE): chunked, a pause between chunks.
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    for chunk in body:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        self.wfile.flush()
                        time.sleep(0.02)
                    self.wfile.write(b"0\r\n\r\n")
                    return
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

            def do_PUT(self):
                self._go("PUT")

            def do_DELETE(self):
                self._go("DELETE")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    # ------------------------------------------------------------------ setup helpers

    def blob_url(self, name):
        return f"{self.origin}/blob/{name}?X-Goog-Signature=sig-{name}"

    def signed_put(self, name, size, md5):
        """A create-only PUT bound to size and MD5 (Studio's storage.upload_instructions)."""
        headers = {"Content-Type": "application/gzip", "x-goog-if-generation-match": "0",
                   "x-goog-content-length-range": f"{size},{size}", "Content-MD5": md5}
        self.signed[name] = headers
        return {"url": self.blob_url(name), "method": "PUT", "headers": headers, "expires_in": 900}

    def add_run(self, spec, *, run_id=None, token=None):
        run_id = run_id or uuid.uuid4().hex
        token = token or "run-token-" + uuid.uuid4().hex
        run = Run(run_id, token, spec)
        self.runs[run_id] = run
        return run, f"{self.origin}/studio/api/workflow-runner/runs/{run_id}/"

    # ------------------------------------------------------------------ dispatch

    def handle(self, request, method):
        parts = urlsplit(request.path)
        length = int(request.headers.get("Content-Length") or 0)
        body = request.rfile.read(length) if length else b""
        self.requests.append((method, parts.path, parts.query))
        if parts.path.startswith("/blob/"):
            return self.blob(request, method, parts, body)
        match = re.fullmatch(r"/studio/api/workflow-runner/runs/([0-9a-f]+)/(.*)", parts.path)
        if parts.query and not (match and match.group(2).startswith("llm/")):
            raise Refused(400, "Query strings aren't accepted here.")
        if match:
            return self.runner(request, method, match.group(1), match.group(2), body)
        raise Refused(404, "Not found.")

    def _json(self, value, status=200):
        return status, json.dumps(value).encode(), "application/json"

    def _body(self, request, body, limit=4 * 1024 * 1024):
        if len(body) > limit:
            raise Refused(413, "Too large.")
        if (request.headers.get("Content-Type") or "").split(";")[0] != "application/json":
            raise Refused(415, "JSON only.")
        try:
            value = json.loads(body.decode())
        except ValueError:
            raise Refused(400, "Malformed JSON.") from None
        if not isinstance(value, dict):
            raise Refused(400, "Expected an object.")
        return value

    # ------------------------------------------------------------------ signed URLs

    def blob(self, request, method, parts, body):
        name = parts.path[len("/blob/"):]
        if parse_qs(parts.query).get("X-Goog-Signature") != [f"sig-{name}"]:
            raise Refused(403, "Bad signature.")
        if request.headers.get("Authorization"):
            raise Refused(400, "Signed URLs take no Authorization header.")
        if method == "PUT":
            if request.headers.get("Content-Type") != "application/gzip":
                raise Refused(400, "Wrong content type.")
            required = self.signed.get(name, {})
            for header, value in required.items():
                if request.headers.get(header) != value:
                    raise Refused(403, "A signed header is missing or different.")
            if any(key.lower().startswith("x-goog-") and key.lower() not in {h.lower() for h in required}
                   for key in request.headers):
                raise Refused(403, "An unsigned x-goog header.")
            if required.get("x-goog-if-generation-match") == "0" and name in self.blobs:
                raise Refused(412, "Create-only: it exists.")
            if "Content-MD5" in required and \
                    base64.b64encode(hashlib.md5(body).digest()).decode() != required["Content-MD5"]:
                raise Refused(400, "BadDigest: the body doesn't match its Content-MD5.")
            low, _, high = required.get("x-goog-content-length-range", ",").partition(",")
            if low and not int(low) <= len(body) <= int(high):
                raise Refused(400, "EntityTooLarge or too small.")
            self.blobs[name] = body
            return 200, b"", "text/plain"
        if method == "GET":
            if name not in self.blobs:
                return 404, b"", "text/plain"
            return 200, self.blobs[name], "application/gzip"
        raise Refused(405, "Method not allowed.")

    # ------------------------------------------------------------------ runner protocol

    def runner(self, request, method, run_id, name, body):
        run = self.runs.get(run_id)
        if run is None:
            raise Refused(404, "No such run.")
        if request.headers.get("Authorization") != f"Bearer {run.token}" or run.finished is not None:
            raise Refused(401, "Bad token.")
        if name == "mcp/" or name.startswith("llm/"):
            run.relayed.append((name, {key.lower(): value for key, value in request.headers.items()}))
            return self.relay_endpoint(request, method, run, name, body)
        if name == "start/" and method == "POST":
            value = self._body(request, body)
            if set(value) != {"runner_version"}:
                raise Refused(400, "Unknown fields.")
            if run.started:
                raise Refused(409, "Already started.")
            run.started = True
            return self._json(run.spec)
        if not run.started:
            raise Refused(409, "Not started.")
        if name == "events/" and method == "POST":
            value = self._body(request, body, limit=64 * 1024)
            events = value.get("events")
            if set(value) != {"events"} or not isinstance(events, list) or not events:
                raise Refused(400, "Expected events.")
            for event in events:
                fields = EVENT_FIELDS.get(event.get("type")) if isinstance(event, dict) else None
                if fields is None or set(event) != fields or not isinstance(event["seq"], int) or event["seq"] < 1:
                    raise Refused(400, "Bad event.")
                if event["type"] == "tool" and event["status"] not in ("started", "ok", "error"):
                    raise Refused(400, "Bad tool status.")
                if any(not isinstance(event[key], str) for key in fields - {"seq"}):
                    raise Refused(400, "Bad event field.")
            with self.lock:
                run.event_posts += 1
                for event in events:
                    run.events.setdefault(event["seq"], event)
            return self._json({"ok": True})
        if name == "heartbeat/" and method == "POST":
            self._body(request, body)
            run.heartbeats += 1
            return self._json({"cancel": run.cancel})
        if name == "approvals/" and method == "POST":
            value = self._body(request, body)
            if str(value.get("tool", "")).startswith("mcp__studio") or value.get("tool") == "studio_wait_for_approval":
                raise Refused(400, "studio_tool: Studio asks for its own tools when they're called.")
            if set(value) != {"tool", "input_summary", "input_sha256"} or \
                    not re.fullmatch(r"[0-9a-f]{64}", str(value["input_sha256"])):
                raise Refused(400, "Bad approval request.")
            approval_id = f"ap{len(run.approval_requests) + 1}"
            run.approval_requests.append({**value, "id": approval_id})
            run.approval_polls[approval_id] = 0
            return self._json({"approval_id": approval_id}, 201)
        match = re.fullmatch(r"approvals/(ap[0-9]+)/", name)
        if match and method == "GET":
            approval_id = match.group(1)
            if approval_id not in run.approval_polls:
                raise Refused(404, "No such approval.")
            request_row = next(row for row in run.approval_requests if row["id"] == approval_id)
            script = run.approval_script.get(request_row["tool"], ["approved"])
            polls = run.approval_polls[approval_id]
            run.approval_polls[approval_id] = polls + 1
            return self._json({"state": script[min(polls, len(script) - 1)]})
        if name == "upload-url/" and method == "POST":
            value = self._body(request, body)
            if set(value) != {"kind", "size", "sha256", "md5"} or value["kind"] not in ("state", "bundle") or \
                    not isinstance(value["size"], int) or not re.fullmatch(r"[0-9a-f]{64}", str(value["sha256"])) \
                    or not re.fullmatch(r"[A-Za-z0-9+/]{22}==", str(value["md5"])):
                raise Refused(400, "Bad upload-url request.")
            run.upload_requests.append(value)
            blob = f"{value['kind']}-{run.id}-{len(run.upload_requests)}"
            run.uploaded_blob = blob
            return self._json(self.signed_put(blob, value["size"], value["md5"]), 201)
        if name == "finish/" and method == "POST":
            value = self._body(request, body)
            if not set(value) <= FINISH_FIELDS or value.get("status") not in ("succeeded", "failed", "cancelled"):
                raise Refused(400, "Bad finish.")
            run.finished = value
            return self._json({"ok": True})
        raise Refused(404, "Not found.")

    # ------------------------------------------------------------------ MCP and the model relay

    def relay_endpoint(self, request, method, run, name, body):
        if name == "mcp/":
            if method != "POST":
                raise Refused(405, "POST only here.")
            message = json.loads(body.decode() or "{}")
            answer = {"jsonrpc": "2.0", "id": message.get("id"), "result": {"echo": message.get("method")}}
            if "text/event-stream" in (request.headers.get("Accept") or ""):
                return 200, [b"event: message\ndata: ", json.dumps(answer).encode(), b"\n\n"], "text/event-stream"
            return self._json(answer)
        if name.split("?")[0] == "llm/v1/messages" and method == "POST":
            value = json.loads(body.decode() or "{}")
            words = ["Hello", " from", " the", " relay."]
            if not value.get("stream"):
                return self._json({"type": "message", "role": "assistant", "model": value.get("model"),
                                   "content": [{"type": "text", "text": "".join(words)}], "stop_reason": "end_turn",
                                   "usage": {"input_tokens": 1, "output_tokens": 4}})
            frames = [("message_start", {"type": "message_start", "message": {
                "id": "msg_fake", "type": "message", "role": "assistant", "model": value.get("model") or "fake",
                "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 1}}}),
                ("content_block_start", {"type": "content_block_start", "index": 0,
                                         "content_block": {"type": "text", "text": ""}})]
            frames += [("content_block_delta", {"type": "content_block_delta", "index": 0,
                                                "delta": {"type": "text_delta", "text": word}}) for word in words]
            frames += [("content_block_stop", {"type": "content_block_stop", "index": 0}),
                       ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "end_turn",
                                                                             "stop_sequence": None},
                                          "usage": {"output_tokens": 4}}),
                       ("message_stop", {"type": "message_stop"})]
            return 200, [f"event: {kind}\ndata: {json.dumps(data)}\n\n".encode() for kind, data in frames], \
                "text/event-stream"
        raise Refused(404, "Not found.")
