#!/usr/bin/env python3
"""A fake Anthropic Messages API for runs of the real Claude Code in the built image (trust_check.sh, from
scripts/check-image.sh). Not part of the image. The first turn asks for one ``Write`` of ``--file``; the next
turn, once a tool result came back, ends the run with text. Streams like the real API when asked to. Loopback only; logs one JSON line per request to ``--log``
(path, whether a tool result came back and whether it was an error), never headers.

    python -I fake_model.py --port 8765 --file /workspace/hello.txt --log /tmp/model.log
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTENT = "Written by Claude Code in the runner image.\n"


def tool_results(body):
    found = []
    for message in body.get("messages") or []:
        content = message.get("content")
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("type") == "tool_result":
                found.append(block)
    return found


def reply(body, target):
    """``(content blocks, stop_reason)`` for this request."""
    results = tool_results(body)
    tools = {tool.get("name") for tool in body.get("tools") or [] if isinstance(tool, dict)}
    if results:
        state = "denied" if any(block.get("is_error") for block in results) else "written"
        return [{"type": "text", "text": f"Write {state}."}], "end_turn"
    if "Write" in tools:
        return [{"type": "tool_use", "id": "toolu_check_1", "name": "Write",
                 "input": {"file_path": target, "content": CONTENT}}], "tool_use"
    return [{"type": "text", "text": "ok"}], "end_turn"


def frames(blocks, stop, model):
    yield {"type": "message_start", "message": {
        "id": "msg_check", "type": "message", "role": "assistant", "content": [], "model": model,
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}}
    for index, block in enumerate(blocks):
        if block["type"] == "text":
            yield {"type": "content_block_start", "index": index, "content_block": {"type": "text", "text": ""}}
            yield {"type": "content_block_delta", "index": index,
                   "delta": {"type": "text_delta", "text": block["text"]}}
        else:
            yield {"type": "content_block_start", "index": index, "content_block": {
                "type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}}
            yield {"type": "content_block_delta", "index": index,
                   "delta": {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}}
        yield {"type": "content_block_stop", "index": index}
    yield {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
           "usage": {"output_tokens": 5}}
    yield {"type": "message_stop"}


def serve(port, target, log):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _json(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "Not found."}})

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except ValueError:
                body = {}
            path = self.path.split("?", 1)[0]
            results = tool_results(body)
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({"path": path, "stream": bool(body.get("stream")),
                                         "tools": len(body.get("tools") or []), "tool_results": len(results),
                                         "errors": sum(1 for block in results if block.get("is_error"))}) + "\n")
            if path.endswith("/count_tokens"):
                return self._json(200, {"input_tokens": 10})
            if not path.endswith("/v1/messages"):
                return self._json(404, {"type": "error", "error": {"type": "not_found_error", "message": "No."}})
            blocks, stop = reply(body, target)
            model = str(body.get("model") or "claude-check")
            if not body.get("stream"):
                return self._json(200, {"id": "msg_check", "type": "message", "role": "assistant", "model": model,
                                        "content": blocks, "stop_reason": stop, "stop_sequence": None,
                                        "usage": {"input_tokens": 10, "output_tokens": 5}})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for frame in frames(blocks, stop, model):
                chunk = f"event: {frame['type']}\ndata: {json.dumps(frame)}\n\n".encode()
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args(argv)
    serve(args.port, args.file, args.log)


if __name__ == "__main__":
    main(sys.argv[1:])
