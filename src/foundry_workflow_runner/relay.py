"""A loopback relay to two of the run's Studio endpoints, so the workflow never holds the run token.

It listens on ``127.0.0.1`` under an unguessable per-run path secret and forwards exactly two paths, adding
``Authorization: Bearer <run token>``:

- ``/<secret>/mcp`` → ``<run url>mcp/`` (the host's MCP server for the run's connections; streamable HTTP, SSE);
- ``/<secret>/llm/<path>`` → ``<run url>llm/<path>`` (the host's Anthropic-compatible model relay; streamed).

Claude Code and ``entry.command`` get ``ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/<secret>/llm`` with a dummy
``ANTHROPIC_AUTH_TOKEN``, and the MCP config points at ``/<secret>/mcp``. Credentials the workflow sends
(``Authorization``, ``X-Api-Key``, cookies) are dropped. Responses stream through as they arrive. Nothing about
a request is logged.
"""

import http.client
import json
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DUMMY_TOKEN = "studio-relay"
MAX_BODY = 32 * 1024 * 1024
_DROP = {"host", "connection", "keep-alive", "proxy-authorization", "proxy-connection", "te", "trailer",
         "transfer-encoding", "upgrade", "authorization", "x-api-key", "cookie", "content-length", "expect"}
_DROP_BACK = {"connection", "keep-alive", "transfer-encoding", "trailer", "upgrade", "proxy-authenticate",
              "set-cookie", "content-length"}
_REST = re.compile(r"^[A-Za-z0-9._~/-]*$")


class Relay:
    def __init__(self, run_url, token, transport):
        self.run_url, self._token, self.transport = run_url, token, transport
        self.secret = secrets.token_urlsafe(32)
        relay = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                relay.forward(self, "GET")

            def do_POST(self):
                relay.forward(self, "POST")

            def do_DELETE(self):
                relay.forward(self, "DELETE")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, name="studio-relay", daemon=True).start()

    @property
    def base(self):
        return f"http://127.0.0.1:{self.port}/{self.secret}"

    @property
    def llm_url(self):
        return self.base + "/llm"

    @property
    def mcp_url(self):
        return self.base + "/mcp"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _target(self, raw_path):
        parts = urlsplit(raw_path)
        prefix = f"/{self.secret}/"
        if not secrets.compare_digest(parts.path[:len(prefix)], prefix):
            return None
        rest = parts.path[len(prefix):]
        query = ("?" + parts.query) if parts.query else ""
        if rest in ("mcp", "mcp/"):
            return self.run_url + "mcp/" + query
        if rest.startswith("llm/") and _REST.match(rest) and "//" not in rest and \
                not any(segment in (".", "..") for segment in rest.split("/")):
            return self.run_url + rest + query
        return None

    def _refuse(self, handler, status, message):
        body = json.dumps({"type": "error", "error": {"type": "api_error", "message": message}}).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _body(self, handler):
        if "chunked" in (handler.headers.get("Transfer-Encoding") or "").lower():
            chunks, total = [], 0
            while True:
                size = int(handler.rfile.readline(64).split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    while handler.rfile.readline(1024) not in (b"\r\n", b"\n", b""):
                        pass
                    return b"".join(chunks)
                total += size
                if total > MAX_BODY:
                    raise ValueError
                chunks.append(handler.rfile.read(size))
                handler.rfile.readline(4)
        length = int(handler.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            raise ValueError
        return handler.rfile.read(length) if length else None

    def forward(self, handler, method):
        target = self._target(handler.path)
        if target is None:
            handler.close_connection = True
            return self._refuse(handler, 404, "Not found.")
        try:
            body = self._body(handler)
        except ValueError:
            handler.close_connection = True
            return self._refuse(handler, 413, "The request is too large or malformed.")
        headers = {name: value for name, value in handler.headers.items() if name.lower() not in _DROP}
        headers["Authorization"] = f"Bearer {self._token}"
        if body is not None:
            headers["Content-Length"] = str(len(body))
        parts = urlsplit(target)
        connection = None
        try:
            connection = self.transport._connection(parts)
            connection.request(method, parts.path + ("?" + parts.query if parts.query else ""), body=body,
                               headers=headers)
            upstream = connection.getresponse()
        except (OSError, http.client.HTTPException):
            if connection is not None:
                connection.close()
            return self._refuse(handler, 502, "The host couldn't be reached.")
        try:
            handler.send_response(upstream.status)
            for name, value in upstream.getheaders():
                if name.lower() not in _DROP_BACK:
                    handler.send_header(name, value)
            length = upstream.getheader("Content-Length")
            empty = upstream.status in (204, 304) or 100 <= upstream.status < 200
            chunked = length is None and not empty
            if chunked:
                handler.send_header("Transfer-Encoding", "chunked")
            elif not empty:
                handler.send_header("Content-Length", length)
            handler.end_headers()
            if empty:
                return
            while True:
                data = upstream.read1(65536)
                if not data:
                    break
                if chunked:
                    handler.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                else:
                    handler.wfile.write(data)
                handler.wfile.flush()
            if chunked:
                handler.wfile.write(b"0\r\n\r\n")
                handler.wfile.flush()
        except (OSError, http.client.HTTPException):
            handler.close_connection = True
        finally:
            connection.close()
