"""Standalone mode: run a workflow with no Studio at all (``foundry-workflow-runner run ./project``).

The same runner runs against a host on ``127.0.0.1`` in this process, which implements the runner protocol
(docs/PROTOCOL.md) for one run:

- ``start`` hands over the manifest's entry, limits and approvals, the trigger, and the declared secrets'
  values from ``--env-file`` or this shell (names only from studio.yaml; nothing else is read);
- the model: the runner's loopback relay forwards to this host's ``llm/``, which forwards to Anthropic (or
  ``ANTHROPIC_BASE_URL``) with your ``ANTHROPIC_API_KEY`` / ``ANTHROPIC_AUTH_TOKEN``, or, for a ``command`` entry
  with only ``OPENAI_API_KEY``, to OpenAI (or ``OPENAI_BASE_URL``). Your key stays in this process: the workflow
  gets the relay address and a dummy key, exactly as in a hosted run;
- approvals for ``approvals.ask`` are asked in this terminal (``--non-interactive`` refuses them all);
- events print as they come; state stays where it is in the project (no uploads);
- no egress proxy unless you pass ``--proxy URL`` (then it's the workflow's only way out).

The project runs in place, like a host's dev run. Exit status: 0 succeeded, 1 failed, 130 cancelled.
"""

import hmac
import http.client
import json
import os
import re
import secrets
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from . import manifest as manifests
from .protocol import Transport
from .relay import _DROP, _DROP_BACK

ANTHROPIC_URL = "https://api.anthropic.com"
OPENAI_URL = "https://api.openai.com/v1"
_FORWARD = {"content-type", "accept", "anthropic-version", "anthropic-beta", "openai-beta", "user-agent"}


def read_env_file(path, names):
    """The values of ``names`` from a dotenv file (``NAME=value``, optional ``export``, quotes, comments)."""
    with open(path, encoding="utf-8") as handle:
        lines = handle.read(1024 * 1024).splitlines()
    found = {}
    for line in lines:
        match = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if not match or match.group(1) not in names:
            continue
        value = match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            quoted_double = value[0] == '"'
            value = value[1:-1]
            if quoted_double:
                value = value.replace("\\n", "\n").replace('\\"', '"')
        else:
            value = re.sub(r"\s+#.*$", "", value)
        found[match.group(1)] = value
    return found


class Asker:
    """Asks for approvals at this terminal, one at a time; refuses all without one or when non-interactive."""

    def __init__(self, interactive, out):
        self.interactive, self.out, self.lock = interactive, out, threading.Lock()

    def _terminal(self):
        if sys.stdin is not None and sys.stdin.isatty():
            return sys.stdin, None
        try:
            handle = open("/dev/tty", "r+", encoding="utf-8")
            return handle, handle
        except OSError:
            return None, None

    def __call__(self, tool, summary):
        if not self.interactive:
            print(f"[approval] {tool}: refused (--non-interactive).", file=self.out, flush=True)
            return "denied"
        with self.lock:
            stream, owned = self._terminal()
            if stream is None:
                print(f"[approval] {tool}: refused (no terminal to ask at).", file=self.out, flush=True)
                return "denied"
            try:
                print(f"\n[approval] The workflow wants to run {tool}:\n  " + summary.replace("\n", "\n  "),
                      file=self.out, flush=True)
                print("Allow it? [y/N] ", end="", file=self.out, flush=True)
                answer = stream.readline().strip().lower()
            finally:
                if owned is not None:
                    owned.close()
            return "approved" if answer in ("y", "yes") else "denied"


class LocalHost:
    """One run's host on loopback. ``spec`` is what ``start`` returns; the model goes upstream from here."""

    def __init__(self, spec, *, model_upstream, asker, transport):
        self.spec, self.upstream, self.ask, self.transport = spec, model_upstream, asker, transport
        self.run_id = uuid.uuid4().hex
        self.token = secrets.token_urlsafe(32)
        self.started = False
        self.finished = None
        self.approvals = {}
        self.cancel = False
        host = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                host.handle(self, "GET")

            def do_POST(self):
                host.handle(self, "POST")

            def do_DELETE(self):
                host.handle(self, "DELETE")

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, name="local-host", daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/runs/{self.run_id}/"

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def _send(self, handler, status, value):
        body = json.dumps(value).encode()
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def handle(self, handler, method):
        parts = urlsplit(handler.path)
        prefix = f"/runs/{self.run_id}/"
        if not parts.path.startswith(prefix):
            return self._send(handler, 404, {"detail": "Not found."})
        given = handler.headers.get("Authorization") or ""
        if not hmac.compare_digest(given, f"Bearer {self.token}") or self.finished is not None:
            return self._send(handler, 401, {"detail": "Bad token."})
        name = parts.path[len(prefix):]
        if name.startswith("llm/"):
            return self._model(handler, method, name[len("llm/"):], parts.query)
        if name == "mcp/":
            return self._send(handler, 404, {"detail": "No Studio connections in a standalone run."})
        length = int(handler.headers.get("Content-Length") or 0)
        try:
            body = json.loads(handler.rfile.read(length).decode() or "{}") if length else {}
        except ValueError:
            return self._send(handler, 400, {"detail": "Malformed JSON."})
        if name == "start/" and method == "POST":
            if self.started:
                return self._send(handler, 409, {"detail": "Already started."})
            self.started = True
            return self._send(handler, 200, self.spec)
        if name == "events/" and method == "POST":
            return self._send(handler, 200, {"accepted": len(body.get("events") or [])})
        if name == "heartbeat/" and method == "POST":
            return self._send(handler, 200, {"cancel": self.cancel})
        if name == "approvals/" and method == "POST":
            approval = uuid.uuid4().hex
            self.approvals[approval] = "pending"

            def decide():
                self.approvals[approval] = self.ask(str(body.get("tool") or "a tool"), str(body.get("input_summary")
                                                                                         or ""))
            threading.Thread(target=decide, daemon=True).start()
            return self._send(handler, 201, {"approval_id": approval, "state": "pending"})
        if name.startswith("approvals/") and method == "GET":
            state = self.approvals.get(name.split("/")[1])
            return self._send(handler, 200 if state else 404, {"state": state} if state else {"detail": "No such."})
        if name == "finish/" and method == "POST":
            self.finished = body
            return self._send(handler, 200, {"status": body.get("status")})
        return self._send(handler, 404, {"detail": "Not found."})

    def _model(self, handler, method, rest, query):
        """Forward the runner relay's model call upstream with your key (never seen by the workflow)."""
        upstream = self.upstream
        if upstream is None:
            return self._send(handler, 403, {"type": "error", "error": {
                "type": "permission_error", "message": "No model key is set for this run (ANTHROPIC_API_KEY)."}})
        if upstream["protocol"] == "openai":
            if not rest.startswith("openai/v1/"):
                return self._send(handler, 404, {"detail": "Not found."})
            rest = rest[len("openai/v1/"):]
        elif rest.startswith("openai/"):
            return self._send(handler, 404, {"detail": "This run's model is Anthropic's."})
        base = upstream["base_url"].rstrip("/")
        target = urlsplit(base + "/" + rest + ("?" + query if query else ""))
        length = int(handler.headers.get("Content-Length") or 0)
        body = handler.rfile.read(length) if length else None
        headers = {name: value for name, value in handler.headers.items() if name.lower() in _FORWARD
                   and name.lower() not in _DROP}
        headers.update(upstream["headers"])
        if body is not None:
            headers["Content-Length"] = str(len(body))
        connection = None
        try:
            connection = self.transport._connection(target)
            connection.request(method, target.path + ("?" + target.query if target.query else ""), body=body,
                               headers=headers)
            response = connection.getresponse()
            handler.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in _DROP_BACK:
                    handler.send_header(name, value)
            handler.send_header("Transfer-Encoding", "chunked")
            handler.end_headers()
            while True:
                data = response.read1(65536)
                if not data:
                    break
                handler.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                handler.wfile.flush()
            handler.wfile.write(b"0\r\n\r\n")
        except (OSError, http.client.HTTPException):
            handler.close_connection = True
            try:
                self._send(handler, 502, {"type": "error", "error": {"type": "api_error",
                                                                     "message": "The model API couldn't be reached."}})
            except OSError:
                pass
        finally:
            if connection is not None:
                connection.close()


def model_upstream(environ, entry):
    """Where this run's model calls go and with which of your credentials, or None."""
    if environ.get("ANTHROPIC_API_KEY") or environ.get("ANTHROPIC_AUTH_TOKEN"):
        headers = ({"x-api-key": environ["ANTHROPIC_API_KEY"]} if environ.get("ANTHROPIC_API_KEY")
                   else {"Authorization": f"Bearer {environ['ANTHROPIC_AUTH_TOKEN']}"})
        return {"protocol": "anthropic", "base_url": environ.get("ANTHROPIC_BASE_URL") or ANTHROPIC_URL,
                "headers": headers}
    if "command" in entry and environ.get("OPENAI_API_KEY"):
        return {"protocol": "openai", "base_url": environ.get("OPENAI_BASE_URL") or OPENAI_URL,
                "headers": {"Authorization": f"Bearer {environ['OPENAI_API_KEY']}"}}
    return None


def run(args, *, environ=None, out=None):
    """``foundry-workflow-runner run DIR``; returns the exit status."""
    from .runner import _PROXY_URL, Runner

    environ = dict(os.environ if environ is None else environ)
    out = sys.stdout if out is None else out
    directory = os.path.abspath(args.directory)
    try:
        _, normal = manifests.read(directory)
    except manifests.ManifestError as error:
        print("studio.yaml isn't valid:\n  " + "\n  ".join(error.errors), file=sys.stderr)
        return 2
    payload = None
    if args.payload:
        try:
            with open(args.payload, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            print("--payload must be a readable JSON file.", file=sys.stderr)
            return 2
    names = set(normal["secrets"])
    values = {}
    if args.env_file:
        try:
            values = read_env_file(args.env_file, names)
        except (OSError, UnicodeError):
            print("--env-file must be a readable UTF-8 file.", file=sys.stderr)
            return 2
    for name in names:
        if name not in values and environ.get(name):
            values[name] = environ[name]
    missing = sorted(names - set(values))
    upstream = model_upstream(environ, normal["entry"])
    if "claude" in normal["entry"] and (upstream is None or upstream["protocol"] != "anthropic"):
        print("Claude Code entries need ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN) in this shell.", file=sys.stderr)
        return 2
    if args.proxy and not _PROXY_URL.match(args.proxy):
        print("--proxy must be an http://[user:pass@]host:port address.", file=sys.stderr)
        return 2
    model = None
    if upstream is not None:
        model = {"relay": True, "protocol": upstream["protocol"], "model": args.model or normal["model"] or "",
                 "base_url": "llm" if upstream["protocol"] == "anthropic" else "llm/openai/v1"}
    spec = {"mode": "run", "attempt": 1, "dev": True, "workflow": {"name": normal["name"], "version": None},
            "entry": normal["entry"], "model": model,
            "trigger": {"kind": args.trigger, "payload": payload, "untrusted": args.trigger == "webhook"},
            "limits": normal["limits"], "approvals": normal["approvals"], "state": normal["state"] or None,
            "package_url": None, "package_sha256": None, "state_get_url": None, "state_sha256": None,
            "env": values, "mcp": None, "workload_proxy": args.proxy or None}
    print(f"Running {normal['name']} here" + (f" (secrets: {', '.join(sorted(values))})" if values else "") + ".",
          file=out, flush=True)
    if missing:
        print("Not set here, so the run won't have them: " + ", ".join(missing), file=out, flush=True)
    host = LocalHost(spec, model_upstream=upstream, asker=Asker(not args.non_interactive, out),
                     transport=Transport(environ=environ, timeout=900))
    runner_env = {key: value for key, value in environ.items() if key not in ("STUDIO_RUN_URL", "STUDIO_RUN_TOKEN")}
    runner_env.update({"STUDIO_RUN_URL": host.url, "STUDIO_RUN_TOKEN": host.token, "STUDIO_WORKDIR": directory,
                       "STUDIO_DEV_SECRETS": ",".join(sorted(values))})
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY"):
        runner_env.pop(key, None)  # The keys stay with the host; the runner and the workflow never hold them.
    for name in values:
        runner_env.pop(name, None)  # Secrets come through start, like a hosted run.
    if os.geteuid() != 0 and not environ.get("STUDIO_WORKLOAD_UID"):
        runner_env.setdefault("STUDIO_RUNNER_SHARED_UID", "1")
    try:
        code = Runner(environ=runner_env, stdout=out).main()
    finally:
        host.close()
    finished = host.finished or {}
    if finished.get("summary"):
        print(f"\n{finished['summary']}", file=out, flush=True)  # Already redacted by the runner.
    return code
