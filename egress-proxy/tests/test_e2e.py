"""End to end: real sockets, a local TLS (HTTPS) server, the proxy on its own event loop, and
clients that tunnel through it (a raw socket and urllib's HTTPS_PROXY path, the one runners use).

The upstream server listens on 127.0.0.1:443 (the proxy only ever connects to port 443), so the
container runs with net.ipv4.ip_unprivileged_port_start=0 (scripts/test-docker.sh). Loopback is
let through only by the test-only ``_test_allowed_networks`` constructor argument, for the name
``echo.test``; every other refusal below runs the production policy.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import http.server
import io
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
import urllib.error
import urllib.request

import egress_proxy as ep

HERE = os.path.dirname(os.path.abspath(__file__))
KEY = b"e2e-test-key-not-a-real-secret-000000000"


def make_cert(directory: str) -> tuple[str, str]:
    cert, key = os.path.join(directory, "cert.pem"), os.path.join(directory, "key.pem")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=echo.test",
                    "-addext", "subjectAltName=DNS:echo.test", "-keyout", key, "-out", cert],
                   check=True, capture_output=True)
    return cert, key


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API.
        body = b"hello from echo.test"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FakeDNS:
    def __init__(self, table: dict[str, list[list[str]]]):
        self.table = {name: list(answers) for name, answers in table.items()}
        self.calls: list[str] = []

    async def __call__(self, host: str, port: int) -> list[str]:
        self.calls.append(host)
        answers = self.table.get(host)
        if not answers:
            raise socket.gaierror("no such name")
        return answers.pop(0) if len(answers) > 1 else answers[0]


class ProxyThread:
    def __init__(self, proxy: ep.EgressProxy):
        self.proxy = proxy
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        asyncio.set_event_loop(self.loop)
        server = self.loop.run_until_complete(self.proxy.start())
        self.port = server.sockets[0].getsockname()[1]
        self.ready.set()
        self.loop.run_forever()

    def __enter__(self):
        self.thread.start()
        self.ready.wait(5)
        return self

    def __exit__(self, *exc):
        asyncio.run_coroutine_threadsafe(self.proxy.stop(), self.loop).result(5)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.cert, cls.key = make_cert(cls.tmp.name)
        try:
            cls.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 443), Handler)
        except PermissionError:
            raise unittest.SkipTest("needs 127.0.0.1:443: run with net.ipv4.ip_unprivileged_port_start=0 "
                                    "(scripts/test-docker.sh)") from None
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cls.cert, cls.key)
        # Handshake in the handler thread, not in accept(): tunnels that hold a connection open without
        # speaking TLS must not stall the accept loop.
        cls.httpd.socket = server_ctx.wrap_socket(cls.httpd.socket, server_side=True, do_handshake_on_connect=False)
        cls.httpd_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.httpd_thread.start()
        cls.client_ctx = ssl.create_default_context(cafile=cls.cert)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        self.dns = FakeDNS({
            "echo.test": [["127.0.0.1"]],
            "metadata.google.internal": [["169.254.169.254"]],
            "internal.test": [["10.0.0.7"]],
            "mixed.test": [["127.0.0.1", "10.0.0.7"]],
            "rebind.test": [["127.0.0.1"], ["10.0.0.7"]],
            "public.test": [["8.8.8.8"]],
            "storage.googleapis.com": [["127.0.0.1"]],
        })
        self.config = ep.Config(listen_host="127.0.0.1", listen_port=0, connect_timeout=1, idle_timeout=5)
        self.hosts = ["echo.test", "rebind.test", "metadata.google.internal", "internal.test", "mixed.test",
                      "public.test", "storage.googleapis.com", "*.run.app"]
        self.logs: list[dict] = []
        patcher = unittest.mock.patch.object(ep, "log", lambda event, **f: self.logs.append({"event": event, **f}))
        patcher.start()
        self.addCleanup(patcher.stop)

    def proxy(self, **config) -> ProxyThread:
        for name, value in config.items():
            setattr(self.config, name, value)
        return ProxyThread(ep.EgressProxy(self.config, [KEY], resolver=self.dns,
                                          _test_allowed_networks=["127.0.0.1/32"]))

    def token(self, run="run-e2e", hosts=None, ttl=60) -> str:
        return ep.mint_token(run, self.hosts if hosts is None else hosts, int(time.time()) + ttl, KEY)

    def connect(self, port: int, target: str, token: str | None) -> tuple[socket.socket, int]:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        head = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if token is not None:
            head += "Proxy-Authorization: Basic " + base64.b64encode(f"run:{token}".encode()).decode() + "\r\n"
        sock.sendall((head + "\r\n").encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk
        status = int(response.split(b" ", 2)[1]) if response else 0
        return sock, status

    def tls(self, sock: socket.socket, sni: str | None = "echo.test", verify: bool = True) -> ssl.SSLSocket:
        ctx = self.client_ctx
        if not verify:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=sni)

    def assert_tunnel_closed(self, sock: socket.socket, sni: str | None, verify: bool = False):
        """The proxy hangs up during the handshake: nothing reached the upstream."""
        sock.settimeout(5)
        with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
            tls = self.tls(sock, sni, verify=verify)
            tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            if not tls.recv(1024):
                raise ConnectionResetError("closed")
        sock.close()

    def get_through(self, sock: socket.socket, path="/") -> bytes:
        tls = self.tls(sock)
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: echo.test\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data += chunk
        tls.close()
        return data

    # --- Allowed ------------------------------------------------------------

    def test_tunnel_tls_through_the_proxy(self):
        with self.proxy() as p:
            sock, status = self.connect(p.port, "echo.test:443", self.token())
            self.assertEqual(status, 200)
            self.assertIn(b"hello from echo.test", self.get_through(sock))
        decisions = [entry for entry in self.logs if entry["event"] == "egress"]
        self.assertEqual(decisions[0]["decision"], "allow")
        close = [entry for entry in decisions if entry["decision"] == "close"][0]
        self.assertEqual((close["run"], close["host"], close["end"]), ("run-e2e", "echo.test", "closed"))
        self.assertGreater(close["bytes_up"], 0)
        self.assertGreater(close["bytes_down"], 0)

    def test_urllib_https_proxy_with_credentials_in_the_url(self):
        """What a runner does: HTTPS_PROXY=http://run:<token>@proxy:3128."""
        with self.proxy() as p:
            proxy_url = f"http://run:{self.token()}@127.0.0.1:{p.port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": proxy_url}),
                                                 urllib.request.HTTPSHandler(context=self.client_ctx))
            body = json.dumps({"n": list(range(20000))}).encode()  # ~100 KB each way.
            with opener.open(urllib.request.Request("https://echo.test/echo", data=body), timeout=5) as response:
                self.assertEqual(response.read(), body)
            other = f"http://run:{self.token(hosts=['other.test'])}@127.0.0.1:{p.port}"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": other}),
                                                 urllib.request.HTTPSHandler(context=self.client_ctx))
            with self.assertRaises(OSError) as caught:
                opener.open("https://echo.test/", timeout=5)
            self.assertIn("403", str(caught.exception))

    def test_early_data_after_the_head_is_forwarded(self):
        """A client may send its TLS ClientHello right behind the CONNECT head."""
        with self.proxy() as p:
            raw = socket.create_connection(("127.0.0.1", p.port), timeout=5)
            auth = base64.b64encode(f"run:{self.token()}".encode()).decode()
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            tls = self.client_ctx.wrap_bio(incoming, outgoing, server_hostname="echo.test")
            with contextlib.suppress(ssl.SSLWantReadError):
                tls.do_handshake()
            raw.sendall(f"CONNECT echo.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode()
                        + outgoing.read())
            buffer = b""
            while b"\r\n\r\n" not in buffer:
                buffer += raw.recv(4096)
            head, _, rest = buffer.partition(b"\r\n\r\n")
            self.assertTrue(head.startswith(b"HTTP/1.1 200"))
            incoming.write(rest)
            while True:
                try:
                    tls.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    if outgoing.pending:
                        raw.sendall(outgoing.read())
                    incoming.write(raw.recv(65536))
            if outgoing.pending:
                raw.sendall(outgoing.read())
            self.assertEqual(tls.server_hostname, "echo.test")
            raw.close()

    # --- Refused ------------------------------------------------------------

    def test_refusals(self):
        token = self.token()
        cases = [
            ("echo.test:443", None, 407),
            ("echo.test:443", self.token(hosts=["other.test"]), 403),
            ("echo.test:80", token, 403),
            ("127.0.0.1:443", token, 403),
            ("[::1]:443", token, 403),
            ("metadata.google.internal:443", token, 403),
            ("x.run.app:443", token, 403),
            ("internal.test:443", token, 403),
            ("mixed.test:443", token, 403),
            ("nxdomain.test:443", self.token(hosts=["nxdomain.test"]), 502),
            ("public.test:443", token, 502),  # No network in the test container: connect fails.
        ]
        with self.proxy() as p:
            for target, tok, expected in cases:
                with self.subTest(target):
                    sock, status = self.connect(p.port, target, tok)
                    self.assertEqual(status, expected)
                    sock.close()
            # Plain HTTP through the proxy is refused.
            sock = socket.create_connection(("127.0.0.1", p.port), timeout=5)
            sock.sendall(b"GET http://echo.test/ HTTP/1.1\r\nHost: echo.test\r\n\r\n")
            self.assertTrue(sock.recv(1024).startswith(b"HTTP/1.1 405"))
            sock.close()
        reasons = [entry.get("reason") for entry in self.logs if entry.get("decision") == "deny"]
        for reason in ("auth_missing", "host_not_allowed", "host_denied", "port", "ip_literal", "address_not_public",
                       "dns", "plain_http"):
            self.assertIn(reason, reasons)

    def test_sni_must_be_the_connect_host(self):
        with self.proxy() as p:
            sock, status = self.connect(p.port, "echo.test:443", self.token())
            self.assertEqual(status, 200)
            self.assert_tunnel_closed(sock, None)  # No SNI.
            sock, _ = self.connect(p.port, "echo.test:443", self.token())
            self.assert_tunnel_closed(sock, "other.test")
            sock, _ = self.connect(p.port, "echo.test:443", self.token())
            sock.sendall(b"GET / HTTP/1.1\r\nHost: echo.test\r\n\r\n")  # Not TLS at all.
            sock.settimeout(5)
            self.assertEqual(sock.recv(1024), b"")
            sock.close()
            sock, _ = self.connect(p.port, "ECHO.test:443", self.token())
            self.assertIn(b"hello from echo.test", self.get_through(sock))  # Case doesn't matter.
        reasons = [entry.get("reason") for entry in self.logs if entry.get("decision") == "deny"]
        self.assertEqual(reasons, ["sni_missing", "sni_mismatch", "not_tls"])
        self.assertEqual(sum(1 for entry in self.logs if entry.get("decision") == "allow"), 1)

    def test_domain_fronting_through_storage_googleapis(self):
        """CONNECT to the one allowed Google API host, then a TLS handshake naming a Cloud Run
        service (which would count as internal from this project's VPC): refused before any byte
        reaches Google. The honest handshake to the same host goes through."""
        with self.proxy() as p:
            for sni in ("service-1234.example-region.run.app", "secretmanager.googleapis.com",
                        "metadata.google.internal"):
                sock, status = self.connect(p.port, "storage.googleapis.com:443", self.token())
                self.assertEqual(status, 200)
                self.assert_tunnel_closed(sock, sni)
            sock, status = self.connect(p.port, "storage.googleapis.com:443", self.token())
            tls = self.tls(sock, "storage.googleapis.com", verify=False)  # The test server's cert is echo.test.
            tls.sendall(b"GET / HTTP/1.1\r\nHost: storage.googleapis.com\r\nConnection: close\r\n\r\n")
            self.assertIn(b"hello from echo.test", tls.recv(4096) + tls.recv(4096))
            tls.close()
            # And naming the Cloud Run host in CONNECT is refused outright, token or not.
            sock, status = self.connect(p.port, "service-1234.example-region.run.app:443", self.token())
            self.assertEqual(status, 403)
            sock.close()
        reasons = [entry.get("reason") for entry in self.logs if entry.get("decision") == "deny"]
        self.assertEqual(reasons, ["sni_mismatch"] * 3 + ["host_denied"])

    def test_dns_rebinding_connects_to_the_checked_address(self):
        """The name resolves once, to an allowed address; the proxy dials that address. A second
        lookup (which would now say 10.0.0.7) never happens."""
        with self.proxy() as p:
            sock, status = self.connect(p.port, "rebind.test:443", self.token())
            self.assertEqual(status, 200)
            sock.close()
            self.assertEqual(self.dns.calls, ["rebind.test"])
            sock, status = self.connect(p.port, "rebind.test:443", self.token())
            self.assertEqual(status, 403)  # The next lookup's private answer is refused.
            sock.close()

    def test_head_too_large_and_slow_clients(self):
        with self.proxy(handshake_timeout=0.3) as p:
            sock = socket.create_connection(("127.0.0.1", p.port), timeout=5)
            sock.sendall(b"CONNECT echo.test:443 HTTP/1.1\r\nX: " + b"a" * (ep.MAX_HEAD_BYTES + 10) + b"\r\n\r\n")
            self.assertTrue(sock.recv(1024).startswith(b"HTTP/1.1 431"))
            sock.close()
            sock = socket.create_connection(("127.0.0.1", p.port), timeout=5)
            sock.sendall(b"CONNECT echo.test:443 HTTP/1.1\r\n")  # Never finishes the head.
            self.assertEqual(sock.recv(1024), b"")
            sock.close()

    def test_per_run_connection_cap(self):
        with self.proxy(max_connections_per_run=2) as p:
            held = [self.connect(p.port, "echo.test:443", self.token())[0] for _ in range(2)]
            sock, status = self.connect(p.port, "echo.test:443", self.token())
            self.assertEqual(status, 429)
            sock.close()
            other, status = self.connect(p.port, "echo.test:443", self.token(run="run-other"))
            self.assertEqual(status, 200)  # The cap is per run.
            other.close()
            held.pop(0).close()
            deadline = time.time() + 5
            while time.time() < deadline:
                sock, status = self.connect(p.port, "echo.test:443", self.token())
                sock.close()
                if status == 200:
                    break
                time.sleep(0.05)
            self.assertEqual(status, 200)
            for sock in held:
                sock.close()

    def test_idle_timeout(self):
        with self.proxy(idle_timeout=0.3) as p:
            sock, status = self.connect(p.port, "echo.test:443", self.token())
            self.assertEqual(status, 200)
            tls = self.tls(sock)
            tls.settimeout(5)
            started = time.monotonic()
            with contextlib.suppress(ssl.SSLError, ConnectionError):
                self.assertEqual(tls.recv(1024), b"")  # The proxy hangs up.
            self.assertLess(time.monotonic() - started, 3)
            sock.close()
        self.assertTrue(any(entry.get("end") == "idle" for entry in self.logs))

    def test_lifetime_ends_at_token_expiry(self):
        with self.proxy(idle_timeout=30) as p:
            sock, status = self.connect(p.port, "echo.test:443", self.token(ttl=2))
            self.assertEqual(status, 200)
            tls = self.tls(sock)
            tls.settimeout(6)
            with contextlib.suppress(ssl.SSLError, ConnectionError):
                self.assertEqual(tls.recv(1024), b"")
            sock.close()
        self.assertTrue(any(entry.get("end") == "lifetime" for entry in self.logs))


class Logs(unittest.TestCase):
    def test_logs_are_value_free_json(self):
        dns = FakeDNS({"echo.test": [["127.0.0.1"]]})
        config = ep.Config(listen_host="127.0.0.1", listen_port=0)
        token = ep.mint_token("run-logs", ["echo.test"], int(time.time()) + 60, KEY)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with ProxyThread(ep.EgressProxy(config, [KEY], resolver=dns)) as p:
                for target in ("echo.test:443", "evil.test:443", "10.1.2.3:443"):
                    sock = socket.create_connection(("127.0.0.1", p.port), timeout=5)
                    auth = base64.b64encode(f"run:{token}".encode()).decode()
                    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n"
                                 f"Cookie: secret-cookie\r\n\r\n".encode())
                    sock.recv(1024)
                    sock.close()
                time.sleep(0.1)
        text = out.getvalue()
        records = [json.loads(line) for line in text.splitlines()]
        self.assertTrue(records)
        for value in (token, token.split(".")[1], auth, "secret-cookie", KEY.decode(), "10.1.2.3"):
            self.assertNotIn(value, text)
        allowed = {"ts", "event", "decision", "reason", "status", "run", "host", "end", "bytes_up", "bytes_down", "ms"}
        for record in records:
            self.assertLessEqual(set(record), allowed)


class Process(unittest.TestCase):
    """The real entry point: fail closed without a key, re-read keys on SIGHUP."""

    def run_proxy(self, key_file: str, port: int) -> subprocess.Popen:
        env = dict(os.environ, EGRESS_LISTEN=f"127.0.0.1:{port}", EGRESS_KEY_FILE=key_file)
        return subprocess.Popen([sys.executable, os.path.join(os.path.dirname(HERE), "egress_proxy.py")], env=env,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    def free_port(self) -> int:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def status(self, port: int, token: str) -> int:
        deadline = time.time() + 5
        while True:
            try:
                sock = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except ConnectionRefusedError:
                if time.time() > deadline:
                    raise
                time.sleep(0.05)
        auth = base64.b64encode(f"run:{token}".encode()).decode()
        # A host that is never in the rules: 403 proves the token verified, 407 that it didn't.
        sock.sendall(f"CONNECT not-allowed.test:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        response = sock.recv(1024)
        sock.close()
        return int(response.split(b" ", 2)[1])

    def test_no_key_no_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_proxy(os.path.join(tmp, "missing"), self.free_port())
            out, _ = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 1)
            self.assertIn('"ok":false', out)

    def test_sighup_reloads_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = os.path.join(tmp, "key")
            old, new = b"o" * 32, b"n" * 32
            with open(key_file, "wb") as handle:
                handle.write(old)
            port = self.free_port()
            proc = self.run_proxy(key_file, port)
            try:
                exp = int(time.time()) + 60
                old_token, new_token = (ep.mint_token("r", ["a.test"], exp, k) for k in (old, new))
                self.assertEqual(self.status(port, old_token), 403)
                self.assertEqual(self.status(port, new_token), 407)
                with open(key_file, "wb") as handle:
                    handle.write(new + b"\n")
                proc.send_signal(signal.SIGHUP)
                deadline = time.time() + 5
                while self.status(port, new_token) != 403 and time.time() < deadline:
                    time.sleep(0.05)
                self.assertEqual(self.status(port, new_token), 403)
                self.assertEqual(self.status(port, old_token), 407)
            finally:
                proc.send_signal(signal.SIGTERM)
                out, _ = proc.communicate(timeout=10)
            self.assertEqual(proc.returncode, 0)
            self.assertNotIn(new.decode(), out)
            self.assertNotIn(old.decode(), out)


if __name__ == "__main__":
    unittest.main()
