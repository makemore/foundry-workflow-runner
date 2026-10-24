"""The workflow runner's egress proof (docs/SECURITY.md, "Egress").

Run as an execution of the runner job, as the runner (start.py drops to uid 10001 first), with
``HTTPS_PROXY`` set to a smoke token for ``example.com``, ``metadata.google.internal`` and
``*.run.app`` only (the last two prove the proxy's deny list beats the token):

    --args=/opt/workflow-runner/bin/python,-I,/opt/workflow-runner/start.py,--egress-probe
    (add --dns-allowed when the runners' DNS block is off)

Expected: the allowed host answers through the proxy, and everything else is refused:

    {"check": "allowed", "target": "https://example.com/", "ok": true, ...}
    {"check": "direct", "target": "https://www.google.com/", "ok": true, ...}      (no route)
    {"check": "other-host", "target": "www.google.com:443", "ok": true, ...}      (403)
    {"check": "metadata", "target": "metadata.google.internal:443", "ok": true}   (403 host_denied)
    {"check": "cloud-run", "target": "<x>.run.app:443", "ok": true}                 (403 host_denied)
    {"check": "sni-mismatch", "target": "example.com:443 + SNI www.google.com", "ok": true} (closed)
    {"check": "dns", "target": "<random>.example.com", "ok": true}                (no answer or 0.0.0.0)
    {"check": "metadata-ip", "target": "169.254.169.254:443", "ok": true}         (403)
    {"check": "private-ip", "target": "<proxy address>:443", "ok": true}          (403)
    {"check": "port", "target": "example.com:80", "ok": true}                     (403)
    {"check": "plain-http", "target": "http://example.com/", "ok": true}          (405)
    {"check": "no-token", "target": "example.com:443", "ok": true}                (407)
    EGRESS PROOF PASSED: 12 of 12

Exit status 0 only when every check is as expected. Never prints the token.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import socket
import ssl
import sys
import urllib.parse
import urllib.request

TIMEOUT = 8


def proxy_parts() -> tuple[str, int, str]:
    url = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or ""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname or not parsed.password:
        raise SystemExit("egress_probe: HTTPS_PROXY=http://run:<token>@host:port is required")
    return parsed.hostname, parsed.port or 3128, urllib.parse.unquote(parsed.password)


def connect_status(host: str, port: int, token: str | None, target: str) -> int:
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        head = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if token is not None:
            head += "Proxy-Authorization: Basic " + base64.b64encode(f"run:{token}".encode()).decode() + "\r\n"
        sock.sendall((head + "\r\n").encode())
        return int(sock.recv(1024).split(b" ", 2)[1])


def plain_status(host: str, port: int, token: str, url: str) -> int:
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        auth = base64.b64encode(f"run:{token}".encode()).decode()
        sock.sendall(f"GET {url} HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
        return int(sock.recv(1024).split(b" ", 2)[1])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allowed", default="example.com")
    parser.add_argument("--dns-allowed", action="store_true", help="the runners' DNS block is off")
    args = parser.parse_args(argv)
    host, port, token = proxy_parts()
    results = []

    def check(name, target, expected, run):
        try:
            got = run()
            ok = got == expected
            detail = f"got {got}, expected {expected}"
        except Exception as exc:  # noqa: BLE001 - every failure is reported, none hidden.
            got, ok = None, expected == "unreachable"
            detail = type(exc).__name__
        results.append(ok)
        print(json.dumps({"check": name, "target": target, "ok": ok, "detail": detail}), flush=True)

    def allowed():
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"https": os.environ.get("HTTPS_PROXY")
                                                                          or os.environ["https_proxy"]}))
        with opener.open(f"https://{args.allowed}/", timeout=TIMEOUT) as response:
            return response.status

    def direct():
        context = ssl.create_default_context()
        with socket.create_connection(("www.google.com", 443), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname="www.google.com"):
                return "reachable"

    def sni_mismatch():
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            auth = base64.b64encode(f"run:{token}".encode()).decode()
            sock.sendall(f"CONNECT {args.allowed}:443 HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
            if not sock.recv(1024).startswith(b"HTTP/1.1 200"):
                return "refused before TLS"
            try:
                with ssl.create_default_context().wrap_socket(sock, server_hostname="www.google.com"):
                    return "handshake completed"
            except (ssl.SSLError, ConnectionError, OSError):
                return "closed"

    def dns():
        name = f"egress-proof-{secrets.token_hex(4)}.example.com"
        try:
            answers = {item[4][0] for item in socket.getaddrinfo(name, 443, proto=socket.IPPROTO_TCP)}
        except OSError:
            return "no answer"
        return "no answer" if answers <= {"0.0.0.0", "::"} else "resolved"

    check("allowed", f"https://{args.allowed}/", 200, allowed)
    check("direct", "https://www.google.com/", "unreachable", direct)
    check("other-host", "www.google.com:443", 403, lambda: connect_status(host, port, token, "www.google.com:443"))
    check("metadata", "metadata.google.internal:443", 403,
          lambda: connect_status(host, port, token, "metadata.google.internal:443"))
    check("cloud-run", "egress-proof.example-region.run.app:443", 403,
          lambda: connect_status(host, port, token, "egress-proof.example-region.run.app:443"))
    check("sni-mismatch", f"{args.allowed}:443 + SNI www.google.com", "closed", sni_mismatch)
    if not args.dns_allowed:
        check("dns", "<random>.example.com", "no answer", dns)
    check("metadata-ip", "169.254.169.254:443", 403, lambda: connect_status(host, port, token, "169.254.169.254:443"))
    check("private-ip", f"{host}:443", 403, lambda: connect_status(host, port, token, f"{host}:443"))
    check("port", f"{args.allowed}:80", 403, lambda: connect_status(host, port, token, f"{args.allowed}:80"))
    check("plain-http", f"http://{args.allowed}/", 405, lambda: plain_status(host, port, token, f"http://{args.allowed}/"))
    check("no-token", f"{args.allowed}:443", 407, lambda: connect_status(host, port, None, f"{args.allowed}:443"))

    passed = sum(results)
    verdict = "PASSED" if passed == len(results) else "FAILED"
    print(f"EGRESS PROOF {verdict}: {passed} of {len(results)}", flush=True)
    return 0 if verdict == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
