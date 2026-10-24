"""Unit tests: tokens (with the fixed vectors), Proxy-Authorization, host rules, addresses, keys."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import pathlib
import ssl
import tempfile
import unittest

import egress_proxy as ep

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = json.loads((HERE / "token_vectors.json").read_text())
KEY = VECTORS["key"].encode()
NOW = VECTORS["now"]


def basic(token: str, user: str = "run") -> str:
    return "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()


class TokenVectorTests(unittest.TestCase):
    def test_vectors(self):
        for vector in VECTORS["vectors"]:
            with self.subTest(vector["name"]):
                if vector["valid"]:
                    grant = ep.verify_token(vector["token"], [KEY], NOW)
                    self.assertEqual(grant.run, vector["run"])
                    self.assertEqual(grant.expires, vector["x"])
                    for rule in vector["hosts"]:
                        if not rule.startswith("*."):
                            self.assertTrue(grant.rules.allows(rule))
                else:
                    with self.assertRaises(ep.TokenError) as caught:
                        ep.verify_token(vector["token"], [KEY], NOW)
                    self.assertEqual(caught.exception.reason, vector["error"])

    def test_vectors_are_the_contract_construction(self):
        """Each vector is exactly base64url(compact JSON r,h,x) + '.' + base64url(HMAC), so another
        implementation that follows the contract produces byte-identical tokens."""
        for vector in VECTORS["vectors"]:
            if "run" not in vector:
                continue
            with self.subTest(vector["name"]):
                key = vector.get("signed_with", VECTORS["key"]).encode()
                self.assertEqual(ep.mint_token(vector["run"], vector["hosts"], vector["x"], key), vector["token"])
                segment = vector["token"].split(".")[0]
                payload = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
                self.assertEqual(payload, json.dumps({"r": vector["run"], "h": vector["hosts"], "x": vector["x"]},
                                                     separators=(",", ":")).encode())

    def test_other_serialisations_verify_too(self):
        """The MAC covers the segment as sent, so spacing, key order and padding don't matter."""
        payload = json.dumps({"x": NOW + 60, "h": ["a.example.com"], "r": 42}, indent=1)
        segment = base64.urlsafe_b64encode(payload.encode()).decode()  # With padding.
        token = segment + "." + ep.sign(segment, KEY)
        grant = ep.verify_token(token, [KEY], NOW)
        self.assertEqual(grant.run, "42")

    def test_any_loaded_key_verifies(self):
        token = VECTORS["vectors"][0]["token"]
        other = b"o" * 40
        self.assertEqual(ep.verify_token(token, [other, KEY], NOW).run, "wfr_7Kq2mN9xT4")
        with self.assertRaises(ep.TokenError):
            ep.verify_token(token, [other], NOW)
        with self.assertRaises(ep.TokenError) as caught:
            ep.verify_token(token, [], NOW)
        self.assertEqual(caught.exception.reason, "no_key")

    def test_expiry_boundary(self):
        token = ep.mint_token("r1", ["a.example.com"], NOW + 1, KEY)
        ep.verify_token(token, [KEY], NOW + 0.999)
        with self.assertRaises(ep.TokenError):
            ep.verify_token(token, [KEY], NOW + 1)

    def test_malformed(self):
        good = ep.mint_token("r1", ["a.example.com"], NOW + 60, KEY)
        segment, mac = good.split(".")
        cases = {
            "empty": "",
            "no dot": segment,
            "two dots": good + ".x",
            "short mac": segment + "." + mac[:-4],
            "bad chars": segment + "!" + "." + mac,
            "huge": "a" * (ep.MAX_TOKEN_CHARS + 1),
        }
        for name, token in cases.items():
            with self.subTest(name), self.assertRaises(ep.TokenError):
                ep.verify_token(token, [KEY], NOW)

        def signed(claims) -> str:
            seg = ep.b64url_encode(json.dumps(claims).encode())
            return seg + "." + ep.sign(seg, KEY)

        bad_claims = {
            "not an object": [1, 2],
            "bool run": {"r": True, "h": [], "x": NOW + 60},
            "empty run": {"r": "", "h": [], "x": NOW + 60},
            "long run": {"r": "r" * 200, "h": [], "x": NOW + 60},
            "hosts not a list": {"r": "r", "h": "a.example.com", "x": NOW + 60},
            "host not a string": {"r": "r", "h": [1], "x": NOW + 60},
            "too many hosts": {"r": "r", "h": ["a.example.com"] * 300, "x": NOW + 60},
            "float expiry": {"r": "r", "h": [], "x": NOW + 60.5},
            "bool expiry": {"r": "r", "h": [], "x": True},
            "missing expiry": {"r": "r", "h": []},
        }
        for name, claims in bad_claims.items():
            with self.subTest(name), self.assertRaises(ep.TokenError) as caught:
                ep.verify_token(signed(claims), [KEY], NOW)
            self.assertEqual(caught.exception.reason, "malformed")

    def test_proxy_authorization(self):
        token = VECTORS["vectors"][0]["token"]
        self.assertEqual(ep.parse_proxy_authorization(basic(token)), token)
        self.assertEqual(ep.parse_proxy_authorization("basic  " + basic(token)[6:]), token)
        for value in (None, "", "Bearer " + token, basic(token, user="other"), "Basic !!!",
                      "Basic " + base64.b64encode(token.encode()).decode(), basic("")):
            with self.subTest(value=value and value[:20]), self.assertRaises(ep.TokenError):
                ep.parse_proxy_authorization(value)


class HostTests(unittest.TestCase):
    def test_ip_literals_in_every_notation(self):
        for host in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "8.8.8.8", "[::1]", "::1", "fe80::1",
                     "2130706433", "0x7f000001", "0x7f.1", "127.1", "017700000001", "0177.0.0.1",
                     "[::ffff:127.0.0.1]", "1.2.3.4."):
            with self.subTest(host):
                self.assertTrue(ep.is_ip_literal(host))
                self.assertIsNone(ep.normalize_host(host))

    def test_names(self):
        self.assertEqual(ep.normalize_host("API.Xero.COM."), "api.xero.com")
        for host in ("localhost", "", ".", "a..b", "-a.com", "a-.com", "a_b.com", "x" * 64 + ".com",
                     "a.123", "é.com", "a.com:443", ("a." * 127) + "com"):
            with self.subTest(host):
                self.assertIsNone(ep.normalize_host(host))

    def test_rules(self):
        rules = ep.HostRules(["api.xero.com", "*.googleapis.com", "Studio.Example.org", "*", "*.com",
                              "10.0.0.1", "*.10.0.0.1", "bad host", "*.", "metadata.google.internal"])
        allowed = ("api.xero.com", "storage.googleapis.com", "a.b.googleapis.com", "studio.example.org",
                   "metadata.google.internal")
        denied = ("xero.com", "googleapis.com", "evilgoogleapis.com", "googleapis.com.evil.net",
                  "api.xero.com.evil.net", "example.com", "foo.com", "10.0.0.1")
        for host in allowed:
            self.assertTrue(rules.allows(host), host)
        for host in denied:
            self.assertFalse(rules.allows(host), host)
        self.assertEqual(rules.suffixes, ("googleapis.com",))

    def test_addresses(self):
        public = ("8.8.8.8", "1.1.1.1", "142.250.180.14", "2001:4860:4860::8888", "::ffff:8.8.8.8")
        private = ("10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "127.255.255.254", "169.254.169.254",
                   "169.254.1.1", "100.64.0.1", "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.1.1.1", "240.0.0.1",
                   "255.255.255.255", "192.0.0.1", "198.18.0.1", "192.0.2.1", "::1", "::", "fe80::1", "fc00::1",
                   "fd00:ec2::254", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a00:1",
                   "2002:a00:1::", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "ff02::1", "fec0::1", "not-an-ip",
                   "fe80::1%eth0")
        for address in public:
            self.assertTrue(ep.address_allowed(address), address)
        for address in private:
            self.assertFalse(ep.address_allowed(address), address)


class DeniedHostTests(unittest.TestCase):
    def test_denied_whatever_the_token_says(self):
        for host in ("service-123.example-region.run.app", "run.app", "x.a.run.app", "compute.googleapis.com",
                     "secretmanager.googleapis.com", "bucket.storage.googleapis.com", "googleapis.com",
                     "lh3.googleusercontent.com", "x.cloud.goog", "metadata.google.internal", "db.internal",
                     "printer.local", "app.localhost", "region-proj.cloudfunctions.net", "proj.appspot.com",
                     "metadata.example.com", "metadata-server.example.com"):
            with self.subTest(host):
                self.assertTrue(ep.host_denied(host))

    def test_not_denied(self):
        for host in ("storage.googleapis.com", "api.anthropic.com", "studio.example.com",
                     "host.example.net", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
                     "api.xero.com", "notgoogleapis.com", "example.com", "my-metadata.example.com",
                     "run.app.example.com", "googleapis.com.example.org"):
            with self.subTest(host):
                self.assertFalse(ep.host_denied(host))


def real_client_hello(server_hostname: str | None) -> bytes:
    """A ClientHello exactly as Python's TLS stack sends it (one or more records)."""
    ctx = ssl.create_default_context()
    if server_hostname is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def build_hello(names=None, extra_extensions=b"", extensions=True) -> bytes:
    """A minimal ClientHello handshake message; ``names`` is [(name_type, bytes)]."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    if extensions:
        exts = b""
        if names is not None:
            entries = b"".join(bytes([kind]) + len(name).to_bytes(2, "big") + name for kind, name in names)
            data = len(entries).to_bytes(2, "big") + entries
            exts += b"\x00\x00" + len(data).to_bytes(2, "big") + data
        exts += extra_extensions
        body += len(exts).to_bytes(2, "big") + exts
    return b"\x01" + len(body).to_bytes(3, "big") + body


def records(handshake: bytes, split: int | None = None) -> bytes:
    parts = [handshake] if split is None else [handshake[:split], handshake[split:]]
    return b"".join(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part for part in parts)


def read_hello(data: bytes, eof: bool = True):
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(data)
        if eof:
            reader.feed_eof()
        return await ep.read_client_hello(reader)
    return asyncio.run(run())


class ClientHelloTests(unittest.TestCase):
    def test_real_client_hello(self):
        raw = real_client_hello("api.example.com")
        got, sni = read_hello(raw + b"trailing application data")
        self.assertEqual((got, sni), (raw, "api.example.com"))
        _, sni = read_hello(real_client_hello(None))
        self.assertIsNone(sni)

    def test_hello_split_across_records(self):
        hello = build_hello([(0, b"api.example.com")])
        raw, sni = read_hello(records(hello, split=7))
        self.assertEqual(sni, "api.example.com")
        self.assertEqual(raw, records(hello, split=7))
        real = real_client_hello("api.example.com")
        handshake = real[5:]
        self.assertEqual(read_hello(records(handshake, split=40))[1], "api.example.com")

    def test_synthetic_cases(self):
        self.assertEqual(ep.client_hello_sni(build_hello([(0, b"a.example.com")])), "a.example.com")
        self.assertIsNone(ep.client_hello_sni(build_hello(None)))
        self.assertIsNone(ep.client_hello_sni(build_hello(extensions=False)))
        self.assertIsNone(ep.client_hello_sni(build_hello([(1, b"not-a-host-name")])))
        for name, hello in {
            "two host names": build_hello([(0, b"a.example.com"), (0, b"b.example.com")]),
            "non-ascii": build_hello([(0, "é.example.com".encode())]),
        }.items():
            with self.subTest(name), self.assertRaises(ep.HelloError) as caught:
                ep.client_hello_sni(hello)
            self.assertEqual(caught.exception.reason, "sni_mismatch")
        dup = b"\x00\x0a\x00\x00" * 2  # The same extension twice.
        for name, hello in {
            "server hello": b"\x02" + build_hello([(0, b"a.example.com")])[1:],
            "duplicate extension": build_hello([(0, b"a.example.com")], extra_extensions=dup),
            "truncated": build_hello([(0, b"a.example.com")])[:-3],
            "bad list length": build_hello([(0, b"a.example.com")]).replace(b"\x00\x10\x00", b"\x00\x11\x00", 1),
        }.items():
            with self.subTest(name), self.assertRaises(ep.HelloError) as caught:
                ep.client_hello_sni(hello)
            self.assertEqual(caught.exception.reason, "not_tls")

    def test_not_tls(self):
        for name, data in {
            "plain http": b"GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n",
            "application data record": b"\x17\x03\x03\x00\x05hello",
            "ssl2-ish": b"\x80\x2e\x01\x03\x01" + b"\x00" * 46,
            "zero-length record": b"\x16\x03\x01\x00\x00",
            "huge record": b"\x16\x03\x01\xff\xff" + b"\x00" * 10,
            "huge hello": records(b"\x01\x7f\xff\xff" + b"\x00" * 100),
        }.items():
            with self.subTest(name), self.assertRaises(ep.HelloError):
                read_hello(data)
        with self.assertRaises(asyncio.IncompleteReadError):
            read_hello(records(build_hello([(0, b"a.example.com")]))[:-5])


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "key")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, text: str) -> None:
        with open(self.path, "w") as handle:
            handle.write(text)

    def test_lines_comments_and_whitespace(self):
        self.write("# rotation 2026-10\n  " + "a" * 32 + "  \n\n" + "b" * 40 + "\n")
        self.assertEqual(ep.load_keys(self.path), (b"a" * 32, b"b" * 40))

    def test_refuses_empty_or_short(self):
        for text in ("", "\n# only a comment\n", "short\n", "a" * 32 + "\nshort\n"):
            self.write(text)
            with self.subTest(text=text[:10]), self.assertRaises(ValueError):
                ep.load_keys(self.path)

    def test_reload_keeps_old_keys_on_failure(self):
        self.write("a" * 32)
        proxy = ep.EgressProxy(ep.Config(key_file=self.path), ep.load_keys(self.path))
        self.write("b" * 32 + "\n")
        self.assertTrue(proxy.reload_keys())
        self.assertEqual(proxy.keys, (b"b" * 32,))
        os.unlink(self.path)
        self.assertFalse(proxy.reload_keys())
        self.assertEqual(proxy.keys, (b"b" * 32,))


class ConfigTests(unittest.TestCase):
    def test_env(self):
        config = ep.Config.from_env({"EGRESS_LISTEN": "127.0.0.1:9000", "EGRESS_IDLE_TIMEOUT": "30",
                                     "EGRESS_MAX_CONNECTIONS_PER_RUN": "8", "EGRESS_KEY_FILE": "/k"})
        self.assertEqual((config.listen_host, config.listen_port, config.idle_timeout,
                          config.max_connections_per_run, config.key_file), ("127.0.0.1", 9000, 30.0, 8, "/k"))
        self.assertEqual(ep.Config.from_env({}).listen_port, 3128)
        with self.assertRaises(ValueError):
            ep.Config.from_env({"EGRESS_IDLE_TIMEOUT": "0"})


class AuthorizeTests(unittest.TestCase):
    """The request-head checks, in the order the proxy applies them."""

    def setUp(self):
        self.proxy = ep.EgressProxy(ep.Config(), [KEY], clock=lambda: NOW)
        self.token = ep.mint_token("run-1", ["api.example.com", "*.example.net", "*.run.app", "*.googleapis.com",
                                             "metadata.google.internal", "studio.example.com"], NOW + 60, KEY)

    def head(self, request_line: str, auth: str | None = "default", extra: str = "") -> bytes:
        lines = [request_line, "Host: x"]
        if auth == "default":
            lines.append("Proxy-Authorization: " + basic(self.token))
        elif auth:
            lines.append("Proxy-Authorization: " + auth)
        return ("\r\n".join(lines) + "\r\n" + extra + "\r\n").encode()

    def refused(self, head: bytes) -> tuple[int, str]:
        with self.assertRaises(ep.Refused) as caught:
            self.proxy.authorize(head)
        return caught.exception.status, caught.exception.reason

    def test_allowed(self):
        grant, host = self.proxy.authorize(self.head("CONNECT API.example.com:443 HTTP/1.1"))
        self.assertEqual((grant.run, host), ("run-1", "api.example.com"))
        _, host = self.proxy.authorize(self.head("CONNECT a.b.example.net:443 HTTP/1.0"))
        self.assertEqual(host, "a.b.example.net")
        # The host's own name and signed-URL storage stay allowed when the token names them.
        for name in ("studio.example.com", "storage.googleapis.com"):
            self.assertEqual(self.proxy.authorize(self.head(f"CONNECT {name}:443 HTTP/1.1"))[1], name)

    def test_refusals(self):
        cases = {
            "GET http://api.example.com/ HTTP/1.1": (405, "plain_http"),
            "POST http://api.example.com/ HTTP/1.1": (405, "plain_http"),
            "BREW api.example.com:443 HTTP/1.1": (405, "method"),
            "CONNECT api.example.com:443": (400, "bad_request"),
            "CONNECT api.example.com HTTP/1.1": (400, "bad_target"),
            "CONNECT api.example.com:80 HTTP/1.1": (403, "port"),
            "CONNECT api.example.com:8443 HTTP/1.1": (403, "port"),
            "CONNECT 93.184.215.14:443 HTTP/1.1": (403, "ip_literal"),
            "CONNECT [2606:2800:21f:cb07:6820:80da:af6b:8b2c]:443 HTTP/1.1": (403, "ip_literal"),
            "CONNECT 2130706433:443 HTTP/1.1": (403, "ip_literal"),
            "CONNECT localhost:443 HTTP/1.1": (403, "bad_host"),
            "CONNECT example.net:443 HTTP/1.1": (403, "host_not_allowed"),
            "CONNECT evil.com:443 HTTP/1.1": (403, "host_not_allowed"),
            "CONNECT service-abc.example-region.run.app:443 HTTP/1.1": (403, "host_denied"),
            "CONNECT compute.googleapis.com:443 HTTP/1.1": (403, "host_denied"),
            "CONNECT metadata.google.internal:443 HTTP/1.1": (403, "host_denied"),
            "CONNECT metadata.example.net:443 HTTP/1.1": (403, "host_denied"),
        }
        for line, expected in cases.items():
            with self.subTest(line):
                self.assertEqual(self.refused(self.head(line)), expected)

    def test_auth_refusals(self):
        line = "CONNECT api.example.com:443 HTTP/1.1"
        self.assertEqual(self.refused(self.head(line, auth=None)), (407, "auth_missing"))
        self.assertEqual(self.refused(self.head(line, extra="Proxy-Authorization: " + basic(self.token) + "\r\n")),
                         (407, "auth_duplicate"))
        other = ep.mint_token("run-1", ["api.example.com"], NOW + 60, b"z" * 32)
        self.assertEqual(self.refused(self.head(line, auth=basic(other))), (407, "token_bad_signature"))
        old = ep.mint_token("run-1", ["api.example.com"], NOW, KEY)
        self.assertEqual(self.refused(self.head(line, auth=basic(old))), (407, "token_expired"))
        # Auth comes before the port and host checks: no token, nothing learned.
        self.assertEqual(self.refused(self.head("CONNECT 10.0.0.1:22 HTTP/1.1", auth=None))[0], 407)


if __name__ == "__main__":
    unittest.main()
