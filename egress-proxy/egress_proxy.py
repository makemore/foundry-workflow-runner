"""The workflow egress proxy: an HTTPS-only CONNECT proxy for workflow runner jobs.

Tokens and policy: docs/PROTOCOL.md ("Egress tokens") and docs/SECURITY.md ("Egress").
Python standard library only.

Every runner job's traffic leaves its VPC only through this proxy (the runner subnet's firewall
denies all other egress). A request is let through only when all of these hold:

1. It is ``CONNECT host:443``. Anything else (plain HTTP, other methods, other ports) is refused.
2. It carries ``Proxy-Authorization: Basic base64("run:" + token)`` where ``token`` is
   ``base64url(payload) + "." + base64url(HMAC-SHA256(key, payload_segment))``:

   - ``payload`` is the UTF-8 JSON object ``{"r": run_id, "h": [host rules], "x": exp_unix}``.
   - ``payload_segment`` is the first part exactly as sent (ASCII); the MAC is over those bytes,
     so the JSON's spacing and key order don't matter to the proxy.
   - base64url is RFC 4648 section 5 without ``=`` padding (padding is tolerated on input).
   - ``key`` is the UTF-8 bytes of ``WORKFLOW_EGRESS_KEY`` with surrounding whitespace stripped.
   - The MAC is compared in constant time against every loaded key; ``x`` must be later than now.

3. The host is a DNS name (never an IP literal, in any notation) that matches a rule in ``h``:
   the exact name, or ``*.suffix`` for any name ending in ``.suffix`` (not ``suffix`` itself).
   Names that lead to Google's own front ends or internal names are refused even when the token
   allows them (``DENIED_SUFFIXES``: Cloud Run, Google APIs except exactly
   ``storage.googleapis.com``, App Engine, Cloud Functions, googleusercontent, ``.goog``,
   ``.internal``, ``.local``, ``localhost``, and any name whose first label starts with
   ``metadata``). Run the proxy in a network (and cloud project) of its own, so the host's own services
   treat it as external; this list is defence in depth on top of that.
4. Every address the name resolves to is public: no private, loopback, link-local (so no
   metadata server), CGNAT, multicast, reserved or unspecified address, including IPv4 embedded
   in IPv6. The proxy then connects to an address it checked (never resolving again), so DNS
   rebinding can't swap in another one.
5. The run is under its connection cap and the proxy under its global cap.
6. The client's first bytes in the tunnel are a TLS ClientHello whose SNI is the CONNECT host
   (case-insensitive). No SNI, another name, or anything that isn't a ClientHello closes the
   tunnel before a byte reaches the upstream: no SNI-based domain fronting (ECH, whose outer SNI
   is another name, is refused the same way). A Host header *inside* TLS can't be seen here; that
   residual is in docs/SECURITY.md.

Connections end when idle too long, at a total lifetime limit, or when the token expires,
whichever comes first. Logs are one JSON object per line on stdout and never contain a token,
header or byte of traffic: run id, host, decision, reason, status and byte counts only.

Keys are read from a file (``EGRESS_KEY_FILE``; one key per non-empty line, so a rotation can
hold the new and the old key at once) and re-read on SIGHUP. With no usable key the proxy does
not start; a failed reload keeps the keys it has.

Subcommands (``python egress_proxy.py <command>``): ``serve`` (default), ``mint`` (a token for a
smoke test, key on stdin) and ``fetch-key`` (the VM's one-shot copy of the key from Secret
Manager into the file the proxy reads; the proxy itself never talks to the metadata server).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import dataclasses
import hashlib
import hmac
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time
import urllib.request
from collections.abc import Awaitable, Callable, Iterable, Sequence

MAX_HEAD_BYTES = 16 * 1024
MAX_TOKEN_CHARS = 8192
MAX_RULES = 256
MAX_RUN_ID_CHARS = 128
MIN_KEY_BYTES = 32
ALLOWED_PORT = 443
BUFFER = 64 * 1024

_B64URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
# Dotted forms inet_aton() would read as an address: decimal, octal or hex parts (127.1, 0x7f.1,
# 2130706433, 017700000001). A real DNS name never looks like this.
_NUMERIC_HOST = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)(?:\.(?:0x[0-9a-f]*|[0-9]+)){0,3}")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
# Refused whatever the token says (see the module docstring, rule 3).
DENIED_SUFFIXES = ("run.app", "googleapis.com", "googleusercontent.com", "goog", "internal", "local",
                   "localhost", "cloudfunctions.net", "appspot.com")
DENIED_EXCEPTIONS = frozenset({"storage.googleapis.com"})  # Signed URLs (path style only).
MAX_CLIENT_HELLO = 64 * 1024
_EXTRA_DENIED = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",  # "this network"
        "100.64.0.0/10",  # CGNAT shared space
        "192.0.0.0/24",  # IETF protocol assignments
        "198.18.0.0/15",  # benchmarking
        "169.254.0.0/16",  # link-local, incl. 169.254.169.254 (metadata)
        "fd00:ec2::/32",  # AWS's IPv6 metadata (unique-local anyway)
    )
)


# --- Tokens ------------------------------------------------------------------


class TokenError(Exception):
    """A token that grants nothing. ``reason`` is a short, value-free code for the logs."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class Grant:
    run: str
    rules: "HostRules"
    expires: int


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not _B64URL.fullmatch(text):
        raise TokenError("malformed")
    stripped = text.rstrip("=")
    try:
        return base64.urlsafe_b64decode(stripped + "=" * (-len(stripped) % 4))
    except (binascii.Error, ValueError):
        raise TokenError("malformed") from None


def sign(payload_segment: str, key: bytes) -> str:
    return b64url_encode(hmac.new(key, payload_segment.encode("ascii"), hashlib.sha256).digest())


def mint_token(run_id: str, hosts: Sequence[str], expires: int, key: bytes) -> str:
    """The token a host hands a runner (a host may have its own implementation; this one is for tests
    and smoke runs). Compact JSON, keys in the order r, h, x."""
    payload = json.dumps({"r": run_id, "h": list(hosts), "x": int(expires)}, separators=(",", ":"))
    segment = b64url_encode(payload.encode("utf-8"))
    return segment + "." + sign(segment, key)


def verify_token(token: str, keys: Sequence[bytes], now: float) -> Grant:
    if not keys:
        raise TokenError("no_key")
    if len(token) > MAX_TOKEN_CHARS or token.count(".") != 1:
        raise TokenError("malformed")
    segment, _, mac_text = token.partition(".")
    mac = b64url_decode(mac_text)
    if not segment or len(mac) != hashlib.sha256().digest_size:
        raise TokenError("malformed")
    if not _B64URL.fullmatch(segment):
        raise TokenError("malformed")
    message = segment.encode("ascii")
    matched = False
    for key in keys:  # Every key is tried, so timing doesn't tell which one (if any) matched.
        expected = hmac.new(key, message, hashlib.sha256).digest()
        matched |= hmac.compare_digest(expected, mac)
    if not matched:
        raise TokenError("bad_signature")
    try:
        claims = json.loads(b64url_decode(segment).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise TokenError("malformed") from None
    if not isinstance(claims, dict):
        raise TokenError("malformed")
    run, hosts, expires = claims.get("r"), claims.get("h"), claims.get("x")
    if isinstance(run, bool) or not isinstance(run, (str, int)) or not str(run) or len(str(run)) > MAX_RUN_ID_CHARS:
        raise TokenError("malformed")
    if not isinstance(hosts, list) or len(hosts) > MAX_RULES or not all(isinstance(h, str) for h in hosts):
        raise TokenError("malformed")
    if isinstance(expires, bool) or not isinstance(expires, int):
        raise TokenError("malformed")
    if now >= expires:
        raise TokenError("expired")
    return Grant(run=str(run), rules=HostRules(hosts), expires=expires)


def parse_proxy_authorization(value: str | None) -> str:
    """The token from ``Basic base64("run:" + token)``."""
    if not value:
        raise TokenError("missing")
    scheme, _, credentials = value.strip().partition(" ")
    if scheme.lower() != "basic" or not credentials.strip():
        raise TokenError("malformed")
    try:
        decoded = base64.b64decode(credentials.strip(), validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        raise TokenError("malformed") from None
    user, sep, token = decoded.partition(":")
    if not sep or user != "run" or not token:
        raise TokenError("malformed")
    return token


# --- Hosts and addresses -----------------------------------------------------


def is_ip_literal(host: str) -> bool:
    text = host.strip().lower().rstrip(".")
    if text.startswith("[") or ":" in text:
        return True
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        pass
    return bool(_NUMERIC_HOST.fullmatch(text))


def normalize_host(host: str) -> str | None:
    """A lower-case DNS name with at least two labels, or None (IP literals included)."""
    text = host.strip().lower()
    if text.endswith("."):
        text = text[:-1]
    if not text or len(text) > 253 or is_ip_literal(text):
        return None
    labels = text.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return text


class HostRules:
    """Exact names and ``*.suffix`` wildcards. Invalid rules (IP literals, ``*``, ``*.com``,
    anything that isn't a DNS name) are dropped: they match nothing."""

    def __init__(self, rules: Iterable[str]):
        exact: set[str] = set()
        suffixes: set[str] = set()
        for rule in rules:
            if rule.startswith("*."):
                suffix = normalize_host(rule[2:])
                if suffix:
                    suffixes.add(suffix)
            else:
                name = normalize_host(rule)
                if name:
                    exact.add(name)
        self.exact = frozenset(exact)
        self.suffixes = tuple(sorted(suffixes))

    def allows(self, host: str) -> bool:
        return host in self.exact or any(host.endswith("." + suffix) for suffix in self.suffixes)


def address_allowed(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return address_allowed(str(ip.ipv4_mapped))
        if ip.sixtofour is not None or ip.teredo is not None or ip in _NAT64 or ip in _NAT64_LOCAL:
            return False  # Embedded IPv4 we'd have to trust a translator with.
        if ip.is_site_local:
            return False
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            or ip.is_unspecified or not ip.is_global):
        return False
    return not any(ip.version == net.version and ip in net for net in _EXTRA_DENIED)


def host_denied(host: str) -> bool:
    """True for names no token can open (``host`` already normalised)."""
    if host in DENIED_EXCEPTIONS:
        return False
    if host.split(".", 1)[0].startswith("metadata"):
        return True
    return any(host == suffix or host.endswith("." + suffix) for suffix in DENIED_SUFFIXES)


# --- TLS ClientHello ---------------------------------------------------------


class HelloError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def client_hello_sni(handshake: bytes) -> str | None:
    """The server_name (host_name) from a ClientHello handshake message (type, length, body), or
    None when it has none. HelloError when the message isn't a well-formed ClientHello or names
    more than one host."""
    if len(handshake) < 4 or handshake[0] != 1:
        raise HelloError("not_tls")
    body = handshake[4:4 + int.from_bytes(handshake[1:4], "big")]
    pos = 2 + 32  # legacy_version, random

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(body):
            raise HelloError("not_tls")
        chunk = body[pos:pos + n]
        pos += n
        return chunk

    take(take(1)[0])  # session id
    take(int.from_bytes(take(2), "big"))  # cipher suites
    take(take(1)[0])  # compression methods
    if pos == len(body):
        return None  # No extensions at all.
    extensions = take(int.from_bytes(take(2), "big"))
    names: list[str] = []
    seen: set[int] = set()
    i = 0
    while i < len(extensions):
        if i + 4 > len(extensions):
            raise HelloError("not_tls")
        ext_type = int.from_bytes(extensions[i:i + 2], "big")
        ext_len = int.from_bytes(extensions[i + 2:i + 4], "big")
        data = extensions[i + 4:i + 4 + ext_len]
        if len(data) != ext_len or ext_type in seen:
            raise HelloError("not_tls")
        seen.add(ext_type)
        i += 4 + ext_len
        if ext_type != 0:
            continue
        if len(data) < 2 or int.from_bytes(data[:2], "big") != len(data) - 2:
            raise HelloError("not_tls")
        j = 2
        while j < len(data):
            if j + 3 > len(data):
                raise HelloError("not_tls")
            name_type, name_len = data[j], int.from_bytes(data[j + 1:j + 3], "big")
            name = data[j + 3:j + 3 + name_len]
            if len(name) != name_len:
                raise HelloError("not_tls")
            j += 3 + name_len
            if name_type == 0:
                try:
                    names.append(name.decode("ascii"))
                except UnicodeDecodeError:
                    raise HelloError("sni_mismatch") from None
    if len(names) > 1:
        raise HelloError("sni_mismatch")
    return names[0] if names else None


async def read_client_hello(reader: asyncio.StreamReader) -> tuple[bytes, str | None]:
    """Reads TLS records until the whole ClientHello is in (it may span records). Returns the raw
    records, to forward unchanged, and the SNI."""
    raw = bytearray()
    handshake = bytearray()
    while True:
        header = await reader.readexactly(5)
        if header[0] != 22 or header[1] != 3:  # handshake record, TLS major version 3
            raise HelloError("not_tls")
        length = int.from_bytes(header[3:5], "big")
        if length == 0 or length > 16384 + 2048:
            raise HelloError("not_tls")
        fragment = await reader.readexactly(length)
        raw += header + fragment
        handshake += fragment
        if len(raw) > MAX_CLIENT_HELLO:
            raise HelloError("not_tls")
        if len(handshake) >= 4:
            if handshake[0] != 1:
                raise HelloError("not_tls")
            needed = 4 + int.from_bytes(handshake[1:4], "big")
            if needed > MAX_CLIENT_HELLO:
                raise HelloError("not_tls")
            if len(handshake) >= needed:
                return bytes(raw), client_hello_sni(bytes(handshake[:needed]))


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    addresses: list[str] = []
    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in addresses:
            addresses.append(sockaddr[0])
    # IPv4 first: the proxy's VM has no IPv6 route (and a first IPv6 answer would only time out).
    return sorted(addresses, key=lambda a: ":" in a)


# --- Keys --------------------------------------------------------------------


def load_keys(path: str) -> tuple[bytes, ...]:
    with open(path, "rb") as handle:
        return parse_keys(handle.read(64 * 1024))


def parse_keys(data: bytes) -> tuple[bytes, ...]:
    text = data.decode("utf-8")
    keys = tuple(line.strip().encode("utf-8") for line in text.splitlines()
                 if line.strip() and not line.strip().startswith("#"))
    if not keys:
        raise ValueError("no key in the key file")
    if any(len(key) < MIN_KEY_BYTES for key in keys):
        raise ValueError(f"every key must be at least {MIN_KEY_BYTES} bytes")
    return keys


# --- The proxy ---------------------------------------------------------------


@dataclasses.dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 3128
    key_file: str = "/run/secrets/workflow-egress-key"
    handshake_timeout: float = 10.0
    connect_timeout: float = 10.0
    idle_timeout: float = 300.0
    max_connection_seconds: float = 3900.0  # 65 minutes: a 60-minute run plus its start.
    max_connections_per_run: int = 64
    max_connections: int = 2048

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        config = cls()
        listen = env.get("EGRESS_LISTEN", "")
        if listen:
            host, _, port = listen.rpartition(":")
            config.listen_host, config.listen_port = host or "0.0.0.0", int(port)
        config.key_file = env.get("EGRESS_KEY_FILE", config.key_file)
        for name, attr, kind in (
            ("EGRESS_HANDSHAKE_TIMEOUT", "handshake_timeout", float),
            ("EGRESS_CONNECT_TIMEOUT", "connect_timeout", float),
            ("EGRESS_IDLE_TIMEOUT", "idle_timeout", float),
            ("EGRESS_MAX_CONNECTION_SECONDS", "max_connection_seconds", float),
            ("EGRESS_MAX_CONNECTIONS_PER_RUN", "max_connections_per_run", int),
            ("EGRESS_MAX_CONNECTIONS", "max_connections", int),
        ):
            if env.get(name):
                value = kind(env[name])
                if value <= 0:
                    raise ValueError(f"{name} must be positive")
                setattr(config, attr, value)
        return config


class Refused(Exception):
    def __init__(self, status: int, reason: str, *, run: str | None = None, host: str | None = None):
        super().__init__(reason)
        self.status, self.reason, self.run, self.host = status, reason, run, host


_STATUS_TEXT = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed",
                407: "Proxy Authentication Required", 429: "Too Many Requests",
                431: "Request Header Fields Too Large", 502: "Bad Gateway", 504: "Gateway Timeout"}


def log(event: str, **fields) -> None:
    record = {"ts": round(time.time(), 3), "event": event}
    record.update({k: v for k, v in fields.items() if v is not None})
    sys.stdout.write(json.dumps(record, separators=(",", ":")) + "\n")
    sys.stdout.flush()


class EgressProxy:
    def __init__(self, config: Config, keys: Sequence[bytes], *, resolver: Resolver = system_resolver,
                 clock: Callable[[], float] = time.time, _test_allowed_networks: Sequence[str] = ()):
        self.config = config
        self.keys = tuple(keys)
        self.resolver = resolver
        self.clock = clock
        # Tests only (the e2e test's echo server is on loopback). Not reachable from the
        # environment or the command line, so a deployed proxy can never widen its policy.
        self._test_allowed = tuple(ipaddress.ip_network(net) for net in _test_allowed_networks)
        self.per_run: dict[str, int] = {}
        self.active = 0
        self.server: asyncio.base_events.Server | None = None
        self._tasks: set[asyncio.Task] = set()

    # Keys -------------------------------------------------------------------

    def reload_keys(self) -> bool:
        try:
            self.keys = load_keys(self.config.key_file)
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            log("keys", ok=False, reason=type(exc).__name__, kept=len(self.keys))
            return False
        log("keys", ok=True, count=len(self.keys))
        return True

    # Policy -----------------------------------------------------------------

    def _address_allowed(self, address: str) -> bool:
        if self._test_allowed:
            ip = ipaddress.ip_address(address)
            if any(ip.version == net.version and ip in net for net in self._test_allowed):
                return True
        return address_allowed(address)

    def authorize(self, head: bytes) -> tuple[Grant, str]:
        """(grant, host) for a request head, or Refused."""
        try:
            text = head.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 decodes anything
            raise Refused(400, "bad_request") from None
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise Refused(400, "bad_request")
        method, target, _ = parts
        if method != "CONNECT":
            raise Refused(405, "plain_http" if method in {"GET", "POST", "PUT", "HEAD", "DELETE", "PATCH",
                                                          "OPTIONS"} else "method")
        auth_values = [line.split(":", 1)[1] for line in lines[1:]
                       if ":" in line and line.split(":", 1)[0].strip().lower() == "proxy-authorization"]
        host_text, sep, port_text = target.rpartition(":")
        if not sep or not port_text.isdigit() or not host_text:
            raise Refused(400, "bad_target")
        host = normalize_host(host_text)
        log_host = host or ("ip_literal" if is_ip_literal(host_text.strip("[]")) else None)
        if len(auth_values) != 1:
            raise Refused(407, "auth_missing" if not auth_values else "auth_duplicate", host=log_host)
        try:
            grant = verify_token(parse_proxy_authorization(auth_values[0]), self.keys, self.clock())
        except TokenError as exc:
            raise Refused(407, "token_" + exc.reason, host=log_host) from None
        if int(port_text) != ALLOWED_PORT:
            raise Refused(403, "port", run=grant.run, host=log_host)
        if host is None:
            raise Refused(403, "ip_literal" if log_host == "ip_literal" else "bad_host", run=grant.run,
                          host=log_host)
        if host_denied(host):
            raise Refused(403, "host_denied", run=grant.run, host=host)
        if not grant.rules.allows(host):
            raise Refused(403, "host_not_allowed", run=grant.run, host=host)
        return grant, host

    async def resolve_checked(self, host: str, run: str) -> list[str]:
        try:
            addresses = await asyncio.wait_for(self.resolver(host, ALLOWED_PORT), self.config.connect_timeout)
        except (OSError, asyncio.TimeoutError, UnicodeError):
            raise Refused(502, "dns", run=run, host=host) from None
        if not addresses:
            raise Refused(502, "dns", run=run, host=host)
        # One disallowed answer refuses the name: a mixed answer is how rebinding attacks start.
        if not all(self._address_allowed(address) for address in addresses):
            raise Refused(403, "address_not_public", run=run, host=host)
        return addresses

    # Connections ------------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        started = time.monotonic()
        grant: Grant | None = None
        host: str | None = None
        counted = False
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.config.handshake_timeout)
            except asyncio.LimitOverrunError:
                raise Refused(431, "head_too_large") from None
            except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                log("egress", decision="deny", reason="no_request")
                return
            grant, host = self.authorize(head)
            if self.active >= self.config.max_connections:
                raise Refused(429, "proxy_busy", run=grant.run, host=host)
            if self.per_run.get(grant.run, 0) >= self.config.max_connections_per_run:
                raise Refused(429, "run_connection_cap", run=grant.run, host=host)
            self.active += 1
            self.per_run[grant.run] = self.per_run.get(grant.run, 0) + 1
            counted = True
            addresses = await self.resolve_checked(host, grant.run)
            upstream = await self._connect(addresses, grant.run, host)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            # Nothing reaches the upstream until the client's ClientHello names this host.
            try:
                hello, sni = await asyncio.wait_for(read_client_hello(reader), self.config.handshake_timeout)
                if sni is None:
                    raise HelloError("sni_missing")
                if normalize_host(sni) != host:
                    raise HelloError("sni_mismatch")
            except (HelloError, asyncio.IncompleteReadError, asyncio.TimeoutError) as exc:
                reason = exc.reason if isinstance(exc, HelloError) else (
                    "no_client_hello" if isinstance(exc, asyncio.IncompleteReadError) else "client_hello_timeout")
                log("egress", decision="deny", reason=reason, run=grant.run, host=host)
                await _close(upstream[1])
                return
            log("egress", decision="allow", run=grant.run, host=host)
            upstream[1].write(hello)
            await upstream[1].drain()
            await self._relay(reader, writer, upstream, grant, host, started, sent=len(hello))
        except Refused as refused:
            await self._refuse(writer, refused)
        except (ConnectionError, asyncio.TimeoutError):
            log("egress", decision="deny", reason="client_gone", run=grant.run if grant else None, host=host)
        finally:
            if counted and grant is not None:
                self.active -= 1
                remaining = self.per_run.get(grant.run, 1) - 1
                if remaining > 0:
                    self.per_run[grant.run] = remaining
                else:
                    self.per_run.pop(grant.run, None)
            await _close(writer)

    async def _connect(self, addresses: list[str], run: str, host: str):
        timed_out = False
        for address in addresses[:4]:
            try:
                return await asyncio.wait_for(asyncio.open_connection(address, ALLOWED_PORT, limit=BUFFER),
                                              self.config.connect_timeout)
            except asyncio.TimeoutError:
                timed_out = True
            except OSError:
                pass
        raise Refused(504 if timed_out else 502, "connect_timeout" if timed_out else "connect_failed",
                      run=run, host=host)

    async def _relay(self, reader, writer, upstream, grant: Grant, host: str, started: float, sent: int = 0) -> None:
        up_reader, up_writer = upstream
        counts = {"up": sent, "down": 0}
        last = [time.monotonic()]
        lifetime = min(self.config.max_connection_seconds, max(0.0, grant.expires - self.clock()))
        deadline = started + lifetime

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, direction: str) -> None:
            while True:
                data = await src.read(BUFFER)
                if not data:
                    break
                counts[direction] += len(data)
                last[0] = time.monotonic()
                dst.write(data)
                await dst.drain()
            if dst.can_write_eof():
                try:
                    dst.write_eof()
                except OSError:
                    pass

        async def watchdog() -> str:
            step = max(0.05, min(5.0, self.config.idle_timeout / 4))
            while True:
                now = time.monotonic()
                if now >= deadline:
                    return "lifetime"
                if now - last[0] >= self.config.idle_timeout:
                    return "idle"
                await asyncio.sleep(min(step, max(0.01, deadline - now)))

        pumps = {asyncio.ensure_future(pump(reader, up_writer, "up")),
                 asyncio.ensure_future(pump(up_reader, writer, "down"))}
        guard = asyncio.ensure_future(watchdog())
        end = "closed"
        try:
            pending = set(pumps)
            while pending:
                done, _ = await asyncio.wait(pending | {guard}, return_when=asyncio.FIRST_COMPLETED)
                if guard in done:
                    end = guard.result()
                    break
                for task in done:
                    pending.discard(task)
                    if task.exception() is not None:
                        end = "reset"
                        pending.clear()
                        break
        finally:
            for task in (*pumps, guard):
                task.cancel()
            await asyncio.gather(*pumps, guard, return_exceptions=True)
            await _close(up_writer)
            log("egress", decision="close", run=grant.run, host=host, end=end, bytes_up=counts["up"],
                bytes_down=counts["down"], ms=int((time.monotonic() - started) * 1000))

    async def _refuse(self, writer: asyncio.StreamWriter, refused: Refused) -> None:
        log("egress", decision="deny", reason=refused.reason, status=refused.status, run=refused.run,
            host=refused.host)
        extra = 'Proxy-Authenticate: Basic realm="studio-workflows"\r\n' if refused.status == 407 else ""
        response = (f"HTTP/1.1 {refused.status} {_STATUS_TEXT.get(refused.status, 'Refused')}\r\n{extra}"
                    "Connection: close\r\nContent-Length: 0\r\n\r\n")
        try:
            writer.write(response.encode("ascii"))
            await asyncio.wait_for(writer.drain(), 5)
        except (ConnectionError, asyncio.TimeoutError):
            pass

    # Serving ----------------------------------------------------------------

    async def _on_client(self, reader, writer) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        await self.handle(reader, writer)

    async def start(self) -> asyncio.base_events.Server:
        self.server = await asyncio.start_server(self._on_client, self.config.listen_host,
                                                 self.config.listen_port, limit=MAX_HEAD_BYTES,
                                                 reuse_address=True, backlog=1024)
        return self.server

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 2)
    except (ConnectionError, OSError, asyncio.TimeoutError):
        pass


async def serve(config: Config) -> None:
    keys = load_keys(config.key_file)  # Fails closed: no key, no proxy.
    proxy = EgressProxy(config, keys)
    await proxy.start()
    log("start", port=config.listen_port, keys=len(keys))
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()
    loop.add_signal_handler(signal.SIGHUP, proxy.reload_keys)
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stopped.set)
    await stopped.wait()
    log("stop", active=proxy.active)
    await proxy.stop()


# --- Subcommands -------------------------------------------------------------


def fetch_key(secret_version: str, out_path: str) -> None:
    """Copy a Secret Manager version into ``out_path`` (0400) using the VM's identity. Run once
    per boot and on rotation by the VM (systemd), never by the long-running proxy."""
    metadata = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    request = urllib.request.Request(metadata, headers={"Metadata-Flavor": "Google"})
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed URL.
        access_token = json.load(response)["access_token"]
    url = f"https://secretmanager.googleapis.com/v1/{secret_version}:access"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - fixed host.
        data = base64.b64decode(json.load(response)["payload"]["data"])
    parse_keys(data)  # Refuse to install a key file the proxy would refuse.
    directory = os.path.dirname(out_path) or "."
    temp = os.path.join(directory, f".key.{os.getpid()}")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    os.replace(temp, out_path)
    log("fetch_key", ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="egress_proxy", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="run the proxy (default)")
    mint = sub.add_parser("mint", help="print a proxy URL with a short-lived token (key read from stdin)")
    mint.add_argument("--run", required=True)
    mint.add_argument("--host", action="append", required=True, dest="hosts")
    mint.add_argument("--ttl", type=int, default=900)
    mint.add_argument("--proxy", required=True, help="host:port of the proxy")
    fetch = sub.add_parser("fetch-key", help="copy the key from Secret Manager into a file")
    fetch.add_argument("--secret", required=True, help="projects/<p>/secrets/<name>/versions/<v>")
    fetch.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    if args.command == "mint":
        key = sys.stdin.readline().strip().encode("utf-8")
        if len(key) < MIN_KEY_BYTES:
            print("mint: a key of at least 32 bytes on stdin is required", file=sys.stderr)
            return 2
        token = mint_token(args.run, args.hosts, int(time.time()) + args.ttl, key)
        print(f"http://run:{token}@{args.proxy}")
        return 0
    if args.command == "fetch-key":
        fetch_key(args.secret, args.out)
        return 0
    try:
        asyncio.run(serve(Config.from_env()))
    except (OSError, ValueError) as exc:
        log("start", ok=False, reason=type(exc).__name__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
