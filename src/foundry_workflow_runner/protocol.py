"""The runner's side of the runner protocol (docs/PROTOCOL.md), and signed-URL transfers.

Every request goes to the run's own URL (``STUDIO_RUN_URL``) with its Bearer token, through the egress proxy
(``HTTPS_PROXY``) when one is set. Transient failures (connection errors, 429 and 5xx) are retried with capped,
jittered exponential backoff; refusals (other 4xx) are not. Errors never include a URL, header or body: signed
URLs and tokens are credentials.
"""

import base64
import http.client
import ipaddress
import json
import os
import random
import ssl
import time
from urllib.parse import unquote, urlsplit

LOOPBACK = ("127.0.0.1", "localhost", "::1")
JSON_LIMIT = 4 * 1024 * 1024
DOWNLOAD_LIMIT = 2 * 1024 * 1024 * 1024


class ProtocolError(Exception):
    """A value-free failure: ``status`` is the HTTP status when the host answered."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class _Proxy:
    def __init__(self, host, port, authorization):
        self.host, self.port, self.authorization = host, port, authorization


def _proxy_from(environ):
    raw = environ.get("HTTPS_PROXY") or environ.get("https_proxy") or ""
    if not raw:
        return None
    parts = urlsplit(raw if "://" in raw else "http://" + raw)
    if parts.scheme != "http" or not parts.hostname:
        raise ProtocolError("HTTPS_PROXY must be an http:// proxy address.")
    authorization = None
    if parts.username is not None:
        pair = f"{unquote(parts.username)}:{unquote(parts.password or '')}".encode()
        authorization = "Basic " + base64.b64encode(pair).decode("ascii")
    return _Proxy(parts.hostname, parts.port or 3128, authorization)


def _bypass(host, environ):
    if host in LOOPBACK:
        return True
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        pass
    for entry in (environ.get("NO_PROXY") or environ.get("no_proxy") or "").split(","):
        entry = entry.strip().lower().lstrip(".")
        if entry == "*" or (entry and (host == entry or host.endswith("." + entry))):
            return True
    return False


def check_url(url, *, what="address"):
    """https anywhere, http only to this computer (local dev and tests)."""
    if not isinstance(url, str) or len(url) > 16384 or not url.isascii() or not url.isprintable():
        raise ProtocolError(f"The host sent an unusable {what}.")
    parts = urlsplit(url)
    if not parts.hostname or parts.fragment or (parts.scheme != "https" and not (
            parts.scheme == "http" and parts.hostname in LOOPBACK)):
        raise ProtocolError(f"The host sent an unusable {what}.")
    return parts


class Transport:
    """One HTTP(S) exchange per call, via the proxy when set, with retries."""

    def __init__(self, *, environ=None, timeout=30, sleep=time.sleep, retries=6):
        self.environ = dict(os.environ if environ is None else environ)
        self.proxy = _proxy_from(self.environ)
        self.timeout, self.sleep, self.retries = timeout, sleep, retries

    def _connection(self, parts):
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme == "http":
            return http.client.HTTPConnection(parts.hostname, port, timeout=self.timeout)
        context = ssl.create_default_context()
        if self.proxy is not None and not _bypass(parts.hostname, self.environ):
            connection = http.client.HTTPSConnection(self.proxy.host, self.proxy.port, timeout=self.timeout,
                                                     context=context)
            headers = {"Proxy-Authorization": self.proxy.authorization} if self.proxy.authorization else None
            connection.set_tunnel(parts.hostname, port, headers=headers)
            return connection
        return http.client.HTTPSConnection(parts.hostname, port, timeout=self.timeout, context=context)

    def _backoff(self, attempt):
        self.sleep(min(30.0, 0.5 * (2 ** attempt)) * random.uniform(0.5, 1.0))

    def exchange(self, method, url, *, headers=None, body=None, body_path=None, sink=None, limit=JSON_LIMIT,
                 what="request", retries=None):
        """Returns ``(status, bytes)`` (bytes empty when ``sink`` received them). Retries transient failures;
        a final transient failure raises ProtocolError (status = the last HTTP status, if any)."""
        parts = check_url(url, what=what)
        target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
        attempts = self.retries if retries is None else retries
        last_status = None
        for attempt in range(attempts):
            connection = None
            try:
                connection = self._connection(parts)
                send_headers = dict(headers or {})
                if body_path is not None:
                    send_headers["Content-Length"] = str(os.path.getsize(body_path))
                    with open(body_path, "rb") as handle:
                        connection.request(method, target, body=handle, headers=send_headers)
                        response = connection.getresponse()
                else:
                    if body is not None:
                        send_headers["Content-Length"] = str(len(body))
                    connection.request(method, target, body=body, headers=send_headers)
                    response = connection.getresponse()
                status = response.status
                if status == 429 or (500 <= status <= 599 and status != 501):
                    last_status = status
                    response.read(65536)
                    if attempt + 1 < attempts:
                        self._backoff(attempt)
                    continue
                if sink is not None and 200 <= status < 300:
                    total = 0
                    while True:
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > limit:
                            raise ProtocolError(f"The {what} was too large.")
                        sink.write(chunk)
                    return status, b""
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise ProtocolError(f"The {what} was too large.")
                return status, data
            except (OSError, http.client.HTTPException):
                if sink is not None:
                    sink.seek(0)
                    sink.truncate()
                if attempt + 1 < attempts:
                    self._backoff(attempt)
            finally:
                if connection is not None:
                    try:
                        connection.close()
                    except (OSError, http.client.HTTPException):
                        pass
        message = f"The {what} failed" + (f" (HTTP {last_status})." if last_status else " (no connection).")
        raise ProtocolError(message, status=last_status)

    def download(self, url, path, *, what="download", missing_ok=False):
        """GET a signed URL into ``path``. Returns False when ``missing_ok`` and the object doesn't exist."""
        with open(path, "wb") as handle:
            status, _ = self.exchange("GET", url, sink=handle, limit=DOWNLOAD_LIMIT, what=what)
        if missing_ok and status == 404:
            os.unlink(path)
            return False
        if not 200 <= status < 300:
            raise ProtocolError(f"The {what} failed (HTTP {status}).", status=status)
        return True

    def upload(self, url, path, *, content_type="application/gzip", headers=None, what="upload"):
        """PUT a file to a signed URL with exactly the headers the host signed (``Content-Type`` defaults to
        gzip only when they don't name one)."""
        sent = {} if any(str(name).lower() == "content-type" for name in (headers or {})) else \
            {"Content-Type": content_type}
        for name, value in (headers or {}).items():
            if isinstance(name, str) and isinstance(value, str) and name.lower() not in (
                    "host", "content-length", "authorization", "proxy-authorization", "transfer-encoding"):
                sent[name] = value
        status, _ = self.exchange("PUT", url, headers=sent, body_path=path, what=what)
        if not 200 <= status < 300:
            raise ProtocolError(f"The {what} failed (HTTP {status}).", status=status)


class RunClient:
    """``STUDIO_RUN_URL`` + ``STUDIO_RUN_TOKEN``: start, events, heartbeat, approvals, finish."""

    def __init__(self, run_url, token, *, transport=None):
        parts = check_url(run_url, what="run address")
        if parts.query or not parts.path.endswith("/"):
            raise ProtocolError("STUDIO_RUN_URL must be the run's address, ending in /.")
        if not isinstance(token, str) or not token or len(token) > 4096 or not token.isprintable() or " " in token:
            raise ProtocolError("STUDIO_RUN_TOKEN is missing or malformed.")
        self.url, self._token = run_url, token
        self.transport = transport or Transport()

    @property
    def run_id(self):
        return [part for part in urlsplit(self.url).path.split("/") if part][-1]

    def call(self, method, name, payload=None, *, retries=None, accept=()):
        """JSON call to ``<run url><name>``; returns ``(status, value)``. Refusals other than ``accept`` raise."""
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode()
        status, data = self.transport.exchange(method, self.url + name, headers=headers, body=body,
                                               what=f"host {name.split('/')[0]} call", retries=retries)
        if not 200 <= status < 300 and status not in accept:
            raise ProtocolError(f"The host refused the {name.split('/')[0]} call (HTTP {status}).", status=status)
        try:
            value = json.loads(data.decode("utf-8")) if data.strip() else {}
        except (ValueError, UnicodeError):
            raise ProtocolError(f"The host's answer to the {name.split('/')[0]} call wasn't JSON.", status=status)
        return status, value

    def start(self, runner_version):
        status, value = self.call("POST", "start/", {"runner_version": runner_version}, accept=(409,))
        if status == 409:
            raise ProtocolError("The host already started this attempt of the run.", status=409)
        if not isinstance(value, dict) or value.get("mode") not in ("run", "build"):
            raise ProtocolError("The host's start answer had no mode.")
        return value

    def events(self, events, *, retries=None):
        self.call("POST", "events/", {"events": events}, retries=retries)

    def heartbeat(self):
        _, value = self.call("POST", "heartbeat/", {}, retries=3)
        return bool(isinstance(value, dict) and value.get("cancel"))

    def request_approval(self, tool, input_summary, input_sha256):
        _, value = self.call("POST", "approvals/", {"tool": tool, "input_summary": input_summary,
                                                    "input_sha256": input_sha256})
        approval = value.get("approval_id") if isinstance(value, dict) else None
        if not isinstance(approval, (str, int)) or not str(approval).replace("-", "").replace("_", "").isalnum():
            raise ProtocolError("The host's approval answer had no approval id.")
        return str(approval)

    def approval_state(self, approval_id):
        _, value = self.call("GET", f"approvals/{approval_id}/", retries=3)
        state = value.get("state") if isinstance(value, dict) else None
        return state if state in ("pending", "approved", "denied", "expired") else "pending"

    def upload_url(self, kind, size, sha256, md5):
        """``upload-url/``: a fresh signed PUT for this run's ``state`` or ``bundle``, bound to its size and MD5
        (base64), asked for just before it's used. The PUT sends exactly the headers it returns."""
        _, value = self.call("POST", "upload-url/", {"kind": kind, "size": size, "sha256": sha256, "md5": md5})
        if not isinstance(value, dict) or not isinstance(value.get("url"), str):
            raise ProtocolError("The host's upload-url answer had no address.")
        headers = value.get("headers") if isinstance(value.get("headers"), dict) else {}
        return value["url"], {str(k): str(v) for k, v in headers.items()}

    def finish(self, payload):
        self.call("POST", "finish/", payload, retries=10)
