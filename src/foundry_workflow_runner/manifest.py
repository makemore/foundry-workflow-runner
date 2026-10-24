"""``studio.yaml``: reading it (a small, strict YAML subset, standard library only) and checking it early.

A host validates manifests too (it is authoritative for its own plan limits and connections); hosts and
clients use these rules with the same wording, so a mistake shows before anything is uploaded. Each message is a fixed
sentence after the key path (``triggers[0].cron: ...``). Unknown keys are errors.

The YAML subset: block mappings and sequences, flow ``[...]`` and ``{...}``, plain, single- and double-quoted
scalars, ``|`` / ``>`` block scalars, comments. Scalars follow YAML 1.2's core schema (``true``/``false``,
``null``/``~``, integers, floats; everything else is text). Anchors, aliases, tags and duplicate keys are errors.
"""

import calendar
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,48}$")
SECRET_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
HOST_RE = re.compile(r"^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
DURATION_RE = re.compile(r"^([1-9][0-9]{0,4})([smh])$")
STATE_RE = re.compile(r"^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*/?$")

TOP_KEYS = {"version", "name", "description", "entry", "model", "triggers", "connections", "google_account",
            "secrets", "egress", "approvals", "limits", "state"}
DEFAULT_TIMEOUT = 30 * 60
MAX_TIMEOUT = 60 * 60
MIN_TIMEOUT = 60
DEFAULT_MAX_TURNS = 50
MAX_TURNS = 500
MAX_CRON_TRIGGERS = 10
# Egress a manifest may never ask for (the proxy refuses them too): Google's and Cloud Run's own
# endpoints, metadata and internal names, and Studio itself (added by Studio automatically).
DENIED_SUFFIXES = ("run.app", "googleapis.com", "googleusercontent.com", "goog", "internal", "local",
                   "cloudfunctions.net", "appspot.com")  # Plus the host's own names (``studio_hosts``).
RESERVED_SECRET_PREFIXES = ("STUDIO_", "ANTHROPIC_", "CLAUDE_")
RESERVED_SECRETS = {"HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "PATH", "HOME"}
MAX_BYTES = 64 * 1024


class ManifestError(ValueError):
    """``errors``: ``"<path>: <sentence>"`` strings, in key order."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# ---------------------------------------------------------------------- YAML subset


class _YAMLError(Exception):
    def __init__(self, line, message):
        super().__init__(f"studio.yaml line {line}: {message}")


_INT = re.compile(r"^[-+]?[0-9]+$|^0o[0-7]+$|^0x[0-9a-fA-F]+$")
_FLOAT = re.compile(r"^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$")


def _plain(text, line):
    text = text.strip()
    if text[:1] in ("&", "*", "!", "|", ">", "@", "`", "%"):
        raise _YAMLError(line, "anchors, aliases, tags and reserved characters aren't supported; quote the value.")
    if text in ("", "~", "null", "Null", "NULL"):
        return None
    if text in ("true", "True", "TRUE"):
        return True
    if text in ("false", "False", "FALSE"):
        return False
    if _INT.match(text):
        return int(text, 0) if text[:2] in ("0o", "0x") else int(text)
    if _FLOAT.match(text) and any(ch.isdigit() for ch in text):
        return float(text)
    if text in (".inf", ".Inf", "-.inf", ".nan", ".NaN"):
        raise _YAMLError(line, "infinite and NaN numbers aren't supported.")
    return text


def _quoted(text, index, line):
    """A quoted scalar starting at ``text[index]``; returns (value, index after it)."""
    quote, out, index = text[index], [], index + 1
    while index < len(text):
        ch = text[index]
        if quote == "'" and ch == "'":
            if text[index + 1:index + 2] == "'":
                out.append("'")
                index += 2
                continue
            return "".join(out), index + 1
        if quote == '"' and ch == "\\":
            escape = text[index + 1:index + 2]
            simple = {"n": "\n", "t": "\t", "\\": "\\", '"': '"', "/": "/", "0": "\0", "r": "\r", " ": " "}
            if escape in simple:
                out.append(simple[escape])
                index += 2
                continue
            if escape in ("u", "x", "U"):
                width = {"x": 2, "u": 4, "U": 8}[escape]
                digits = text[index + 2:index + 2 + width]
                if not re.fullmatch(r"[0-9a-fA-F]{%d}" % width, digits):
                    raise _YAMLError(line, "a \\u escape needs hex digits.")
                out.append(chr(int(digits, 16)))
                index += 2 + width
                continue
            raise _YAMLError(line, "unknown escape in a double-quoted string.")
        if quote == '"' and ch == '"':
            return "".join(out), index + 1
        out.append(ch)
        index += 1
    raise _YAMLError(line, "a quoted string isn't closed.")


def _flow(text, index, line):
    """A flow value at ``text[index]``: [..], {..}, a quoted or a plain scalar. Returns (value, index)."""
    while index < len(text) and text[index] == " ":
        index += 1
    if index >= len(text):
        return None, index
    ch = text[index]
    if ch in "\"'":
        return _quoted(text, index, line)
    if ch == "[":
        items, index = [], index + 1
        while True:
            while index < len(text) and text[index] == " ":
                index += 1
            if index < len(text) and text[index] == "]":
                return items, index + 1
            value, index = _flow(text, index, line)
            items.append(value)
            while index < len(text) and text[index] == " ":
                index += 1
            if index < len(text) and text[index] == ",":
                index += 1
            elif index < len(text) and text[index] == "]":
                return items, index + 1
            else:
                raise _YAMLError(line, "a [list] isn't closed.")
    if ch == "{":
        mapping, index = {}, index + 1
        while True:
            while index < len(text) and text[index] == " ":
                index += 1
            if index < len(text) and text[index] == "}":
                return mapping, index + 1
            key, index = _flow_key(text, index, line)
            if key in mapping:
                raise _YAMLError(line, f"duplicate key {key}.")
            value, index = _flow(text, index, line)
            mapping[key] = value
            while index < len(text) and text[index] == " ":
                index += 1
            if index < len(text) and text[index] == ",":
                index += 1
            elif index < len(text) and text[index] == "}":
                return mapping, index + 1
            else:
                raise _YAMLError(line, "a {mapping} isn't closed.")
    end = index
    while end < len(text) and text[end] not in ",]}":
        end += 1
    return _plain(text[index:end], line), end


def _flow_key(text, index, line):
    if text[index] in "\"'":
        key, index = _quoted(text, index, line)
    else:
        end = text.find(":", index)
        if end < 0:
            raise _YAMLError(line, "a {mapping} entry needs key: value.")
        key, index = text[index:end].strip(), end
        if not key:
            raise _YAMLError(line, "a {mapping} entry needs a key.")
    while index < len(text) and text[index] == " ":
        index += 1
    if text[index:index + 1] != ":":
        raise _YAMLError(line, "a {mapping} entry needs key: value.")
    return key, index + 1


def _strip_comment(text):
    quote, index = None, 0
    while index < len(text):
        ch = text[index]
        if quote:
            if ch == "\\" and quote == '"':
                index += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'" and (index == 0 or text[index - 1] in " [{,:-"):
            quote = ch
        elif ch == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
        index += 1
    return text.rstrip()


def _depth(text):
    depth = 0
    quote = None
    for index, ch in enumerate(text):
        if quote:
            if ch == quote and (quote == "'" or text[index - 1] != "\\"):
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
    return depth


class _Lines:
    def __init__(self, source):
        self.raw = source.split("\n")
        self.items = []  # (line number, indent, text)
        number = 0
        while number < len(self.raw):
            text = self.raw[number].rstrip("\r")
            number += 1
            if "\t" in text[:len(text) - len(text.lstrip(" \t"))]:
                raise _YAMLError(number, "indent with spaces, not tabs.")
            stripped = _strip_comment(text)
            if not stripped.strip() or stripped.strip() in ("---", "..."):
                continue
            indent = len(stripped) - len(stripped.lstrip(" "))
            start = number
            while _depth(stripped) > 0 and number < len(self.raw):  # A flow value over several lines.
                stripped += " " + _strip_comment(self.raw[number].rstrip("\r")).strip()
                number += 1
            self.items.append((start, indent, stripped.strip(), number))


def _block_scalar(lines, position, indicator, parent_indent, line):
    """``|`` / ``>`` at items[position-1]; consumes the more-indented raw lines after it."""
    if not re.fullmatch(r"[|>][-+]?", indicator):
        raise _YAMLError(line, "a block scalar is | or > (optionally with - or +).")
    _, _, _, end = lines.items[position - 1]
    raw_index, collected = end, []
    while raw_index < len(lines.raw):
        text = lines.raw[raw_index].rstrip("\r")
        if text.strip() and len(text) - len(text.lstrip(" ")) <= parent_indent:
            break
        collected.append(text)
        raw_index += 1
    while collected and not collected[-1].strip():
        collected.pop()
    width = min((len(text) - len(text.lstrip(" ")) for text in collected if text.strip()), default=0)
    body = [text[width:] for text in collected]
    if indicator[0] == ">":
        value, paragraph = "", []
        for text in body + [""]:
            if text.strip():
                paragraph.append(text.strip())
            else:
                if paragraph:
                    value += " ".join(paragraph) + "\n"
                    paragraph = []
                elif value:
                    value += "\n"
        value = value.rstrip("\n") + "\n" if value else ""
    else:
        value = "\n".join(body) + ("\n" if body else "")
    if indicator.endswith("-"):
        value = value.rstrip("\n")
    while position < len(lines.items) and lines.items[position][0] <= raw_index:
        position += 1
    return value, position


def _split_key(text, line):
    if text[:1] in "\"'":
        key, index = _quoted(text, 0, line)
        rest = text[index:]
        if not re.match(r"^\s*:(\s|$)", rest):
            return None, None  # A quoted scalar, not a key.
        return key, rest.split(":", 1)[1]
    match = re.match(r"^([^:#\[\]{},]+?)\s*:(?:\s+|$)(.*)$", text)
    if not match:
        return None, None
    return match.group(1), match.group(2)


def _value(lines, position, text, indent, line):
    """The value after ``key:`` or ``- `` (``text``), possibly a nested block below. Returns (value, position)."""
    text = text.strip()
    if text.startswith(("|", ">")):
        return _block_scalar(lines, position, text, indent, line)
    if text:
        value, end = _flow(text, 0, line)
        if text[end:].strip():
            raise _YAMLError(line, "unexpected text after the value.")
        return value, position
    if position < len(lines.items) and lines.items[position][1] > indent:
        return _block(lines, position, lines.items[position][1])
    if position < len(lines.items) and lines.items[position][1] == indent and \
            lines.items[position][2].startswith("- "):
        return _block(lines, position, indent)  # A list may sit at its key's indent.
    return None, position


def _block(lines, position, indent):
    first_line, _, text, _ = lines.items[position]
    if text == "-" or text.startswith("- "):
        items = []
        while position < len(lines.items):
            line, this_indent, text, _ = lines.items[position]
            if this_indent < indent:
                break
            if this_indent > indent or not (text == "-" or text.startswith("- ")):
                raise _YAMLError(line, "bad indentation in a list.")
            rest = text[1:].lstrip(" ")
            position += 1
            key, after = _split_key(rest, line) if rest and rest[0] not in "[{" else (None, None)
            if key is not None:
                # "- key: value" starts a mapping whose other keys sit under the key.
                child_indent = this_indent + (len(text) - len(rest))
                lines.items.insert(position, (line, child_indent, rest, lines.items[position - 1][3]))
                value, position = _block(lines, position, child_indent)
            else:
                value, position = _value(lines, position, rest, this_indent, line)
            items.append(value)
        return items, position
    mapping = {}
    while position < len(lines.items):
        line, this_indent, text, _ = lines.items[position]
        if this_indent < indent:
            break
        if this_indent > indent:
            raise _YAMLError(line, "bad indentation.")
        if text.startswith("- "):
            break
        key, rest = _split_key(text, line)
        if key is None:
            raise _YAMLError(line, "expected key: value.")
        if key in mapping:
            raise _YAMLError(line, f"duplicate key {key}.")
        position += 1
        mapping[key], position = _value(lines, position, rest, this_indent, line)
    if not mapping:
        raise _YAMLError(first_line, "expected key: value.")
    return mapping, position


def load(source):
    """Parse studio.yaml text; raises ManifestError with one ``studio.yaml line N: ...`` message."""
    if len(source.encode("utf-8")) > MAX_BYTES:
        raise ManifestError(["studio.yaml: must be at most 64 KB."])
    try:
        lines = _Lines(source.lstrip("﻿"))
        if not lines.items:
            raise ManifestError(["studio.yaml: must be a mapping."])
        if lines.items[0][2].startswith(("[", "{")) and len(lines.items) == 1:
            value, _ = _flow(lines.items[0][2], 0, lines.items[0][0])
            return value
        value, position = _block(lines, 0, lines.items[0][1])
        if position < len(lines.items):
            raise _YAMLError(lines.items[position][0], "bad indentation.")
        return value
    except _YAMLError as error:
        raise ManifestError([str(error)]) from None
    except RecursionError:
        raise ManifestError(["studio.yaml: nested too deeply."]) from None


# ---------------------------------------------------------------------- the rules (as Studio's)


def parse_duration(value):
    """``"30m"`` → 1800. Integers are seconds. None when malformed."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = DURATION_RE.match(value) if isinstance(value, str) else None
    if not match:
        return None
    return int(match.group(1)) * {"s": 1, "m": 60, "h": 3600}[match.group(2)]


def host_denied(host, studio_hosts=()):
    """True for an egress entry that names (or, as a wildcard, covers) a refused host (as Studio's)."""
    name = host[2:] if host.startswith("*.") else host
    if host.startswith("*.") and name.count(".") < 1:
        return True  # "*.com" would cover everything under a public suffix.
    if name.split(".", 1)[0].startswith("metadata"):
        return True
    for suffix in (*DENIED_SUFFIXES, *(item.lower() for item in studio_hosts if item)):
        if name == suffix or name.endswith("." + suffix):
            return True
        if host.startswith("*.") and suffix.endswith("." + name):
            return True  # A wildcard over a refused host ("*.example.com" when the host is studio.example.com).
    return False


def _cron_field(text, low, high):
    values = set()
    for item in text.split(","):
        if not re.fullmatch(r"(?:\*|[0-9]+(?:-[0-9]+)?)(?:/[0-9]+)?", item):
            raise ValueError
        base, slash, step_text = item.partition("/")
        step = int(step_text) if slash else 1
        if step < 1:
            raise ValueError
        if base == "*":
            start, end = low, high
        elif "-" in base:
            start, end = (int(part) for part in base.split("-"))
        else:
            start = int(base)
            end = high if slash else start
        if not low <= start <= end <= high:
            raise ValueError
        values.update(range(start, end + 1, step))
    return values


def cron_valid(expression):
    """The runtime's numeric five-field cron (agent_runtime_core.scheduling), as Studio checks it."""
    try:
        fields = " ".join(expression.split()).split()
        if len(fields) != 5:
            return False
        _cron_field(fields[0], 0, 59)
        _cron_field(fields[1], 0, 23)
        days = _cron_field(fields[2], 1, 31)
        months = _cron_field(fields[3], 1, 12)
        _cron_field(fields[4], 0, 7)
        if (fields[2].startswith("*") or fields[4].startswith("*")) and not any(
                day <= calendar.monthrange(2000, month)[1] for month in months for day in days):
            return False
        return True
    except (TypeError, ValueError, OverflowError, AttributeError):
        return False


def _cron_rule(expression):
    fields = " ".join(expression.split()).split()
    days, weekdays = _cron_field(fields[2], 1, 31), {day % 7 for day in _cron_field(fields[4], 0, 7)}
    return {"minutes": sorted(_cron_field(fields[0], 0, 59)), "hours": sorted(_cron_field(fields[1], 0, 23)),
            "days": days, "months": _cron_field(fields[3], 1, 12), "weekdays": weekdays,
            "star": fields[2].startswith("*") or fields[4].startswith("*")}


def _cron_firings(trigger, start, end, limit):
    """Each UTC instant in (start, end] the trigger fires (the runtime's rules: Vixie day OR, DST gaps
    skipped, fold=0)."""
    from datetime import date, datetime, time as wall_time, timezone

    rule, zone = _cron_rule(trigger["cron"]), ZoneInfo(trigger.get("tz") or "UTC")
    first, last = start.astimezone(zone).date(), end.astimezone(zone).date()
    for ordinal in range(first.toordinal(), last.toordinal() + 2):
        day = date.fromordinal(ordinal)
        dom, dow = day.day in rule["days"], (day.weekday() + 1) % 7 in rule["weekdays"]
        if day.month not in rule["months"] or not (dom and dow if rule["star"] else dom or dow):
            continue
        for hour in rule["hours"]:
            for minute in rule["minutes"]:
                wall = datetime.combine(day, wall_time(hour, minute))
                candidate = wall.replace(tzinfo=zone, fold=0).astimezone(timezone.utc)
                if candidate.astimezone(zone).replace(tzinfo=None) != wall:
                    continue  # A wall time skipped by a DST change.
                if start < candidate <= end:
                    yield candidate
                    limit -= 1
                    if limit <= 0:
                        return


def cron_min_gap_seconds(triggers, *, days=8, limit=5000):
    """The shortest gap between two firings of all these cron triggers together, in UTC across their time
    zones, over ``days`` days from a fixed Monday (as Studio's schedule.min_gap_seconds)."""
    from datetime import datetime, timedelta, timezone

    start = datetime(2026, 1, 5, tzinfo=timezone.utc)
    end = start + timedelta(days=days)
    times = set()
    for trigger in triggers:
        for when in _cron_firings(trigger, start, end, limit - len(times)):
            if when in times:
                return 0
            times.add(when)
        if len(times) >= limit:
            break
    ordered = sorted(times)
    gaps = [(b - a).total_seconds() for a, b in zip(ordered, ordered[1:])]
    return min(gaps) if gaps else float("inf")


def plan_errors(normal, usage):
    """Studio's plan checks the CLI can make early, from the workspace's ``usage`` (same wording)."""
    errors = []
    if not isinstance(usage, dict):
        return errors
    cap = usage.get("max_timeout_seconds")
    if isinstance(cap, int) and cap and normal["limits"]["timeout"] > cap and normal.get("_timeout_set"):
        errors.append(f"limits.timeout: at most {cap // 60}m on this workspace's plan.")
    floor = usage.get("min_cron_seconds")
    crons = [trigger for trigger in normal["triggers"] if "cron" in trigger]
    if isinstance(floor, int) and floor and crons and cron_min_gap_seconds(crons) < floor:
        errors.append(f"triggers: the cron triggers together may fire at most once every {floor // 60} minutes "
                      "on this workspace's plan.")
    return errors


def _str_list(value, path, errors, *, item_re=None, item_message="", limit=50):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        errors.append(f"{path}: must be a list of strings.")
        return []
    if len(value) > limit:
        errors.append(f"{path}: at most {limit} entries.")
    if len(set(value)) != len(value):
        errors.append(f"{path}: entries must be unique.")
    if item_re is not None:
        for index, item in enumerate(value):
            if not item_re.match(item):
                errors.append(f"{path}[{index}]: {item_message}")
    return value


def validate(manifest, *, studio_hosts=()):
    """Raise ManifestError unless ``manifest`` is a valid studio.yaml object; returns ``normalise``'s result.

    ``studio_hosts``: the chosen Studio's host names, refused in ``egress`` like the built-in list. The plan's
    timeout and cron limits and the workspace's model policy are Studio's to check (it says so on deploy)."""
    errors = []
    if not isinstance(manifest, dict):
        raise ManifestError(["studio.yaml: must be a mapping."])
    for key in manifest:
        if key not in TOP_KEYS:
            errors.append(f"{key}: unknown key.")
    if manifest.get("version") != 1 or isinstance(manifest.get("version"), bool):
        errors.append("version: must be 1.")
    name = manifest.get("name")
    if not isinstance(name, str) or not NAME_RE.match(name):
        errors.append("name: must match ^[a-z][a-z0-9-]{1,48}$ (lowercase letters, digits and dashes).")
    description = manifest.get("description", "")
    if not isinstance(description, str) or len(description) > 500:
        errors.append("description: must be text of at most 500 characters.")

    entry = manifest.get("entry")
    if not isinstance(entry, dict):
        errors.append("entry: needs exactly one of claude or command.")
    else:
        for key in entry:
            if key not in ("claude", "command"):
                errors.append(f"entry.{key}: unknown key.")
        chosen = [key for key in ("claude", "command") if key in entry]
        if len(chosen) != 1:
            errors.append("entry: needs exactly one of claude or command.")
        elif chosen == ["claude"]:
            if not isinstance(entry["claude"], str) or not entry["claude"].strip() or len(entry["claude"]) > 4000:
                errors.append("entry.claude: must be a prompt or slash command of 1 to 4000 characters.")
        else:
            command = entry["command"]
            if (not isinstance(command, list) or not command or len(command) > 64
                    or not all(isinstance(part, str) and part for part in command)):
                errors.append("entry.command: must be a non-empty list of up to 64 non-empty strings.")

    model = manifest.get("model")
    if model is not None and (not isinstance(model, str) or not re.match(r"^[A-Za-z0-9._:@/-]{1,100}$", model)):
        errors.append("model: must be a model id such as claude-opus-5-5.")

    triggers = manifest.get("triggers", [])
    if not isinstance(triggers, list):
        errors.append("triggers: must be a list.")
        triggers = []
    crons = webhooks = 0
    for index, trigger in enumerate(triggers):
        path = f"triggers[{index}]"
        if not isinstance(trigger, dict):
            errors.append(f"{path}: must be a mapping with cron or webhook.")
            continue
        if "cron" in trigger:
            crons += 1
            for key in trigger:
                if key not in ("cron", "tz"):
                    errors.append(f"{path}.{key}: unknown key.")
            if not isinstance(trigger["cron"], str) or not cron_valid(trigger["cron"]):
                errors.append(f"{path}.cron: must be a five-field cron expression such as \"0 7 * * *\".")
            tz = trigger.get("tz", "UTC")
            try:
                if not isinstance(tz, str) or not tz:
                    raise ZoneInfoNotFoundError
                ZoneInfo(tz)
            except (ZoneInfoNotFoundError, ValueError):
                errors.append(f"{path}.tz: must be an IANA time zone such as Europe/London.")
        elif "webhook" in trigger:
            webhooks += 1
            for key in trigger:
                if key != "webhook":
                    errors.append(f"{path}.{key}: unknown key.")
            if trigger["webhook"] not in ({}, None):
                errors.append(f"{path}.webhook: takes no options yet; write webhook: {{}}.")
        else:
            errors.append(f"{path}: must be a mapping with cron or webhook.")
    if crons > MAX_CRON_TRIGGERS:
        errors.append(f"triggers: at most {MAX_CRON_TRIGGERS} cron triggers.")
    if webhooks > 1:
        errors.append("triggers: at most one webhook trigger.")

    _str_list(manifest.get("connections", []), "connections", errors,
              item_re=re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"),
              item_message="must be a Studio connection name such as google.gmail.")
    if manifest.get("google_account", "personal") not in ("personal", "workspace"):
        errors.append("google_account: must be personal or workspace.")

    names = _str_list(manifest.get("secrets", []), "secrets", errors, item_re=SECRET_RE,
                      item_message="must be an UPPER_SNAKE_CASE name of at most 64 characters.")
    for index, item in enumerate(names):
        if isinstance(item, str) and (item in RESERVED_SECRETS or item.startswith(RESERVED_SECRET_PREFIXES)):
            errors.append(f"secrets[{index}]: {item} is reserved for Studio.")

    hosts = manifest.get("egress", [])
    if isinstance(hosts, list):
        hosts = [host.lower() if isinstance(host, str) else host for host in hosts]
    _str_list(hosts, "egress", errors, item_re=HOST_RE,
              item_message="must be a host name such as api.xero.com or *.xero.com (no IP addresses or ports).")
    for index, host in enumerate(hosts if isinstance(hosts, list) else []):
        if isinstance(host, str) and HOST_RE.match(host) and host_denied(host, studio_hosts):
            errors.append(f"egress[{index}]: {host} isn't allowed (Google, metadata, internal and Studio's own "
                          "hosts are refused; Studio adds what runs need itself).")

    approvals = manifest.get("approvals", {})
    if not isinstance(approvals, dict):
        errors.append("approvals: must be a mapping with ask.")
    else:
        for key in approvals:
            if key != "ask":
                errors.append(f"approvals.{key}: unknown key.")
        rules = _str_list(approvals.get("ask", []), "approvals.ask", errors, limit=100)
        for index, rule in enumerate(rules):
            if isinstance(rule, str) and not re.match(r"^[A-Za-z0-9_.-]+(\(.{1,500}\))?$", rule):
                errors.append(f"approvals.ask[{index}]: must be a Claude Code permission rule such as Bash(git push:*).")

    limits = manifest.get("limits", {})
    if not isinstance(limits, dict):
        errors.append("limits: must be a mapping with timeout and max_turns.")
        limits = {}
    for key in limits:
        if key not in ("timeout", "max_turns"):
            errors.append(f"limits.{key}: unknown key.")
    if "timeout" in limits:
        seconds = parse_duration(limits["timeout"])
        if seconds is None or not MIN_TIMEOUT <= seconds <= MAX_TIMEOUT:
            errors.append("limits.timeout: must be a duration from 1m to 60m, such as 30m.")
    if "max_turns" in limits:
        turns = limits["max_turns"]
        if isinstance(turns, bool) or not isinstance(turns, int) or not 1 <= turns <= MAX_TURNS:
            errors.append(f"limits.max_turns: must be a whole number from 1 to {MAX_TURNS}.")

    state = manifest.get("state")
    if state is not None and (not isinstance(state, str) or not STATE_RE.match(state)
                              or any(part in ("..", ".") for part in state.rstrip("/").split("/"))
                              or state.startswith((".git", ".claude"))):
        errors.append("state: must be a relative directory inside the project, such as state/.")

    if errors:
        raise ManifestError(errors)
    return normalise(manifest)


def normalise(manifest):
    """The manifest with every default filled in. Call only on a validated manifest."""
    limits = manifest.get("limits") or {}
    triggers = []
    for trigger in manifest.get("triggers") or []:
        if "cron" in trigger:
            triggers.append({"cron": " ".join(trigger["cron"].split()), "tz": trigger.get("tz") or "UTC"})
        else:
            triggers.append({"webhook": {}})
    state = manifest.get("state")
    return {
        "version": 1,
        "name": manifest["name"],
        "description": manifest.get("description") or "",
        "entry": dict(manifest["entry"]),
        "model": manifest.get("model") or "",
        "triggers": triggers,
        "connections": list(manifest.get("connections") or []),
        "google_account": manifest.get("google_account") or "personal",
        "secrets": list(manifest.get("secrets") or []),
        "egress": [host.lower() for host in manifest.get("egress") or []],
        "approvals": {"ask": list((manifest.get("approvals") or {}).get("ask") or [])},
        "limits": {"timeout": parse_duration(limits.get("timeout", DEFAULT_TIMEOUT)),
                   "max_turns": limits.get("max_turns", DEFAULT_MAX_TURNS)},
        "state": (state.rstrip("/") + "/") if state else "",
    }


def read(directory, *, studio_hosts=()):
    """``(manifest as written, normalised)`` from ``directory/studio.yaml``; ManifestError otherwise."""
    import os

    path = os.path.join(directory, "studio.yaml")
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except FileNotFoundError:
        raise ManifestError(["studio.yaml: not found here."]) from None
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise ManifestError(["studio.yaml: must be UTF-8 text."]) from None
    manifest = load(text)
    return manifest, validate(manifest, studio_hosts=studio_hosts)
