"""Credential shapes and redaction, shared by the runner (events) and the CLI (packaging refusals)."""

import re

# Shapes that are a credential on their own. Packaging refuses a file containing one; the runner redacts them.
KEY_SHAPES = (
    ("a private key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("an Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    ("a GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("an AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("a Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("a Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("a Stripe key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{10,}")),
    ("a GitLab token", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}")),
    ("an OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}")),
)

# Only redacted (too broad to refuse a file over).
_REDACT_ONLY = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    re.compile(r"(?i)\b(?:bearer|basic|token)\s+[A-Za-z0-9._~+/\-]{16,}=*"),
    re.compile(r"(?i)://[^/\s:@]+:[^/\s@]+@"),
)
_ASSIGNMENT = re.compile(
    r"(?i)\b((?:[a-z0-9_]*_)?(?:password|passwd|secret|token|api_?key|access_?key|private_?key))(\s*[=:]\s*)"
    r"(\"[^\"\n]{8,}\"|'[^'\n]{8,}'|(?=[^\s\"',;]*[0-9_/+=.-])[^\s\"',;]{8,})")
MARK = "[REDACTED]"


class Redactor:
    """Replaces known secret values (exactly) and credential shapes in text."""

    def __init__(self, values=()):
        self.values = []
        self.add(values)

    def add(self, values):
        for value in values:
            if isinstance(value, str) and len(value) >= 6 and value not in self.values:
                self.values.append(value)
        self.values.sort(key=len, reverse=True)

    def __call__(self, text):
        if not isinstance(text, str):
            text = str(text)
        for value in self.values:
            if value in text:
                text = text.replace(value, MARK)
        for pattern in _REDACT_ONLY:
            text = pattern.sub(MARK, text)
        for _, pattern in KEY_SHAPES:
            text = pattern.sub(MARK, text)
        return _ASSIGNMENT.sub(lambda match: match.group(1) + match.group(2) + MARK, text)


def first_key_shape(text):
    """The name of the first credential shape in ``text`` and its line number, or None."""
    for label, pattern in KEY_SHAPES:
        match = pattern.search(text)
        if match:
            return label, text.count("\n", 0, match.start()) + 1
    return None
