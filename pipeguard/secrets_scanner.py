"""Detect hard-coded secrets using signature regexes and entropy analysis."""
from __future__ import annotations

import math
import os
import re
from typing import Iterator

from .models import Finding

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".tox"}
MAX_FILE_BYTES = 1_000_000
IGNORE_MARKER = "pipeguard:ignore"
EXCLUDES: list[str] = []   # path fragments to skip (set by --exclude)

# (rule_id, title, regex, severity)
SIGNATURES = [
    ("PG-SEC001", "AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("PG-SEC002", "GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("PG-SEC003", "Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("PG-SEC004", "Private key block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("PG-SEC005", "Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("PG-SEC006", "JSON Web Token",
     re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    ("PG-SEC007", "Credentials inside URL",
     re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]{2,}:[^/\s:@]{3,}@[^/\s]+"), "high"),
]

ASSIGNMENT = re.compile(
    r"""(?ix)
    (?P<name>[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?key|private[_-]?key)[\w.-]*)
    \s*[:=]\s*
    (?P<q>['"])(?P<value>[^'"\n]{8,})(?P=q)
    """
)
PLACEHOLDERS = ("changeme", "example", "your_", "your-", "<", "xxxx", "placeholder",
                "dummy", "sample", "test", "${", "{{", "os.environ", "getenv")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) for c in set(text)}
    return -sum((n / len(text)) * math.log2(n / len(text)) for n in freq.values())


def redact(value: str) -> str:
    """Never write full secrets into reports."""
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def iter_files(root: str) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            if any(x in path.replace("\\", "/") for x in EXCLUDES):
                continue
            try:
                if os.path.getsize(path) <= MAX_FILE_BYTES and not os.path.islink(path):
                    yield path
            except OSError:
                continue


def _read_text(path: str) -> list[str] | None:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:2048]:      # binary file
        return None
    return data.decode("utf-8", errors="ignore").splitlines()


def _base(root: str) -> str:
    return root if os.path.isdir(root) else (os.path.dirname(root) or ".")


def scan_secrets(root: str) -> list[Finding]:
    findings: list[Finding] = []
    base = _base(root)
    for path in iter_files(root):
        lines = _read_text(path)
        if lines is None:
            continue
        rel = os.path.relpath(path, base)
        for lineno, line in enumerate(lines, start=1):
            if IGNORE_MARKER in line:
                continue
            matched_on_line = False
            for rule_id, title, regex, severity in SIGNATURES:
                m = regex.search(line)
                if m:
                    matched_on_line = True
                    findings.append(Finding(
                        rule_id=rule_id, title=f"Hard-coded secret: {title}", severity=severity,
                        category="secret", file=rel, line=lineno, snippet=redact(m.group(0)),
                        description=f"A value matching the format of a {title} was committed to source control.",
                        remediation="Revoke and rotate the credential immediately, remove it from git history "
                                    "(git filter-repo / BFG), and load it from a secrets manager or environment variable.",
                        cwe="CWE-798", confidence="high"))
            if matched_on_line:
                continue
            m = ASSIGNMENT.search(line)
            if m:
                value = m.group("value")
                if any(p in value.lower() for p in PLACEHOLDERS):
                    continue
                entropy = shannon_entropy(value)
                high_entropy = entropy >= 3.5 and len(value) >= 16
                findings.append(Finding(
                    rule_id="PG-SEC008", title="Possible hard-coded credential",
                    severity="high" if high_entropy else "medium", category="secret",
                    file=rel, line=lineno, snippet=f"{m.group('name')} = {redact(value)}",
                    description=f"Variable '{m.group('name')}' is assigned a literal string "
                                f"(entropy {entropy:.2f} bits/char).",
                    remediation="Move the value to an environment variable or secrets manager. "
                                "If it is a false positive, add '# pipeguard:ignore' to the line.",
                    cwe="CWE-798", confidence="high" if high_entropy else "low",
                    extra={"entropy": round(entropy, 2)}))
    return findings
