"""Lightweight Python SAST built on the standard-library `ast` module."""
from __future__ import annotations

import ast
import os

from .models import Finding
from .secrets_scanner import iter_files, IGNORE_MARKER, _base

RULES = {
    "PG-S001": ("Use of eval()/exec()", "high", "CWE-95",
                "Avoid eval/exec on dynamic input. Use ast.literal_eval or explicit parsing."),
    "PG-S002": ("Shell command execution", "high", "CWE-78",
                "Pass an argument list to subprocess.run(..., shell=False) and validate input."),
    "PG-S003": ("Insecure deserialization (pickle/marshal)", "high", "CWE-502",
                "Never unpickle untrusted data. Use JSON or a signed/validated format."),
    "PG-S004": ("yaml.load without SafeLoader", "high", "CWE-502",
                "Use yaml.safe_load()."),
    "PG-S005": ("Weak hash algorithm (MD5/SHA-1)", "medium", "CWE-327",
                "Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords."),
    "PG-S006": ("TLS certificate verification disabled", "medium", "CWE-295",
                "Remove verify=False; trust a proper CA bundle instead."),
    "PG-S007": ("Possible SQL injection (string-built query)", "high", "CWE-89",
                "Use parameterised queries: cursor.execute('... WHERE id = ?', (value,))."),
    "PG-S008": ("Flask debug mode enabled", "medium", "CWE-489",
                "Never run with debug=True in production; it exposes the Werkzeug console."),
    "PG-S009": ("Insecure temporary file (mktemp)", "low", "CWE-377",
                "Use tempfile.mkstemp() or NamedTemporaryFile()."),
    "PG-S010": ("Insecure random for security use", "low", "CWE-338",
                "Use the 'secrets' module for tokens, passwords and keys."),
}

WEAK_HASHES = {"hashlib.md5", "hashlib.sha1"}
SHELL_CALLS = {"os.system", "os.popen"}
SUBPROCESS_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen",
                    "subprocess.check_call", "subprocess.check_output"}
PICKLE_CALLS = {"pickle.load", "pickle.loads", "marshal.load", "marshal.loads",
                "cPickle.load", "cPickle.loads", "dill.load", "dill.loads"}
HTTP_CALLS = {f"requests.{m}" for m in ("get", "post", "put", "delete", "head", "patch", "request")}
SQL_METHODS = {"execute", "executemany", "executescript"}
RANDOM_FUNCS = {"random", "randint", "choice", "randrange", "getrandbits"}
SECURITY_WORDS = ("token", "secret", "password", "passwd", "key", "salt", "nonce", "otp", "session")


class _Visitor(ast.NodeVisitor):
    def __init__(self, relpath: str, source_lines: list[str]):
        self.relpath = relpath
        self.lines = source_lines
        self.findings: list[Finding] = []
        self.aliases: dict[str, str] = {}

    # Import alias resolution so `from hashlib import md5` is still caught.
    def visit_Import(self, node):
        for a in node.names:
            self.aliases[a.asname or a.name] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            for a in node.names:
                self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        self.generic_visit(node)

    def _dotted(self, node) -> str:
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
            return ".".join(reversed(parts))
        return ""

    def _add(self, rule_id: str, node, confidence="high", detail=""):
        line = getattr(node, "lineno", 1)
        text = self.lines[line - 1].strip() if 0 < line <= len(self.lines) else ""
        if IGNORE_MARKER in text:
            return
        title, sev, cwe, fix = RULES[rule_id]
        self.findings.append(Finding(
            rule_id=rule_id, title=title, severity=sev, category="sast", file=self.relpath,
            line=line, snippet=text[:160], description=detail or title, remediation=fix,
            cwe=cwe, confidence=confidence))

    @staticmethod
    def _kw_const(node: ast.Call, name: str, value) -> bool:
        return any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is value
                   for k in node.keywords)

    @staticmethod
    def _is_dynamic_string(node) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            sides = (node.left, node.right)
            has_str = any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides)
            return has_str and not all(isinstance(s, ast.Constant) for s in sides)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return isinstance(node.func.value, ast.Constant)
        return False

    def visit_Call(self, node: ast.Call):
        name = self._dotted(node.func)
        bare = name.split(".")[-1] if name else ""

        if name in ("eval", "exec"):
            if not (node.args and isinstance(node.args[0], ast.Constant)):
                self._add("PG-S001", node)
        if name in SHELL_CALLS:
            self._add("PG-S002", node)
        elif name in SUBPROCESS_CALLS and self._kw_const(node, "shell", True):
            self._add("PG-S002", node, detail="subprocess called with shell=True")
        if name in PICKLE_CALLS:
            self._add("PG-S003", node)
        if name == "yaml.load":
            loader = next((self._dotted(k.value) for k in node.keywords if k.arg == "Loader"), "")
            if "Safe" not in loader:
                self._add("PG-S004", node)
        if name in WEAK_HASHES:
            self._add("PG-S005", node, confidence="medium")
        if name in HTTP_CALLS and self._kw_const(node, "verify", False):
            self._add("PG-S006", node)
        if bare in SQL_METHODS and node.args and self._is_dynamic_string(node.args[0]):
            self._add("PG-S007", node, detail="SQL statement is assembled with string formatting/concatenation.")
        if bare == "run" and self._kw_const(node, "debug", True):
            self._add("PG-S008", node)
        if name == "tempfile.mktemp":
            self._add("PG-S009", node)
        if name.startswith("random.") and bare in RANDOM_FUNCS:
            line = self.lines[node.lineno - 1].lower() if node.lineno <= len(self.lines) else ""
            if any(w in line for w in SECURITY_WORDS):
                self._add("PG-S010", node, confidence="low")
        self.generic_visit(node)


def scan_sast(root: str) -> list[Finding]:
    findings: list[Finding] = []
    base = _base(root)
    for path in iter_files(root):
        if not path.endswith(".py"):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
            tree = ast.parse(source, filename=path)
        except (SyntaxError, OSError, ValueError):
            continue
        visitor = _Visitor(os.path.relpath(path, base), source.splitlines())
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings
