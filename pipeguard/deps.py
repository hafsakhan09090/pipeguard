"""Dependency vulnerability scanning (offline advisory DB, optional live OSV lookup)."""
from __future__ import annotations

import json
import os
import re
import urllib.request

from .models import Finding
from .secrets_scanner import iter_files, _base

ADVISORY_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "advisories.json")
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[.*\])?\s*==\s*([A-Za-z0-9_.\-]+)")
OSV_URL = "https://api.osv.dev/v1/query"


def parse_version(v: str) -> tuple:
    """'2.28.1' -> (2, 28, 1). Non-numeric suffixes are ignored (good enough for triage)."""
    nums = []
    for part in re.split(r"[.\-+]", v.strip().lstrip("vV^~")):
        m = re.match(r"\d+", part)
        if not m:
            break
        nums.append(int(m.group()))
    return tuple(nums) or (0,)


def is_affected(version: str, fixed: str) -> bool:
    """An advisory here is expressed as 'vulnerable before <fixed>'."""
    return parse_version(version) < parse_version(fixed)


def load_advisories(path: str = ADVISORY_FILE) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_requirements(path: str) -> list[tuple[str, str, int]]:
    out = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, line in enumerate(fh, start=1):
            m = REQ_LINE.match(line.split("#")[0])
            if m:
                out.append((m.group(1).lower().replace("_", "-"), m.group(2), lineno))
    return out


def parse_package_json(path: str) -> list[tuple[str, str, int]]:
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return out
    for section in ("dependencies", "devDependencies"):
        for name, ver in (data.get(section) or {}).items():
            out.append((name.lower(), str(ver), 1))
    return out


def query_osv(name: str, version: str, ecosystem: str, timeout: int = 8) -> list[dict]:
    """Live lookup against the public OSV.dev API. Returns [] on any network error."""
    body = json.dumps({"version": version, "package": {"name": name, "ecosystem": ecosystem}}).encode()
    req = urllib.request.Request(OSV_URL, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # nosec - fixed HTTPS URL
            return json.load(resp).get("vulns", [])
    except Exception:
        return []


def scan_dependencies(root: str, use_osv: bool = False) -> list[Finding]:
    advisories = load_advisories()
    findings: list[Finding] = []
    base = _base(root)
    for path in iter_files(root):
        fname = os.path.basename(path)
        if fname.startswith("requirements") and fname.endswith(".txt"):
            deps, eco = parse_requirements(path), "PyPI"
        elif fname == "package.json":
            deps, eco = parse_package_json(path), "npm"
        else:
            continue
        rel = os.path.relpath(path, base)
        for name, version, lineno in deps:
            for adv in advisories:
                if adv["ecosystem"] == eco and adv["package"] == name and is_affected(version, adv["fixed"]):
                    findings.append(Finding(
                        rule_id=adv["id"], title=f"Vulnerable dependency: {name} {version}",
                        severity=adv["severity"], category="dependency", file=rel, line=lineno,
                        snippet=f"{name}=={version}", description=adv["summary"],
                        remediation=f"Upgrade {name} to {adv['fixed']} or later.",
                        cwe=adv.get("cwe", ""), confidence="high",
                        extra={"cve": adv.get("cve", ""), "fixed_in": adv["fixed"]}))
            if use_osv:
                for vuln in query_osv(name, version.lstrip("^~vV"), eco):
                    findings.append(Finding(
                        rule_id=vuln.get("id", "OSV"), title=f"Vulnerable dependency: {name} {version}",
                        severity="high", category="dependency", file=rel, line=lineno,
                        snippet=f"{name}=={version}", description=vuln.get("summary", "See OSV entry."),
                        remediation="Review the OSV advisory and upgrade to a patched release.",
                        confidence="medium", extra={"source": "osv.dev"}))
    return findings
