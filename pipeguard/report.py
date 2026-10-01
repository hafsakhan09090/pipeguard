"""Report generators: JSON, Markdown, self-contained HTML and SARIF 2.1.0."""
from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone

from . import __version__
from .models import Finding, severity_rank

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SEV_COLOR = {"critical": "#b91c1c", "high": "#ea580c", "medium": "#ca8a04", "low": "#2563eb", "info": "#6b7280"}


def triage(findings: list[Finding], baseline: set[str] | None = None) -> tuple[list[Finding], list[Finding]]:
    """De-duplicate by fingerprint, drop baselined findings, sort by score (highest first).

    Returns (active, suppressed).
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.fingerprint, f)
    unique = list(seen.values())
    baseline = baseline or set()
    active = [f for f in unique if f.fingerprint not in baseline]
    suppressed = [f for f in unique if f.fingerprint in baseline]
    active.sort(key=lambda f: (-f.score, f.file, f.line))
    return active, suppressed


def summary(findings: list[Finding]) -> dict:
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)
    return {"total": len(findings),
            "by_severity": {s: by_sev.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            "by_category": dict(by_cat)}


def to_json(findings: list[Finding], suppressed: int = 0) -> str:
    return json.dumps({
        "tool": "pipeguard", "version": __version__,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary(findings), "suppressed_by_baseline": suppressed,
        "findings": [f.to_dict() for f in findings]}, indent=2)


def to_markdown(findings: list[Finding], suppressed: int = 0) -> str:
    s = summary(findings)
    lines = ["# PipeGuard Security Report", "",
             f"_Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} by PipeGuard v{__version__}_", "",
             f"**{s['total']} findings** "
             + " | ".join(f"{k}: {v}" for k, v in s["by_severity"].items()) +
             (f" | suppressed by baseline: {suppressed}" if suppressed else ""), ""]
    if not findings:
        lines.append("No findings. :tada:")
        return "\n".join(lines)
    lines += ["| Severity | Score | Rule | Location | Title |", "|---|---|---|---|---|"]
    for f in findings:
        lines.append(f"| {f.severity.upper()} | {f.score} | `{f.rule_id}` | `{f.file}:{f.line}` | {f.title} |")
    lines += ["", "## Details", ""]
    for f in findings:
        lines += [f"### [{f.severity.upper()}] {f.title}",
                  f"- **Rule:** `{f.rule_id}` {('(' + f.cwe + ')') if f.cwe else ''}",
                  f"- **Location:** `{f.file}:{f.line}`",
                  f"- **Evidence:** `{f.snippet}`",
                  f"- **Why it matters:** {f.description}",
                  f"- **Fix:** {f.remediation}", ""]
    return "\n".join(lines)


def to_html(findings: list[Finding], suppressed: int = 0) -> str:
    s = summary(findings)
    esc = html.escape
    cards = "".join(
        f'<div class="card" style="border-top:4px solid {SEV_COLOR[k]}"><b>{v}</b><span>{k}</span></div>'
        for k, v in s["by_severity"].items())
    rows = "".join(
        f"<tr><td><span class='pill' style='background:{SEV_COLOR.get(f.severity, '#666')}'>{esc(f.severity)}</span></td>"
        f"<td>{f.score}</td><td><code>{esc(f.rule_id)}</code></td><td><code>{esc(f.file)}:{f.line}</code></td>"
        f"<td><b>{esc(f.title)}</b><br><small>{esc(f.description)}</small><br>"
        f"<small><i>Fix:</i> {esc(f.remediation)}</small><br><code>{esc(f.snippet)}</code></td></tr>"
        for f in findings)
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>PipeGuard Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:1100px;padding:0 1rem;color:#111;background:#fafafa}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.card{{background:#fff;padding:1rem 1.5rem;border-radius:8px;box-shadow:0 1px 3px #0002;display:flex;flex-direction:column;min-width:110px}}
.card b{{font-size:1.8rem}} .card span{{text-transform:uppercase;font-size:.75rem;color:#555}}
table{{border-collapse:collapse;width:100%;background:#fff}} td,th{{padding:.6rem;border-bottom:1px solid #eee;text-align:left;vertical-align:top}}
.pill{{color:#fff;padding:2px 8px;border-radius:99px;font-size:.75rem;text-transform:uppercase}}
code{{background:#f1f5f9;padding:1px 4px;border-radius:4px;word-break:break-all}}
</style></head><body>
<h1>PipeGuard Security Report</h1>
<p>{s['total']} findings{(' (' + str(suppressed) + ' suppressed by baseline)') if suppressed else ''} &middot; PipeGuard v{__version__}</p>
<div class="cards">{cards}</div>
<table><thead><tr><th>Severity</th><th>Score</th><th>Rule</th><th>Location</th><th>Details</th></tr></thead>
<tbody>{rows or '<tr><td colspan=5>No findings.</td></tr>'}</tbody></table></body></html>"""


def to_sarif(findings: list[Finding]) -> str:
    """SARIF 2.1.0 - uploads to GitHub Code Scanning (Security tab)."""
    rules, seen = [], set()
    for f in findings:
        if f.rule_id not in seen:
            seen.add(f.rule_id)
            rules.append({"id": f.rule_id, "name": f.title,
                          "shortDescription": {"text": f.title},
                          "help": {"text": f.remediation},
                          "properties": {"tags": [t for t in (f.category, f.cwe) if t]}})
    results = [{
        "ruleId": f.rule_id, "level": SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f"{f.title}. {f.description}"},
        "partialFingerprints": {"pipeguard/v1": f.fingerprint},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file.replace('\\', '/')},
                                            "region": {"startLine": max(f.line, 1)}}}]}
        for f in findings]
    return json.dumps({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
                       "runs": [{"tool": {"driver": {"name": "PipeGuard", "version": __version__,
                                                      "rules": rules}}, "results": results}]}, indent=2)


def console(findings: list[Finding], suppressed: int = 0, color: bool = True) -> str:
    def c(text, sev):
        if not color:
            return text
        code = {"critical": "1;31", "high": "31", "medium": "33", "low": "34", "info": "90"}[sev]
        return f"\033[{code}m{text}\033[0m"
    s = summary(findings)
    out = [f"\nPipeGuard v{__version__} - {s['total']} finding(s)"
           + (f", {suppressed} suppressed by baseline" if suppressed else "")]
    for f in findings:
        out.append(f"  {c(f.severity.upper().ljust(8), f.severity)} {f.score:>3}  "
                   f"{f.file}:{f.line}  {f.rule_id}  {f.title}")
    out.append("  Summary: " + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items()))
    return "\n".join(out)
