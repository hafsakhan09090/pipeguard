"""Command-line interface. Exit code 1 when findings meet the --fail-on threshold (for CI gating)."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, report
from .deps import scan_dependencies
from .models import severity_rank
from .sast import scan_sast
from .secrets_scanner import scan_secrets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pipeguard", description="Lightweight CI/CD security scanner & triage tool.")
    p.add_argument("path", nargs="?", default=".", help="File or directory to scan (default: .)")
    p.add_argument("--format", "-f", action="append", choices=["json", "md", "html", "sarif"],
                   help="Report format(s) to write (repeatable). Console summary is always printed.")
    p.add_argument("--output-dir", "-o", default="pipeguard-report", help="Where to write reports")
    p.add_argument("--fail-on", choices=["low", "medium", "high", "critical", "never"], default="high",
                   help="Exit 1 if any finding is at/above this severity (default: high)")
    p.add_argument("--baseline", help="JSON file of accepted fingerprints to suppress")
    p.add_argument("--write-baseline", metavar="FILE", help="Save current findings' fingerprints as a baseline")
    p.add_argument("--osv", action="store_true", help="Also query the live OSV.dev API for dependency vulns")
    p.add_argument("--skip", action="append", default=[], choices=["secrets", "sast", "deps"],
                   help="Skip a scanner (repeatable)")
    p.add_argument("--exclude", action="append", default=[], metavar="FRAGMENT",
                   help="Skip paths containing this fragment, e.g. --exclude tests/ (repeatable)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"pipeguard {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.exists(args.path):
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    from . import secrets_scanner
    secrets_scanner.EXCLUDES[:] = args.exclude
    findings = []
    if "secrets" not in args.skip:
        findings += scan_secrets(args.path)
    if "sast" not in args.skip:
        findings += scan_sast(args.path)
    if "deps" not in args.skip:
        findings += scan_dependencies(args.path, use_osv=args.osv)

    baseline: set[str] = set()
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline, "r", encoding="utf-8") as fh:
            baseline = set(json.load(fh).get("fingerprints", []))

    active, suppressed = report.triage(findings, baseline)

    if args.write_baseline:
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"fingerprints": sorted({f.fingerprint for f in active + suppressed})}, fh, indent=2)
        print(f"Baseline written to {args.write_baseline}")

    print(report.console(active, len(suppressed), color=not args.no_color and sys.stdout.isatty()))

    if args.format:
        os.makedirs(args.output_dir, exist_ok=True)
        writers = {"json": ("report.json", lambda: report.to_json(active, len(suppressed))),
                   "md": ("report.md", lambda: report.to_markdown(active, len(suppressed))),
                   "html": ("report.html", lambda: report.to_html(active, len(suppressed))),
                   "sarif": ("pipeguard.sarif", lambda: report.to_sarif(active))}
        for fmt in dict.fromkeys(args.format):
            name, fn = writers[fmt]
            with open(os.path.join(args.output_dir, name), "w", encoding="utf-8") as fh:
                fh.write(fn())
            print(f"Wrote {os.path.join(args.output_dir, name)}")

    if args.fail_on != "never":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in active):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
