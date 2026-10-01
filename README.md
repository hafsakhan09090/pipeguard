# PipeGuard

**A dependency-free CI/CD security scanner and triage tool for Python projects.**

[![PipeGuard Security Scan](https://github.com/hafsakhan09090/pipeguard/actions/workflows/security.yml/badge.svg)](https://github.com/hafsakhan09090/pipeguard/actions/workflows/security.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

PipeGuard scans a repository for **hard-coded secrets**, **insecure code patterns (SAST)** and **vulnerable dependencies**. It then de-duplicates, scores and prioritises the results, and exports them as Console, JSON, Markdown, HTML and **SARIF** (GitHub Code Scanning). It is built to run inside a CI/CD pipeline and fail the build when serious issues are found.

It mirrors the day-to-day workflow of a security team: automated scanning, triage, reporting, then remediation guidance.

## Features

| Module | What it finds | Techniques |
| --- | --- | --- |
| `secrets_scanner` | AWS, GitHub, Slack and Google keys, private keys, JWTs, credentials in URLs, hard-coded passwords and tokens | Signature regexes, Shannon-entropy scoring, placeholder filtering, secret redaction in reports |
| `sast` | `eval`/`exec`, shell injection, insecure deserialisation (pickle/YAML), SQL injection via string-building, weak hashes, disabled TLS verification, Flask debug mode, insecure temp files and random | Python `ast` tree walking with import-alias resolution (`from hashlib import md5 as h` is still caught); each rule mapped to a CWE |
| `deps` | Known-vulnerable pinned packages in `requirements*.txt` and `package.json` | Offline advisory DB (`data/advisories.json`) plus optional live OSV.dev lookup (`--osv`) |
| `report` | Triage and output | Fingerprint de-duplication, severity x confidence risk score, baseline/suppression file, SARIF 2.1.0 |

## How it works

```
 files in repo
      |
      v
 [ secrets ] [ SAST ] [ deps ]     three independent scanners
      |
      v
 fingerprint + de-duplicate        same issue is reported once
      |
      v
 score (severity x confidence)     highest risk first
      |
      v
 apply baseline / ignore markers   accepted findings are suppressed
      |
      v
 reports + exit code               console, JSON, MD, HTML, SARIF
```

## Quick start

```bash
git clone https://github.com/hafsakhan09090/pipeguard.git
cd pipeguard

# scan the current directory, write all reports, fail on HIGH and above
python -m pipeguard . -f html -f md -f json -f sarif

# try it on the intentionally vulnerable sample
python -m pipeguard tests/fixtures -f html --fail-on never
```

Open `pipeguard-report/report.html` for the dashboard. No packages need installing: PipeGuard uses only the Python standard library (Python 3.9+).

## Useful flags

```
--fail-on {low,medium,high,critical,never}   CI gate threshold (default: high)
--baseline baseline.json                     suppress already-accepted findings
--write-baseline baseline.json               accept everything currently found
--skip {secrets,sast,deps}                   disable a scanner
--exclude FRAGMENT                           skip paths containing FRAGMENT (e.g. tests/)
--osv                                        also query OSV.dev (needs internet)
```

**Exit codes:** `0` clean, `1` findings at or above the threshold, `2` bad input.

## CI/CD integration

`.github/workflows/security.yml` runs the unit tests, scans on every push and pull request, uploads SARIF so findings appear under **Security -> Code scanning**, and attaches the HTML report as a build artifact.

To make the pipeline fail the build on serious findings, remove `continue-on-error: true` from the PipeGuard step in the workflow.

## Suppressing false positives

- **Per line:** add `# pipeguard:ignore` to the line.
- **Per project:** run `--write-baseline baseline.json`, commit the file, and use `--baseline baseline.json`. Only new findings will fail future builds.

## Design decisions

- **Fingerprints exclude line numbers**, so a finding stays the same finding when code above it moves. This is what makes baselining practical.
- **Secrets are redacted before they reach a report** (`AKIA************MNOP`), so the report itself is not a leak.
- **Entropy and placeholder filtering** keep the false-positive rate down (`changeme`, `os.environ[...]` and `${VAR}` are ignored).
- **AST instead of regex for code rules**, so comments, strings and formatting don't cause false matches.
- **HTML output is escaped**, because scanned code is untrusted input.

## Project layout

```
pipeguard/
  pipeguard/          models.py  secrets_scanner.py  sast.py  deps.py  report.py  cli.py
  data/advisories.json
  tests/              unit tests + intentionally vulnerable fixtures
  .github/workflows/security.yml
```

## Tests

```bash
python -m unittest discover -s tests -v      # or: pytest
```

## Limitations and roadmap

- The bundled advisory file is a small demo dataset. Use `--osv` (or swap in a feed such as OSV/GHSA) for real coverage.
- SAST covers Python only.
- Planned: JavaScript rules, Dockerfile and Terraform misconfiguration checks, GitHub Actions workflow hardening checks, and a Slack/Teams notifier for new CRITICAL findings.

## Responsible use

Only scan code you own or have permission to analyse.

The files in `tests/fixtures/` are **intentionally insecure** and exist solely to test the scanner. The password in `vulnerable_app.py` is fake, and the pinned versions in the fixture `requirements.txt` are deliberately outdated. Please don't copy any of it.

## License

[MIT](LICENSE)
