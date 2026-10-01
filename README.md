# PipeGuard - CI/CD Security Scanner & Triage Tool

PipeGuard is a dependency-free Python tool that scans a repository for **hard-coded secrets**, **insecure code patterns (SAST)** and **vulnerable dependencies**, then **de-duplicates, scores and prioritises** the results and exports them as Console, JSON, Markdown, HTML and **SARIF** (GitHub Code Scanning). It is designed to run inside a CI/CD pipeline and fail the build when serious issues are found.

> Built to mirror the day-to-day workflow of a security-engineering team: automated scanning -> triage -> reporting -> remediation guidance.

## Features

| Module | What it finds | Techniques |
|---|---|---|
| `secrets_scanner` | AWS/GitHub/Slack/Google keys, private keys, JWTs, credentials in URLs, hard-coded passwords/tokens | Signature regexes + Shannon-entropy scoring, placeholder filtering, **secret redaction in reports** |
| `sast` | `eval/exec`, shell injection, insecure deserialisation (pickle/YAML), SQL injection via string-building, weak hashes, disabled TLS verification, Flask debug mode, insecure temp files/random | Python `ast` tree walking with import-alias resolution (`from hashlib import md5 as h` is still caught); each rule mapped to a **CWE** |
| `deps` | Known-vulnerable pinned packages in `requirements*.txt` and `package.json` | Offline advisory DB (`data/advisories.json`) + optional live **OSV.dev** lookup (`--osv`) |
| `report` | Triage & output | Fingerprint de-duplication, severity x confidence **risk score**, **baseline/suppression** file, SARIF 2.1.0 |

## Quick start

```bash
git clone https://github.com/<your-username>/pipeguard.git
cd pipeguard

# scan the current directory, write all reports, fail on HIGH+
python -m pipeguard . -f html -f md -f json -f sarif

# try it on the intentionally vulnerable sample
python -m pipeguard tests/fixtures -f html --fail-on never
```

Open `pipeguard-report/report.html` for the dashboard.

### Useful flags

```text
--fail-on {low,medium,high,critical,never}   CI gate threshold (default: high)
--baseline baseline.json                     suppress already-accepted findings
--write-baseline baseline.json               accept everything currently found
--skip {secrets,sast,deps}                   disable a scanner
--exclude FRAGMENT                           skip paths containing FRAGMENT (e.g. tests/)
--osv                                        also query OSV.dev (needs internet)
```

Exit codes: `0` clean, `1` findings at/above threshold, `2` bad input.

## CI/CD integration

`.github/workflows/security.yml` runs the tests, scans on every push/PR, uploads SARIF so findings show up in the repo's **Security -> Code scanning** tab, and attaches the HTML report as a build artifact.

## Suppressing false positives

* Per line: add `# pipeguard:ignore` to the line.
* Per project: run `--write-baseline baseline.json`, commit it, and use `--baseline baseline.json`. Only **new** findings will fail future builds.

## Design decisions (good interview talking points)

* **Fingerprints exclude line numbers**, so a finding stays "the same finding" when code above it moves. This is what makes baselining practical.
* **Secrets are redacted before they ever reach a report** (`AKIA************MNOP`) so the report itself is not a leak.
* **Entropy + placeholder filtering** keeps the false-positive rate down (`changeme`, `os.environ[...]`, `${VAR}` are ignored).
* **AST instead of regex** for code rules means comments, strings and formatting don't cause false matches.
* HTML output is **escaped** because scanned code is untrusted input.

## Project layout

```text
pipeguard/
  pipeguard/        models.py secrets_scanner.py sast.py deps.py report.py cli.py
  data/advisories.json
  tests/            unit tests + intentionally vulnerable fixtures
  .github/workflows/security.yml
```

## Tests

```bash
python -m unittest discover -s tests -v      # or: pytest
```

## Limitations & roadmap

* The bundled advisory file is a small **demo dataset** - use `--osv` (or swap in a feed such as OSV/GHSA) for real coverage.
* SAST covers Python only. Next: JavaScript rules, Dockerfile/Terraform misconfiguration checks, GitHub Actions workflow hardening checks, and a Slack/Teams notifier for new CRITICAL findings.

## Responsible use

Only scan code you own or have permission to analyse. The files in `tests/fixtures/` are intentionally insecure and exist solely to test the scanner.

## License

MIT
