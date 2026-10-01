import json
import os
import tempfile
import unittest

from pipeguard import report
from pipeguard.cli import main
from pipeguard.deps import is_affected, parse_version, scan_dependencies
from pipeguard.sast import scan_sast
from pipeguard.secrets_scanner import redact, scan_secrets, shannon_entropy

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


class TestSecrets(unittest.TestCase):
    def _scan_text(self, text):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "cfg.py"), "w") as fh:
                fh.write(text)
            return scan_secrets(d)

    def test_aws_key_detected_and_redacted(self):
        key = "AKIA" + "ABCDEFGHIJKLMNOP"          # built at runtime so this file isn't flagged by scanners
        res = self._scan_text(f'aws = "{key}"\n')
        self.assertTrue(any(f.rule_id == "PG-SEC001" for f in res))
        self.assertNotIn(key, json.dumps([f.to_dict() for f in res]))

    def test_high_entropy_password_assignment(self):
        res = self._scan_text('password = "Zk3$9fQ!x7Lm2Pq8Rt5Vw1"\n')
        self.assertEqual(res[0].rule_id, "PG-SEC008")
        self.assertEqual(res[0].severity, "high")

    def test_placeholder_and_env_ignored(self):
        self.assertEqual(self._scan_text('password = "changeme-please"\ntoken = os.environ["T"]\n'), [])

    def test_inline_ignore_marker(self):
        self.assertEqual(self._scan_text('password = "Zk3$9fQ!x7Lm2Pq8Rt5Vw1"  # pipeguard:ignore\n'), [])

    def test_entropy_and_redact(self):
        self.assertGreater(shannon_entropy("Zk3$9fQ!x7Lm2Pq8"), 3.5)
        self.assertEqual(redact("abcdefghijkl"), "abcd****ijkl")


class TestSast(unittest.TestCase):
    def test_fixture_triggers_all_core_rules(self):
        ids = {f.rule_id for f in scan_sast(FIX)}
        for expected in ("PG-S001", "PG-S002", "PG-S003", "PG-S004", "PG-S005", "PG-S006", "PG-S007", "PG-S008"):
            self.assertIn(expected, ids)

    def test_safe_code_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "ok.py"), "w") as fh:
                fh.write("import sqlite3, yaml, subprocess\n"
                         "c = sqlite3.connect(':memory:')\n"
                         "c.execute('SELECT * FROM t WHERE id = ?', (1,))\n"
                         "yaml.safe_load('a: 1')\n"
                         "subprocess.run(['ls', '-l'])\n")
            self.assertEqual(scan_sast(d), [])

    def test_import_alias_resolution(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.py"), "w") as fh:
                fh.write("from hashlib import md5 as h\nh(b'x')\n")
            self.assertEqual([f.rule_id for f in scan_sast(d)], ["PG-S005"])


class TestDeps(unittest.TestCase):
    def test_version_logic(self):
        self.assertEqual(parse_version("2.28.1"), (2, 28, 1))
        self.assertTrue(is_affected("2.25.0", "2.31.0"))
        self.assertFalse(is_affected("2.31.0", "2.31.0"))

    def test_vulnerable_requirements_found(self):
        pkgs = {f.snippet.split("==")[0] for f in scan_dependencies(FIX)}
        self.assertEqual(pkgs, {"flask", "requests", "pyyaml"})   # pillow 10.2.0 is patched


class TestReportingAndCli(unittest.TestCase):
    def test_triage_dedup_and_baseline(self):
        findings = scan_sast(FIX)
        active, suppressed = report.triage(findings + findings)       # duplicates collapse
        self.assertEqual(len(active), len({f.fingerprint for f in findings}))
        active2, suppressed2 = report.triage(findings, {active[0].fingerprint})
        self.assertEqual(len(suppressed2), 1)
        self.assertEqual(active, sorted(active, key=lambda f: (-f.score, f.file, f.line)))

    def test_sarif_is_valid_json_with_results(self):
        sarif = json.loads(report.to_sarif(scan_sast(FIX)))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

    def test_html_escapes_content(self):
        from pipeguard.models import Finding
        f = Finding("X", "<script>alert(1)</script>", "high", "sast", "a.py", 1, snippet="<b>")
        self.assertNotIn("<script>alert(1)</script>", report.to_html([f]))

    def test_cli_exit_codes_and_outputs(self):
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(main([FIX, "-f", "json", "-f", "html", "-f", "sarif", "-f", "md", "-o", out, "--no-color"]), 1)
            self.assertEqual(sorted(os.listdir(out)), ["pipeguard.sarif", "report.html", "report.json", "report.md"])
            base = os.path.join(out, "base.json")
            main([FIX, "--write-baseline", base, "--fail-on", "never"])
            self.assertEqual(main([FIX, "--baseline", base, "--no-color"]), 0)   # everything baselined
        self.assertEqual(main(["/nonexistent/path"]), 2)


if __name__ == "__main__":
    unittest.main()
