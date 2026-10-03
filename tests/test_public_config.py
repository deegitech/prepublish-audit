"""The public config ships with the repository, so it must not be able to switch the denylist gate off.

Each test is a bypass that worked before the config was treated as untrusted
input: excluding the file, shrinking the size limit, allowing or disabling
the coverage rules, turning decoding or archives off, or fail-on = "never"
and "error".
"""

import base64
import json
import unittest

from . import builders as B
from .helpers import TempTestCase, commit_all, findings_for, has_git, init_repo, rules_of, run_cli, scan_json

DENY = "falconcode\n  label: codename\n"


class PublicConfigTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.deny = self.denylist(DENY)
        self.write("tree/src/a.txt", "the falconcode plan\n")

    def config(self, data: dict) -> None:
        # JSON, so the tests also run where no TOML parser is installed.
        self.write("tree/.prepublish-audit.json", json.dumps(data))

    def scan(self, *args):
        return scan_json(self.root, "--denylist", str(self.deny), *args)

    def run_scan(self, *args):
        return run_cli("scan", "--denylist", str(self.deny), "--gitleaks", "never", "--no-external-tools", *args,
                       str(self.root), cwd=self.root)

    def assertDenylistFound(self, report, path="src/a.txt"):
        self.assertEqual(report["_exit"], 1, json.dumps(report["findings"])[:800])
        self.assertIn(path, [f["path"] for f in findings_for(report, "denylist")])

    def test_baseline(self):
        self.assertDenylistFound(self.scan())

    def test_excluded_paths_are_still_checked_against_the_denylist(self):
        self.write("tree/src/b.txt", "mail jane.roe@acme-corp.io\n")
        for exclude in (["src/**"], ["*"], ["src"]):
            with self.subTest(exclude):
                self.config({"exclude": exclude})
                report = self.scan()
                self.assertDenylistFound(report)
                self.assertEqual(findings_for(report, "leak.email"), [])  # built-in rules stay off there
                self.assertGreaterEqual(report["scanned"]["denylist_only"], 1)
                self.assertTrue(any("denylist only" in n for n in report["notes"]))

    def test_command_line_excludes_still_skip_everything(self):
        report = self.scan("--exclude", "src/**")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scanned"]["excluded"], 1)

    def test_excludes_without_a_denylist_skip_the_path(self):
        self.config({"exclude": ["src/**"]})
        report = scan_json(self.root, "--no-denylist")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scanned"]["excluded"], 1)

    def test_a_tiny_max_file_size_is_not_applied(self):
        self.config({"max-file-size": "1"})
        self.write("tree/logo.png", "falconcode in a text file named like an image\n")
        report = self.scan()
        self.assertDenylistFound(report)
        self.assertDenylistFound(report, "logo.png")
        self.assertTrue(any("max-file-size" in n and "Not applied" in n for n in report["notes"]))

    def test_coverage_rules_cannot_be_disabled_or_allowed_from_the_config(self):
        for data in ({"max-file-size": "1", "disable": ["scan.incomplete"]},
                     {"max-file-size": "1", "allow": [{"rules": ["scan.*"], "paths": ["**"]}]},
                     {"severity": {"scan.incomplete": "note"}}):
            with self.subTest(data):
                self.config(data)
                res = self.run_scan()
                self.assertEqual(res.code, 2)
                self.assertIn("command line", res.err)

    def test_wildcards_in_the_config_do_not_reach_coverage_rules(self):
        self.config({"allow": [{"rules": ["*"], "paths": ["**"]}]})
        self.write("tree/backup.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
        report = self.scan()
        self.assertIn("scan.incomplete", rules_of(report))
        self.assertDenylistFound(report)

    def test_decoding_cannot_be_turned_off(self):
        encoded = base64.b64encode(b"the falconcode plan, base64 encoded here").decode()
        self.write("tree/src/a.txt", f"x = '{encoded}'\n")
        self.config({"decode": False})
        self.assertDenylistFound(self.scan())
        self.assertEqual(findings_for(self.scan("--no-decode"), "denylist"), [])  # the command line still can

    def test_archives_cannot_be_turned_off(self):
        self.config({"archives": False, "max-archive-depth": 0})
        self.write("tree/bundle.zip", B.zip_bytes({"inner.zip": B.zip_bytes({"notes.txt": b"falconcode\n"})}))
        report = self.scan()
        self.assertIn("bundle.zip!/inner.zip!/notes.txt", [f["path"] for f in findings_for(report, "denylist")])

    def test_fail_on_never_is_command_line_only(self):
        self.config({"fail-on": "never"})
        res = self.run_scan()
        self.assertEqual(res.code, 2)
        self.assertIn("--fail-on never", res.err)
        self.config({})
        self.assertEqual(self.run_scan("--fail-on", "never").code, 0)

    def test_fail_on_error_still_fails_on_content_the_denylist_could_not_check(self):
        self.write("tree/src/a.txt", "clean\n")
        self.write("tree/backup.7z", b"7z\xbc\xaf\x27\x1c" + b"falconcode")
        self.config({"fail-on": "error"})
        report = self.scan()
        self.assertEqual(rules_of(report), ["scan.incomplete"])
        self.assertEqual(report["_exit"], 1)
        self.assertTrue(any("could not check" in n for n in report["notes"]))
        self.assertEqual(self.scan("--fail-on", "error")["_exit"], 0)  # trusted command line
        self.assertEqual(scan_json(self.root, "--no-denylist")["_exit"], 0)  # no denylist, config honoured

    def test_reports_say_what_was_excluded_and_when_nothing_was_scanned(self):
        summary = self.tmp / "summary.md"
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "--exclude", "src/**",
                      "--summary-markdown", str(summary), str(self.root), cwd=self.root)
        self.assertIn("1 excluded", res.out)
        self.assertIn("1 excluded", summary.read_text())
        self.assertIn("no files were scanned", res.out)
        self.assertIn("no files were scanned", summary.read_text())
        quiet = run_cli("scan", "-q", "--no-denylist", "--gitleaks", "never", "--exclude", "*", str(self.root),
                        cwd=self.root)
        self.assertIn("Warning: no files were scanned", quiet.out)

    def test_denylist_matches_still_fail_with_fail_on_error(self):
        self.config({"fail-on": "error"})
        self.assertDenylistFound(self.scan())


@unittest.skipUnless(has_git(), "git is required")
class PublicConfigHistoryTests(TempTestCase):
    def test_config_excludes_in_history_are_checked_against_the_denylist_only(self):
        repo = init_repo(self.tmp / "repo")
        deny = self.denylist(DENY)
        self.write("repo/.prepublish-audit.json", '{"exclude": ["vendor/**"]}')
        self.write("repo/vendor/old.txt", "falconcode and jane.roe@acme-corp.io\n")
        commit_all(repo, "add vendor notes")
        (repo / "vendor" / "old.txt").unlink()
        commit_all(repo, "remove")
        report = scan_json(repo, "--denylist", str(deny), "--history")
        deny_findings = findings_for(report, "denylist")
        self.assertEqual([(f["path"], f["origin"]) for f in deny_findings], [("vendor/old.txt", "history")])
        self.assertEqual(findings_for(report, "leak.email"), [])
        self.assertEqual(report["_exit"], 1)


if __name__ == "__main__":
    unittest.main()
