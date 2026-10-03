"""Every known error gets a one-line fix, and the fix never repeats what the error was about."""

import json
import os
import textwrap
import unittest
from pathlib import Path

from prepublish_audit.config import ConfigError, Settings, apply_mapping, parse_cli_allow
from prepublish_audit.denylist import Denylist, DenylistError
from prepublish_audit.hints import all_hints, hint_for

from .helpers import POSIX, PY, TempTestCase, has_git, run_cli

ROOT = Path(__file__).resolve().parents[1]


class HintTableTests(unittest.TestCase):
    def test_every_fix_is_one_short_line(self):
        for fix in all_hints():
            with self.subTest(fix=fix[:40]):
                self.assertNotIn("\n", fix)
                self.assertLessEqual(len(fix), 240)
                self.assertTrue(fix.endswith("."), "a fix is a sentence")

    def test_unknown_messages_have_no_fix(self):
        self.assertIsNone(hint_for("something nobody has seen before"))
        self.assertIsNone(hint_for(""))

    def test_messages_from_the_code(self):
        # (message exactly as the code builds it, a fragment of the expected fix)
        cases = [
            ("path not found: site/dist", "cd into the repository"),
            ("--reveal is refused in CI because build logs are often public "
             "(set PREPUBLISH_AUDIT_ALLOW_REVEAL=1 to override)", "on your own machine"),
            ("--reveal output must not be written inside a scanned tree", "outside every repository"),
            ("no denylist entries were loaded (--require-denylist)", "pull requests from forks"),
            ("no denylist given and none found in the default location", "prepublish-audit init"),
            ("cannot find a home directory for the private denylist", "Set HOME"),
            ("--history needs a git repository (and git on PATH)", "git rev-parse --show-toplevel"),
            ("--git-files: not inside a git work tree (or git failed)", "git ls-files"),
            ("--git-files needs git: [Errno 2] No such file or directory", "git ls-files"),
            ("git cat-file failed: fatal: missing blob object", "git fsck"),
            ("gitleaks was requested (--gitleaks always) but is not on PATH", "brew install gitleaks"),
            ("gitleaks timed out", "--exclude"),
            ("gitleaks could not start (Exec format error)", "CPU architecture"),
            ("gitleaks exited with status 3", "gitleaks version"),
            ("gitleaks wrote an unreadable report", "gitleaks version"),
            ("could not write the report: Permission denied", "output folder"),
            ("the denylist cannot be disabled", "indented 'allow: PATH-GLOB'"),
            ("--allow expects RULE:PATH-GLOB, for example leak.email:docs/**", "quote it"),
            ("--max-file-size: unrecognised size (use bytes or a unit such as 10MiB)", "64MiB"),
            ("denylist 2 could not be read (No such file or directory)", "ls -l FILE"),
            ("denylist 1 could not be read (Permission denied)", "As the file's owner, run chmod 600 FILE"),
            ("denylist 1 could not be read (Is a directory)", "not its folder"),
            ("denylist 1 is not valid UTF-8", "UTF-8"),
            (".prepublish-audit.toml: reading TOML on Python 3.10 needs the 'tomli' package: install it", "tomli"),
            ("cannot read config pyproject.toml: Permission denied", "--no-config"),
        ]
        for message, fragment in cases:
            with self.subTest(message=message):
                fix = hint_for(message)
                self.assertIsNotNone(fix, message)
                self.assertIn(fragment, fix)

    def test_real_denylist_errors(self):
        cases = [
            ("bad.txt", "re:(heron\n", "Escape characters"),
            ("bad.txt", "re:a*\n", "matches everywhere"),
            ("bad.txt", "ab\n", "more specific"),
            ("bad.txt", "  allow: docs/**\n", "Indented lines belong"),
            ("bad.txt", "Heron\n  allow:\n", "Indented lines belong"),
            ("bad.txt", "Heron\n  allow: docs/** colour=red\n", "Indented lines belong"),
            ("bad.txt", "Heron\n  allow: docs/** line=x line=y\n", "Indented lines belong"),
            ("bad.txt", "Heron\n  allow: docs/** line=(x\n", "allow lines"),
            ("bad.json", "{oops", "json.tool"),
            ("bad.json", '{"Heron Corp": "company"}', "'entries' list"),
            ("bad.json", '{"entries": {"literal": "Heron"}}', "'entries' list"),
            ("bad.json", '{"entries": [42]}', "exactly one of literal"),
            ("bad.json", '{"entries": [{"literal": "Heron", "regex": "x+"}]}', "exactly one of literal"),
            ("bad.json", '{"entries": [{"literal": "Heron", "colour": "red"}]}', "exactly one of literal"),
            ("bad.json", '{"entries": [{"literal": "Heron", "allow": [{"line": "x"}]}]}', "exactly one of literal"),
            ("bad.json", '{"entries": [{"regex": "(x"}]}', "Escape characters"),
            ("bad.json", '{"entries": [{"literal": "Heron", "allow": [{"path": ""}]}]}', "allow lines"),
        ]
        with self.subTest("binary"):
            self._assert_denylist_fix("bad.txt", b"\xff\xfe\x00bad", "UTF-8")
        for name, content, fragment in cases:
            with self.subTest(content=content):
                self._assert_denylist_fix(name, content.encode(), fragment)

    def _assert_denylist_fix(self, name: str, content: bytes, fragment: str) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / name
            path.write_bytes(content)
            with self.assertRaises(DenylistError) as ctx:
                Denylist.load([path])
            message = str(ctx.exception)
            fix = hint_for(message)
            self.assertIsNotNone(fix, message)
            self.assertIn(fragment, fix, message)
            self.assertNotIn("heron", fix.lower())

    def test_real_config_errors(self):
        cases = [
            ({"fial-on": "warning"}, "keys use dashes"),
            ({"heuristics": {"numeric-id-length": 8}}, "heuristics.*"),
            ({"fail-on": "never"}, "--fail-on never"),
            ({"fail-on": "sometimes"}, "error, warning or note"),
            ({"severity": {"leak.email": "loud"}}, "as the level"),
            ({"gitleaks": "maybe"}, '"auto"'),
            ({"disable": ["denylist"]}, "private denylist itself"),
            ({"severity": {"denylist": "note"}}, "private denylist itself"),
            ({"allow": [{"rules": ["denylist"], "paths": ["**"]}]}, "private denylist itself"),
            ({"disable": ["scan.incomplete"]}, "on the command line"),
            ({"allow": [{"rules": ["git.shallow-clone"]}]}, "on the command line"),
            ({"allow": [{"reason": "x"}]}, "at least one of"),
            ({"allow": [{"rules": ["leak.*"], "path": ["x"]}]}, "takes the keys"),
            ({"allow": [{"paths": ["/"]}]}, "'/'-only pattern"),
            ({"allow": [{"rules": ["leak.*"], "line": "(x"}]}, "public config"),
            ({"heuristics": {"internal-patterns": ["(x"]}}, "public config"),
            ({"heuristics": {"internal-patterns": ["x*"]}}, "matches everywhere"),
            ({"max-file-size": "huge"}, "64MiB"),
            ({"exclude": 3}, "Fix the value type"),
            ({"decode": "yes"}, "Fix the value type"),
            ({"max-archive-depth": -1}, "Fix the value type"),
            ({"heuristics": {"entropy-threshold": 9}}, "Fix the value type"),
            ({"heuristics": []}, "Fix the value type"),
            ({"severity": []}, "Fix the value type"),
            ({"allow": 3}, "Fix the value type"),
        ]
        for data, fragment in cases:
            with self.subTest(data=data):
                with self.assertRaises(ConfigError) as ctx:
                    apply_mapping(Settings(), data)
                fix = hint_for(str(ctx.exception))
                self.assertIsNotNone(fix, str(ctx.exception))
                self.assertIn(fragment, fix, str(ctx.exception))
        for bad in (["leak.email"], ["denylist:**"]):
            with self.subTest(allow=bad):
                with self.assertRaises(ConfigError) as ctx:
                    parse_cli_allow(bad)
                self.assertIsNotNone(hint_for(str(ctx.exception)))

    def test_troubleshooting_lists_the_same_errors(self):
        doc = (ROOT / "docs" / "troubleshooting.md").read_text(encoding="utf-8")
        for fragment in ("could not be read", "is not valid UTF-8", "invalid regular expression",
                         "pattern matches the empty string", "shorter than 3 characters", "unknown config key",
                         "can only be changed on the command line", "--fail-on never", "path not found",
                         "refused in CI", "must not be written inside a scanned tree", "--require-denylist",
                         "--history needs a git repository", "--git-files", "gitleaks was requested",
                         "gitleaks did not complete", "could not write the report", "readable by other users",
                         "No private denylist loaded", "config.denylist-in-tree", "git.shallow-clone",
                         "scan.incomplete", "git.author-identity", "GH007", "GH013", "GH006"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, doc)


class ReportFixesTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()

    def test_human_report_ends_with_a_fix_per_rule(self):
        self.write("tree/a.py", "LOG = '/Users/alice/x/y'\n")
        deny = self.denylist("Project Falcon\n  label: codename\n")
        self.write("tree/notes.md", "Project Falcon notes\n")
        res = run_cli("scan", "--denylist", str(deny), "--gitleaks", "never", "--no-external-tools", str(self.root),
                      cwd=self.root)
        self.assertEqual(res.code, 1)
        fixes = res.out.split("How to fix:\n", 1)[1]
        self.assertRegex(fixes, r"(?m)^  denylist +Remove or rename it\.")
        self.assertRegex(fixes, r"(?m)^  leak\.home-path  Use relative paths, ~, or an environment variable\.$")
        self.assertIn("docs/troubleshooting.md", fixes)
        self.assertNotIn("falcon", res.out.lower())
        quiet = run_cli("scan", "--denylist", str(deny), "--gitleaks", "never", "-q", str(self.root), cwd=self.root)
        self.assertNotIn("How to fix", quiet.out)

    def test_clean_report_has_no_fix_section(self):
        self.write("tree/a.txt", "hello\n")
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 0)
        self.assertNotIn("How to fix", res.out)

    def test_gitleaks_rules_have_a_fix(self):
        from collections import Counter

        from prepublish_audit.report import Report

        report = Report(findings=[], stats=None, roots=[], catalogue={}, suppressed=Counter())
        self.assertIn("Rotate the credential", report.remediation("gitleaks.generic-api-key"))
        self.assertEqual(report.remediation("unknown.rule"),
                         "See https://github.com/deegitech/prepublish-audit/blob/v0.1.0/docs/rules.md.")


class CliPrintsTheFixTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.write("tree/a.txt", "hello\n")

    def test_error_is_followed_by_its_fix(self):
        res = run_cli("scan", "--denylist", str(self.tmp / "missing.txt"), str(self.root), cwd=self.root)
        self.assertEqual(res.code, 2)
        lines = res.err.splitlines()
        self.assertTrue(lines[0].startswith("prepublish-audit: error: denylist 1 could not be read"))
        self.assertTrue(lines[1].startswith("prepublish-audit: fix: Check that the file named by --denylist"))

    def test_fix_does_not_leak_the_entry(self):
        bad = self.denylist("re:(Project Falcon\n")
        res = run_cli("check-denylist", str(bad))
        self.assertEqual(res.code, 2)
        self.assertIn("prepublish-audit: fix: Escape characters", res.err)
        self.assertNotIn("falcon", res.err.lower())

    @unittest.skipUnless(POSIX, "POSIX file permissions")
    def test_unreadable_denylist_and_a_folder_get_their_own_fix(self):
        folder = self.tmp / "_private"
        folder.mkdir()
        res = run_cli("check-denylist", str(folder))
        self.assertEqual(res.code, 2)
        self.assertIn("could not be read (Is a directory)", res.err)
        self.assertIn("prepublish-audit: fix: Pass the denylist file, not its folder", res.err)
        if os.geteuid() == 0:  # root reads any file
            return
        locked = self.denylist("Project Falcon\n")
        locked.chmod(0)
        res = run_cli("check-denylist", str(locked))
        self.assertEqual(res.code, 2)
        self.assertIn("could not be read (Permission denied)", res.err)
        self.assertIn("prepublish-audit: fix: As the file's owner, run chmod 600 FILE", res.err)

    def test_usage_errors_get_a_fix_line(self):
        for args, command in ((("scan", "--fail-on", "sometimes"), "prepublish-audit scan --help"),
                              (("doctor", "--frobnicate"), "prepublish-audit doctor --help"),
                              (("--fail-on", "sometimes", "."), "prepublish-audit scan --help")):
            with self.subTest(args=args):
                res = run_cli(*args, cwd=self.root)
                self.assertEqual(res.code, 2)
                self.assertIn("error:", res.err)
                self.assertEqual(res.err.splitlines()[-1],
                                 f"prepublish-audit: fix: run '{command}' to see the options and their values.")
        self.assertEqual(run_cli("--version").code, 0)

    def test_require_denylist_explains_ci(self):
        res = run_cli("scan", "--require-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 2)
        self.assertIn("environment:", res.err)

    @unittest.skipUnless(has_git(), "git")
    def test_history_outside_a_repository(self):
        res = run_cli("scan", "--no-denylist", "--history", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 2)
        self.assertIn("prepublish-audit: fix: Run it inside a git clone", res.err)

    @unittest.skipUnless(POSIX, "fake executables need a POSIX shell")
    def test_gitleaks_failure_note_carries_the_fix(self):
        bin_dir = self.tmp / "_bin"
        bin_dir.mkdir()
        fake = bin_dir / "gitleaks"
        fake.write_text(f"#!{PY}\n" + textwrap.dedent("""
            import sys
            if sys.argv[1:2] == ["version"]:
                print("8.30.1")
                sys.exit(0)
            sys.exit(3)
        """), encoding="utf-8")
        fake.chmod(0o755)
        res = run_cli("scan", "--no-denylist", "--no-external-tools", "-f", "json", str(self.root), cwd=self.root,
                      env={"PATH": str(bin_dir)})
        notes = json.loads(res.out)["notes"]
        self.assertTrue(any("gitleaks did not complete" in n and "Fix: Run 'gitleaks version'" in n for n in notes),
                        notes)
        res = run_cli("scan", "--no-denylist", "--gitleaks", "always", str(self.root), cwd=self.root,
                      env={"PATH": str(self.tmp / "empty-bin")})
        self.assertIn("prepublish-audit: fix: Install gitleaks", res.err)


if __name__ == "__main__":
    unittest.main()
