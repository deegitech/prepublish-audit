import json
import os
import stat
import subprocess
import sys
import unittest
from pathlib import Path

from .helpers import POSIX, PY, Fake, TempTestCase, run_cli, scan_json


class ExitCodeTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()

    def cli(self, *args, **kw):
        return run_cli(*args, **kw)

    def test_clean_tree_exits_zero(self):
        self.write("tree/a.txt", "hello\n")
        res = self.cli("scan", "--no-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 0, res.err)
        self.assertIn("PASSED", res.out)

    def test_findings_exit_one(self):
        self.write("tree/a.txt", "/Users/alice/x/y\n")
        res = self.cli("scan", "--no-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 1)
        self.assertIn("FAILED", res.out)

    def test_fail_on_levels(self):
        self.write("tree/a.txt", "/Users/alice/x/y\n")
        base = ("scan", "--no-denylist", "--gitleaks", "never")
        self.assertEqual(self.cli(*base, "--fail-on", "error", str(self.root), cwd=self.root).code, 0)
        self.assertEqual(self.cli(*base, "--fail-on", "never", str(self.root), cwd=self.root).code, 0)
        self.assertEqual(self.cli(*base, "--fail-on", "note", str(self.root), cwd=self.root).code, 1)

    def test_usage_errors_exit_two(self):
        self.assertEqual(self.cli("scan", str(self.tmp / "missing")).code, 2)
        self.assertEqual(self.cli("scan", "--fail-on", "sometimes", str(self.root)).code, 2)
        self.assertEqual(self.cli("scan", "--denylist", str(self.tmp / "nope.txt"), str(self.root)).code, 2)

    def test_scan_is_the_default_command(self):
        self.write("tree/a.txt", "hello\n")
        res = self.cli("--no-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 0)
        res = self.cli(cwd=self.root, env={"XDG_CONFIG_HOME": str(self.tmp / "empty")})
        self.assertIn(res.code, (0, 1))

    def test_version_and_help(self):
        res = self.cli("--version")
        self.assertEqual(res.code, 0)
        self.assertIn("prepublish-audit 0.1.0", res.out)
        self.assertEqual(self.cli("--help").code, 0)

    def test_module_entry_point(self):
        env = dict(os.environ)
        src = str(Path(__file__).resolve().parents[1] / "src")
        env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
        p = subprocess.run([PY, "-m", "prepublish_audit", "--version"], capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 0)
        self.assertIn("0.1.0", p.stdout)


class DenylistLocationTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.write("tree/a.txt", "Project Falcon\n")

    def test_env_var(self):
        deny = self.denylist("Project Falcon\n")
        res = run_cli("scan", "--gitleaks", "never", "-f", "json", str(self.root), cwd=self.root,
                      env={"PREPUBLISH_AUDIT_DENYLIST": str(deny)})
        self.assertEqual(json.loads(res.out)["scanned"]["denylist_entries"], 1)

    def test_default_location_and_opt_out(self):
        folder = self.home / ".config" / "prepublish-audit"
        folder.mkdir(parents=True)
        (folder / "denylist.txt").write_text("Project Falcon\n")
        (folder / "denylist.txt").chmod(0o600)
        report = json.loads(run_cli("scan", "--gitleaks", "never", "-f", "json", str(self.root), cwd=self.root).out)
        self.assertEqual(report["summary"]["error"], 1)
        report = json.loads(run_cli("scan", "--no-denylist", "--gitleaks", "never", "-f", "json", str(self.root),
                                    cwd=self.root).out)
        self.assertEqual(report["findings"], [])
        self.assertTrue(any("No private denylist" in n for n in report["notes"]))

    def test_require_denylist(self):
        res = run_cli("scan", "--require-denylist", "--gitleaks", "never", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 2)

    def test_an_empty_denylist_given_on_the_command_line_is_called_out(self):
        # For example --denylist <(pa_denylist) whose command failed: the pipe is empty.
        empty = self.denylist("# nothing yet\n")
        res = run_cli("scan", "--denylist", str(empty), "--gitleaks", "never", "-q", str(self.root), cwd=self.root)
        self.assertEqual(res.code, 0)
        self.assertIn("prepublish-audit: warning: the denylist given with --denylist has no entries", res.err)
        self.assertIn("add --require-denylist to stop instead", res.err)
        self.assertIn("Note: no private denylist entries were loaded", res.out)  # shown even with --quiet
        report = json.loads(run_cli("scan", "--denylist", str(empty), "--gitleaks", "never", "-f", "json",
                                    str(self.root), cwd=self.root).out)
        self.assertTrue(any(n.startswith("The private denylist has no entries") for n in report["notes"]))
        res = run_cli("scan", "--require-denylist", "--denylist", str(empty), "--gitleaks", "never", str(self.root),
                      cwd=self.root)
        self.assertEqual(res.code, 2)

    def test_check_denylist_never_prints_entries(self):
        deny = self.denylist("Project Falcon\n  label: codename\nre:\\bfalcon-\\d+\\b\nProject Falcon\n")
        res = run_cli("check-denylist", str(deny))
        self.assertEqual(res.code, 0)
        self.assertIn("2 entries", res.out)
        self.assertIn("duplicate", res.out)
        self.assertNotIn("Falcon", res.out)
        bad = self.denylist("re:(unclosed\n", name="bad.txt")
        res = run_cli("check-denylist", str(bad))
        self.assertEqual(res.code, 2)
        self.assertNotIn("unclosed", res.err)


class InitTests(TempTestCase):
    def test_init_creates_public_config_and_private_template(self):
        from prepublish_audit.cli import _toml_available

        work = self.tree("work")
        res = run_cli("init", cwd=work)
        self.assertEqual(res.code, 0, res.err)
        name = ".prepublish-audit.toml" if _toml_available() else ".prepublish-audit.json"
        self.assertTrue((work / name).is_file())
        private = self.home / ".config" / "prepublish-audit" / "denylist.txt"
        self.assertTrue(private.is_file())
        if POSIX:
            self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o600)
        self.assertNotIn(str(self.home), res.out)
        res = run_cli("init", cwd=work)
        self.assertIn("already exists", res.out)

    def test_init_names_the_real_location(self):
        work = self.tree("work")
        res = run_cli("init", cwd=work, env={"XDG_CONFIG_HOME": str(self.home / "cfg")})
        self.assertEqual(res.code, 0, res.err)
        self.assertTrue((self.home / "cfg" / "prepublish-audit" / "denylist.txt").is_file())
        self.assertIn("~/cfg/prepublish-audit/denylist.txt", res.out)

    def test_init_writes_json_when_toml_cannot_be_read(self):
        from unittest import mock

        work = self.tree("work")
        with mock.patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            res = run_cli("init", "--no-denylist", cwd=work)
            self.assertEqual(res.code, 0, res.err)
            self.assertTrue((work / ".prepublish-audit.json").is_file())
            self.assertFalse((work / ".prepublish-audit.toml").exists())
            self.assertIn("JSON", res.out)
            res = run_cli("scan", "--no-denylist", "--gitleaks", "never", str(work), cwd=work)
            self.assertEqual(res.code, 0, res.err)

    def test_generated_files_are_valid(self):
        work = self.tree("work")
        run_cli("init", cwd=work)
        res = run_cli("check-denylist")
        self.assertEqual(res.code, 1)  # the template only contains comments
        self.assertTrue(res.out.startswith("EMPTY: 0 entries in 1 file(s), so it protects nothing."), res.out)
        self.assertNotIn("OK:", res.out)
        try:
            import tomllib  # noqa: F401
        except ModuleNotFoundError:  # pragma: no cover
            self.skipTest("TOML parser not available")
        res = run_cli("scan", "--gitleaks", "never", str(work), cwd=work)
        self.assertEqual(res.code, 0, res.err)


class OptionTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.write("tree/docs/team.md", "alice.smith@acme-corp.io\n")
        self.write("tree/src/a.py", "LOG = '/Users/alice/x/y'\n")

    def test_allow_disable_and_exclude(self):
        report = scan_json(self.root, "--no-denylist", "--allow", "leak.email:docs/**")
        self.assertEqual([f["rule_id"] for f in report["findings"]], ["leak.home-path"])
        report = scan_json(self.root, "--no-denylist", "--disable", "leak.home-path", "--exclude", "docs")
        self.assertEqual(report["findings"], [])

    def test_cli_cannot_touch_the_denylist(self):
        self.assertEqual(run_cli("scan", "--disable", "denylist", str(self.root)).code, 2)
        self.assertEqual(run_cli("scan", "--allow", "denylist:**", str(self.root)).code, 2)

    def test_output_files(self):
        out = self.tmp / "report.sarif"
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "-f", "sarif", "-o", str(out), str(self.root),
                      cwd=self.root)
        self.assertEqual(res.code, 1)
        self.assertEqual(res.out, "")
        self.assertEqual(json.loads(out.read_text())["version"], "2.1.0")
        human = self.tmp / "report.txt"
        run_cli("scan", "--no-denylist", "--gitleaks", "never", "-o", str(human), str(self.root), cwd=self.root)
        self.assertIn("leak.home-path", human.read_text())
        self.assertNotIn("\x1b[", human.read_text())

    def test_color_and_quiet(self):
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "--color", "always", str(self.root), cwd=self.root)
        self.assertIn("\x1b[", res.out)
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "--color", "always", str(self.root),
                      cwd=self.root, env={"NO_COLOR": "1"})
        self.assertIn("\x1b[", res.out)  # --color always wins over NO_COLOR
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "-q", str(self.root), cwd=self.root)
        self.assertNotIn("Scanned:", res.out)

    def test_rules_command(self):
        res = run_cli("rules")
        self.assertIn("secret.github-token", res.out)
        data = json.loads(run_cli("rules", "--format", "json").out)
        self.assertTrue(any(r["id"] == "denylist" for r in data))
        self.assertIn("| [`leak.email`](#leakemail) |", run_cli("rules", "--format", "markdown").out)

    def test_multiple_roots_and_file_roots(self):
        other = self.tree("other")
        (other / "x.txt").write_text(f"token {Fake.github()}\n")
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "-f", "json", str(self.root / "src" / "a.py"),
                      str(other), cwd=self.tmp)
        data = json.loads(res.out)
        self.assertEqual(sorted(f["path"] for f in data["findings"]), ["other/x.txt", "tree/src/a.py"])


if __name__ == "__main__":
    unittest.main()
