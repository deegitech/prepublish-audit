"""Repository-level checks: generated docs are current, docs cover the CLI, and the repo passes its own audit."""

import json
import os
import re
import unittest
from pathlib import Path

from prepublish_audit.cli import build_parser, rules_markdown
from prepublish_audit.config import Settings
from prepublish_audit.rules import catalogue

from .helpers import TempTestCase, run_cli

ROOT = Path(__file__).resolve().parents[1]


class DocsTests(unittest.TestCase):
    def test_rules_reference_is_up_to_date(self):
        items = sorted(catalogue(Settings()).values(), key=lambda r: r.id)
        self.assertEqual((ROOT / "docs" / "rules.md").read_text(encoding="utf-8"), rules_markdown(items),
                         "run: prepublish-audit rules --format markdown > docs/rules.md")

    def test_readme_documents_every_option_and_config_key(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        parser = build_parser()
        sub = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
        options = set()
        for name, p in sub.choices.items():
            self.assertIn(f"prepublish-audit {name}" if name != "scan" else "prepublish-audit [scan]", readme)
            for action in p._actions:
                options.update(o for o in action.option_strings if o.startswith("--"))
        missing = sorted(o for o in options if o not in readme)
        self.assertEqual(missing, [], "README misses options")
        for key in ("fail-on", "exclude", "default-excludes", "max-file-size", "max-archive-size", "max-archive-depth",
                    "disable", "severity", "[[allow]]", "loose-denylist", "decode", "archives", "external-tools",
                    "gitleaks", "numeric-id-min-length", "allowed-email-domains", "allowed-emails", "allowed-numbers",
                    "allowed-hosts", "allowed-ips", "allowed-home-users", "git-identity-domains", "git-identity-emails",
                    "entropy-threshold", "entropy-min-length", "internal-patterns"):
            self.assertIn(key, readme, key)

    def test_every_option_has_help(self):
        parser = build_parser()
        sub = next(a for a in parser._actions if a.__class__.__name__ == "_SubParsersAction")
        for name, p in sub.choices.items():
            for action in p._actions:
                with self.subTest(command=name, option=action.dest):
                    self.assertTrue(action.help, f"{name} {action.option_strings or action.dest} has no help")

    def test_action_inputs_are_defined_and_documented(self):
        action = (ROOT / "action.yml").read_text(encoding="utf-8")
        block = action.split("\ninputs:\n", 1)[1].split("\noutputs:\n", 1)[0]
        defined = set(re.findall(r"^  ([a-z][a-z-]*):\s*$", block, re.MULTILINE))
        used = set(re.findall(r"\$\{\{ inputs\.([a-z-]+) \}\}", action))
        self.assertEqual(used, defined)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for name in defined:
            self.assertIn(f"`{name}`", readme)
        script = (ROOT / "scripts" / "github-action.sh").read_text(encoding="utf-8")
        self.assertNotIn("${{", script)  # inputs reach the script only as environment variables

    def test_pre_commit_hooks(self):
        hooks = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        self.assertIn("- id: prepublish-audit\n", hooks)
        self.assertIn("- id: prepublish-audit-history\n", hooks)
        self.assertIn("entry: prepublish-audit scan", hooks)

    def test_workflows_pin_actions_to_commits(self):
        for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")) + [ROOT / "examples" / "github-workflow.yml"]:
            for ref in re.findall(r"uses:\s*([^\s#]+)", wf.read_text(encoding="utf-8")):
                if ref.startswith("./") or ref.startswith("deegitech/prepublish-audit@"):
                    continue
                with self.subTest(workflow=wf.name, ref=ref):
                    self.assertRegex(ref, r"@[0-9a-f]{40}$")

    def test_version_is_consistent(self):
        from prepublish_audit import __version__

        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn(f'version = "{__version__}"', pyproject)
        self.assertIn(f"## [{__version__}]", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))


def _toml_available() -> bool:
    try:
        import tomllib  # noqa: F401
    except ModuleNotFoundError:
        try:
            import tomli  # noqa: F401
        except ModuleNotFoundError:
            return False
    return True


class SelfAuditTests(TempTestCase):
    @unittest.skipUnless(_toml_available(), "the repository config is TOML (Python 3.10 needs tomli)")
    def test_repository_passes_its_own_audit(self):
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "--no-external-tools", "-f", "json",
                      str(ROOT), cwd=ROOT)
        report = json.loads(res.out)
        self.assertEqual(report["findings"], [], json.dumps(report["findings"], indent=1)[:2000])
        self.assertEqual(res.code, 0)



@unittest.skipUnless(os.name == "posix" and __import__("shutil").which("bash"), "needs bash")
class ActionScriptTests(TempTestCase):
    """Run scripts/github-action.sh the way the composite action does, with a fake runner environment."""

    def run_action(self, **inputs):
        import subprocess

        runner = self.tmp / "runner"
        runner.mkdir(exist_ok=True)
        env = dict(os.environ)
        env.update({
            "RUNNER_TEMP": str(runner),
            "GITHUB_OUTPUT": str(self.tmp / "outputs.txt"),
            "GITHUB_STEP_SUMMARY": str(self.tmp / "summary.md"),
            "PA_ACTION_PATH": str(ROOT),
            "PA_PATH": "tree",
            "PA_HISTORY": "false",
            "PA_GITLEAKS": "never",
            "PA_ARGS": "--no-external-tools",
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        env.update(inputs)
        p = subprocess.run(["bash", str(ROOT / "scripts" / "github-action.sh")], cwd=self.tmp, env=env,
                           capture_output=True, text=True)
        return p, runner

    def test_findings_outputs_and_cleanup(self):
        self.write("tree/notes.txt", "The Project Falcon plan\n")
        sarif = self.tmp / "out.sarif"
        p, runner = self.run_action(PA_DENYLIST="Project Falcon\n  label: codename", PA_SARIF=str(sarif))
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("::error file=tree/notes.txt,line=1", p.stdout)
        self.assertNotIn("Falcon", p.stdout + p.stderr)
        outputs = (self.tmp / "outputs.txt").read_text()
        self.assertIn("exit-code=1", outputs)
        self.assertIn("findings=1", outputs)
        self.assertEqual(list(runner.iterdir()), [], "the private temp directory must be removed")
        self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
        self.assertNotIn("Falcon", (self.tmp / "summary.md").read_text())

    def test_repository_config_decides_fail_on_by_default(self):
        self.write("tree/notes.txt", "/Users/alice/x/y\n")
        self.write("tree/.prepublish-audit.json", '{"fail-on": "error"}')
        p, _ = self.run_action(PA_DENYLIST="")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        p, _ = self.run_action(PA_DENYLIST="", PA_FAIL_ON="warning")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)

    def test_missing_denylist(self):
        self.write("tree/notes.txt", "nothing here\n")
        p, _ = self.run_action(PA_DENYLIST="")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("::warning title=prepublish-audit::No denylist", p.stdout)
        p, _ = self.run_action(PA_DENYLIST="", PA_REQUIRE_DENYLIST="true")
        self.assertEqual(p.returncode, 2)
        self.assertIn("::error", p.stdout)
        # A secret with no entries is no denylist either.
        p, _ = self.run_action(PA_DENYLIST="# only a comment", PA_REQUIRE_DENYLIST="true")
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertIn("no denylist entries were loaded", p.stderr)


if __name__ == "__main__":
    unittest.main()
