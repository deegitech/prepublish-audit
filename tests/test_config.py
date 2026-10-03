import sys
import unittest
from unittest import mock

from prepublish_audit import tomlcompat
from prepublish_audit.config import ConfigError, Settings, apply_mapping, discover, load_settings
from prepublish_audit.globs import GlobSet, compile_glob, glob_match
from prepublish_audit.util import is_placeholder, parse_size, shannon_entropy

from .helpers import TempTestCase


class SettingsTests(unittest.TestCase):
    def test_kebab_and_snake_case(self):
        s = apply_mapping(Settings(), {"fail-on": "error", "max_file_size": "2MiB",
                                       "heuristics": {"numeric-id-min-length": 8, "allowed_emails": ["a@b.io"]}})
        self.assertEqual(s.fail_on, "error")
        self.assertEqual(s.max_file_size, 2 * 1024 * 1024)
        self.assertEqual(s.numeric_id_min_length, 8)
        self.assertIn("a@b.io", s.allowed_emails)
        self.assertIn("git@github.com", s.allowed_emails)  # defaults are extended, not replaced

    def test_unknown_keys_are_errors(self):
        for bad in ({"fail_onn": "error"}, {"heuristics": {"numeric_min": 3}}, {"allow": [{"rule": ["x"]}]}):
            with self.subTest(bad), self.assertRaises(ConfigError):
                apply_mapping(Settings(), bad)

    def test_invalid_values(self):
        for bad in ({"fail-on": "always"}, {"max-file-size": "lots"}, {"heuristics": {"entropy-threshold": 12}},
                    {"heuristics": {"numeric-id-min-length": 3}}, {"gitleaks": "maybe"},
                    {"heuristics": {"internal-patterns": ["(unclosed"]}},
                    {"heuristics": {"internal-patterns": ["x*"]}}, {"decode": "yes"}):
            with self.subTest(bad), self.assertRaises(ConfigError):
                apply_mapping(Settings(), bad)

    def test_public_config_cannot_weaken_the_denylist(self):
        for bad in ({"disable": ["denylist"]}, {"severity": {"denylist": "note"}},
                    {"allow": [{"rules": ["denylist"], "paths": ["**"]}]}):
            with self.subTest(bad), self.assertRaises(ConfigError):
                apply_mapping(Settings(), bad)

    def test_wildcards_only_touch_builtin_rules(self):
        s = apply_mapping(Settings(), {"allow": [{"rules": ["*"], "paths": ["tests/**"]}], "disable": ["leak.*"]})
        self.assertTrue(s.is_allowed("leak.email", "tests/a.py", "", ""))
        self.assertTrue(s.rule_disabled("leak.email"))

    def test_public_config_cannot_touch_coverage_rules(self):
        for bad in ({"disable": ["scan.incomplete"]}, {"disable": ["scan.*"]}, {"severity": {"scan.incomplete": "note"}},
                    {"allow": [{"rules": ["scan.*"], "paths": ["**"]}]}, {"disable": ["git.shallow-clone"]},
                    {"disable": ["config.*"]}, {"fail-on": "never"}):
            with self.subTest(bad), self.assertRaises(ConfigError):
                apply_mapping(Settings(), bad)
        s = apply_mapping(Settings(), {"disable": ["*"], "severity": {"*": "note"},
                                       "allow": [{"rules": ["*"], "paths": ["**"]}]})
        for rid in ("scan.incomplete", "git.shallow-clone", "config.denylist-in-tree"):
            with self.subTest(rid):
                self.assertFalse(s.rule_disabled(rid))
                self.assertFalse(s.is_allowed(rid, "a.txt", None, None))
                self.assertEqual(s.severity_for(rid, "warning"), "warning")
        self.assertTrue(s.rule_disabled("leak.email"))

    def test_command_line_can_touch_coverage_rules(self):
        from prepublish_audit.config import AllowRule

        s = Settings()
        s.cli_disable.append("scan.incomplete")
        s.allow.append(AllowRule(rules=["git.shallow-clone"], paths=None, cli=True))
        self.assertTrue(s.rule_disabled("scan.incomplete"))
        self.assertTrue(s.is_allowed("git.shallow-clone", None, None, None))

    def test_narrowing_values_are_not_applied_with_a_denylist(self):
        s = apply_mapping(Settings(), {"max-file-size": "1", "max-archive-size": "1KiB", "max-archive-depth": 0,
                                       "decode": False, "archives": False, "external-tools": False})
        ignored = s.keep_denylist_coverage()
        self.assertEqual(sorted(ignored), ["archives", "decode", "external-tools", "max-archive-depth",
                                           "max-archive-size", "max-file-size"])
        defaults = Settings()
        for key in ("max_file_size", "max_archive_size", "max_archive_depth", "decode", "archives", "external_tools"):
            self.assertEqual(getattr(s, key), getattr(defaults, key), key)
        # Raising a limit is fine, and the command line always wins.
        s = apply_mapping(Settings(), {"max-file-size": "64MiB", "decode": False})
        s.cli_keys.add("decode")
        self.assertEqual(s.keep_denylist_coverage(), [])
        self.assertEqual(s.max_file_size, 64 * 1024 * 1024)
        self.assertFalse(s.decode)

    def test_allow_rule_needs_a_condition(self):
        with self.assertRaises(ConfigError):
            apply_mapping(Settings(), {"allow": [{"reason": "everything"}]})

    def test_allow_rule_matching(self):
        s = apply_mapping(Settings(), {"allow": [{"rules": ["leak.email"], "values": ["Press@Acme.io"]},
                                                 {"rules": ["leak.numeric-id"], "line": "^PHONE"}]})
        self.assertTrue(s.is_allowed("leak.email", "x", "", "press@acme.io"))
        self.assertFalse(s.is_allowed("leak.email", "x", "", "other@acme.io"))
        self.assertTrue(s.is_allowed("leak.numeric-id", "x", "PHONE = 4829173650", "4829173650"))

    def test_internal_patterns(self):
        s = apply_mapping(Settings(), {"heuristics": {"internal-patterns": [
            "(?i)\\bproject-[a-z]+\\b", {"pattern": "\\bops-[0-9]+\\b", "label": "tickets"}]}})
        self.assertEqual([p.label for p in s.internal_patterns], ["internal pattern 1", "tickets"])


class DiscoveryTests(TempTestCase):
    def test_discovery_order_and_boundaries(self):
        repo = self.tree("repo")
        (repo / ".git").mkdir()
        sub = repo / "site" / "dist"
        sub.mkdir(parents=True)
        self.assertIsNone(discover(sub))
        (repo / "pyproject.toml").write_text('[project]\nname = "x"\n')
        self.assertIsNone(discover(sub))
        (repo / "pyproject.toml").write_text('[tool.prepublish-audit]\nfail-on = "error"\n')
        self.assertEqual(discover(sub), (repo / "pyproject.toml").resolve())
        (repo / ".prepublish-audit.json").write_text("{}")
        self.assertEqual(discover(sub), (repo / ".prepublish-audit.json").resolve())

    def test_load_toml_from_pyproject(self):
        try:
            import tomllib  # noqa: F401
        except ModuleNotFoundError:  # pragma: no cover
            self.skipTest("no tomllib")
        root = self.tree()
        (root / "pyproject.toml").write_text('[tool.prepublish-audit]\nfail-on = "error"\nexclude = ["dist/**"]\n')
        s = load_settings(None, discover_from=root)
        self.assertEqual(s.fail_on, "error")
        self.assertEqual(s.exclude, ["dist/**"])
        self.assertEqual(s.base_dir, root.resolve())

    def test_invalid_files(self):
        root = self.tree()
        (root / ".prepublish-audit.json").write_text("{oops")
        with self.assertRaises(ConfigError):
            load_settings(None, discover_from=root)
        (root / ".prepublish-audit.json").write_text("[1, 2]")
        with self.assertRaises(ConfigError):
            load_settings(None, discover_from=root)

    def test_python_310_without_tomli_gets_a_clear_message(self):
        with mock.patch.dict(sys.modules, {"tomllib": None, "tomli": None}):
            with self.assertRaises(tomlcompat.TomlUnavailable) as ctx:
                tomlcompat.loads("a = 1")
        self.assertIn("prepublish-audit[toml]", str(ctx.exception))


class GlobTests(unittest.TestCase):
    def test_semantics(self):
        cases = [
            ("LICENSE", "LICENSE", True), ("LICENSE", "sub/LICENSE", True), ("/LICENSE", "sub/LICENSE", False),
            ("*.md", "docs/a.md", True), ("docs/*.md", "docs/a.md", True), ("docs/*.md", "docs/x/a.md", False),
            ("docs/**", "docs/x/y/z.txt", True), ("**/fixtures/*.json", "a/b/fixtures/c.json", True),
            ("**/fixtures/*.json", "fixtures/c.json", True), ("node_modules", "a/node_modules/b/c.js", True),
            ("build/", "build/out.js", True), ("a?c.txt", "abc.txt", True), ("[ab].txt", "c.txt", False),
            ("[!ab].txt", "c.txt", True), ("*.zip", "dist/x.zip/inner.txt", True),
        ]
        for pattern, path, expected in cases:
            with self.subTest(pattern=pattern, path=path):
                self.assertEqual(glob_match(pattern, path), expected)

    def test_globset_and_errors(self):
        gs = GlobSet(["*.md", "", "docs/**"])
        self.assertEqual(len(gs), 2)
        self.assertTrue(gs.match("README.md"))
        with self.assertRaises(ValueError):
            compile_glob("  ")


class UtilTests(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(parse_size(10), 10)
        self.assertEqual(parse_size("1KB"), 1000)
        self.assertEqual(parse_size("1 KiB"), 1024)
        self.assertEqual(parse_size("1.5MiB"), int(1.5 * 1024 * 1024))
        for bad in ("-1", "ten", True, 1.5, "3 parsecs"):
            with self.subTest(bad), self.assertRaises(ValueError):
                parse_size(bad)

    def test_entropy_and_placeholders(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertAlmostEqual(shannon_entropy("abcd"), 2.0)
        for value in ("your-token-here", "xxxxxxxxxxxx", "<TOKEN>", "${TOKEN}", "123456789012", "sk_live_00000000"):
            with self.subTest(value):
                self.assertTrue(is_placeholder(value))
        self.assertFalse(is_placeholder("q8Zt3LmV0pXa9Rk2"))


if __name__ == "__main__":
    unittest.main()
