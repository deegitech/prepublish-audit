import json
import unittest
import unicodedata

from prepublish_audit.config import Settings
from prepublish_audit.denylist import Denylist, DenylistError
from prepublish_audit.engine import Engine, markdown_sections

from .helpers import POSIX, TempTestCase


def hits(dl: Denylist, text: str):
    return [(e.number, text[s:e2]) for e, s, e2 in dl.find(text)]


class DenylistParsingTests(TempTestCase):
    def load(self, text: str, name: str = "deny.txt", **kw) -> Denylist:
        return Denylist.load([self.denylist(text, name)], **kw)

    def test_plain_literal_is_case_insensitive_substring(self):
        dl = self.load("Acme Internal\n")
        self.assertEqual(len(hits(dl, "see ACME internal docs")), 1)
        self.assertEqual(len(hits(dl, "acmeinternal")), 0)

    def test_whitespace_inside_a_literal_matches_wrapped_lines(self):
        dl = self.load("Project Falcon\n")
        self.assertEqual(len(hits(dl, "about Project\n  Falcon here")), 1)
        self.assertEqual(len(hits(dl, "Project\tFalcon")), 1)

    def test_regex_entry(self):
        dl = self.load("re:\\bacct-\\d{6,}\\b\n")
        self.assertEqual(hits(dl, "x acct-123456 y acct-12 z"), [(1, "acct-123456")])

    def test_word_entry_requires_boundaries(self):
        dl = self.load("word:4821\n")
        self.assertEqual(len(hits(dl, "card ending 4821.")), 1)
        self.assertEqual(len(hits(dl, "order 148210 and 4821x")), 0)

    def test_loose_entry_ignores_separators(self):
        dl = self.load("loose:project falcon\n")
        for text in ("project-falcon", "project_falcon", "projectfalcon", "PROJECT.FALCON", "Project  Falcon"):
            self.assertEqual(len(hits(dl, text)), 1, text)

    def test_loose_keeps_leading_and_trailing_separators(self):
        dl = self.load("loose:.secret-dir\n")
        self.assertEqual(len(hits(dl, "path/.secret_dir/x")), 1)
        self.assertEqual(len(hits(dl, "path/secretdir/x")), 0)

    def test_global_loose_option(self):
        dl = self.load("Project Falcon\n", loose=True)
        self.assertEqual(len(hits(dl, "project-falcon")), 1)

    def test_comments_blank_lines_and_lit_prefix(self):
        dl = self.load("# a comment\n\nlit:# hashed\nlit:re:not a regex\n")
        self.assertEqual(len(dl), 2)
        self.assertEqual(len(hits(dl, "x # hashed y")), 1)
        self.assertEqual(len(hits(dl, "it said re:not a regex")), 1)

    def test_labels_and_allow_directives(self):
        dl = self.load("Acme Corp\n  label: company name\n  allow: LICENSE\n  allow: README.md section=^About line=Built\n")
        entry = dl.entries[0]
        self.assertEqual(entry.label, "company name")
        self.assertEqual(len(entry.allow), 2)
        self.assertEqual(entry.allow[1].section, "^About")
        self.assertEqual(entry.allow[1].line, "Built")
        self.assertEqual(str(entry), "company name")

    def test_default_label_names_the_line_not_the_entry(self):
        dl = self.load("# header\nSecret Codename\n")
        self.assertEqual(dl.entries[0].label, "entry 1 (line 2)")
        self.assertNotIn("Codename", repr(dl.entries[0]))

    def test_directive_without_entry_is_an_error(self):
        with self.assertRaises(DenylistError):
            self.load("  allow: LICENSE\nAcme\n")

    def test_bad_allow_option(self):
        with self.assertRaises(DenylistError):
            self.load("Acme Corp\n  allow: README.md nonsense\n")

    def test_short_entries_are_rejected_without_echoing_them(self):
        with self.assertRaises(DenylistError) as ctx:
            self.load("ok entry\nzq\n")
        self.assertIn("line 2", str(ctx.exception))
        self.assertNotIn("zq", str(ctx.exception))

    def test_invalid_regex_error_does_not_echo_the_pattern(self):
        with self.assertRaises(DenylistError) as ctx:
            self.load("re:topsecretname(\n")
        self.assertNotIn("topsecretname", str(ctx.exception))
        self.assertIn("line 1", str(ctx.exception))

    def test_regex_matching_empty_string_is_rejected(self):
        with self.assertRaises(DenylistError):
            self.load("re:x*\n")

    def test_duplicates_are_reported_as_warnings(self):
        dl = self.load("Acme Corp\nACME CORP\n")
        self.assertEqual(len(dl), 1)
        self.assertTrue(any("duplicate" in w for w in dl.warnings))

    def test_three_character_entries_warn(self):
        dl = self.load("abc\n")
        self.assertTrue(any("noisy" in w for w in dl.warnings))

    def test_json_format(self):
        data = {"entries": ["Acme Internal", {"regex": "\\bfalcon-\\d+\\b", "label": "codenames"},
                            {"literal": "Acme Corp", "allow": [{"path": "LICENSE"}]}]}
        dl = self.load(json.dumps(data), name="deny.json")
        self.assertEqual(len(dl), 3)
        self.assertEqual(dl.entries[1].label, "codenames")
        self.assertEqual(dl.entries[2].allow[0].path, "LICENSE")

    def test_toml_format(self):
        try:
            import tomllib  # noqa: F401
        except ModuleNotFoundError:  # pragma: no cover - Python 3.10 without tomli
            try:
                import tomli  # noqa: F401
            except ModuleNotFoundError:
                self.skipTest("no TOML parser")
        text = ('[[entries]]\nliteral = "Acme Corp"\nlabel = "company"\n'
                'allow = [{ path = "LICENSE" }, { path = "README.md", section = "^About" }]\n'
                '[[entries]]\nloose = "project falcon"\n')
        dl = self.load(text, name="deny.toml")
        self.assertEqual([e.kind for e in dl.entries], ["literal", "loose"])
        self.assertEqual(dl.entries[0].allow[1].section, "^About")

    def test_structured_format_validation(self):
        with self.assertRaises(DenylistError):
            self.load(json.dumps({"entries": [{"literal": "a b c", "regex": "x"}]}), name="d.json")
        with self.assertRaises(DenylistError):
            self.load(json.dumps({"entries": [{"literal": "abc", "colour": "red"}]}), name="d.json")
        with self.assertRaises(DenylistError):
            self.load(json.dumps({"rows": []}), name="d.json")
        with self.assertRaises(DenylistError):
            self.load("{not json", name="d.json")

    @unittest.skipUnless(POSIX, "POSIX permissions")
    def test_group_or_world_readable_file_warns(self):
        path = self.denylist("Acme Internal\n")
        self.assertFalse(Denylist.load([path]).warnings)
        path.chmod(0o644)
        self.assertTrue(any("chmod 600" in w for w in Denylist.load([path]).warnings))

    def test_unreadable_file(self):
        with self.assertRaises(DenylistError) as ctx:
            Denylist.load([self.tmp / "missing.txt"])
        self.assertIn("denylist 1", str(ctx.exception))

    def test_structured_errors_never_echo_keys(self):
        """A mapping written as {"<entry>": "<label>"} must not print the entries."""
        cases = {
            "top.json": json.dumps({"Acme Corp": "company", "Project Falcon": "codename"}),
            "entry.json": json.dumps({"entries": [{"literal": "abc def", "Acme Corp": "x"}]}),
            "allow.json": json.dumps({"entries": [{"literal": "abc def", "allow": [{"path": "x", "Acme Corp": "y"}]}]}),
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(DenylistError) as ctx:
                self.load(text, name=name)
            self.assertNotIn("acme", str(ctx.exception).lower())
            self.assertNotIn("falcon", str(ctx.exception).lower())
            self.assertIn("unknown", str(ctx.exception))

    def test_toml_mapping_errors_never_echo_keys(self):
        try:
            import tomllib  # noqa: F401
        except ModuleNotFoundError:  # pragma: no cover - Python 3.10 without tomli
            try:
                import tomli  # noqa: F401
            except ModuleNotFoundError:
                self.skipTest("no TOML parser")
        with self.assertRaises(DenylistError) as ctx:
            self.load('"Acme Corp" = "company"\n', name="deny.toml")
        self.assertNotIn("acme", str(ctx.exception).lower())

    def test_regex_errors_never_quote_the_pattern(self):
        for text in ("re:(?P=falconsecret)\n", "re:falcon\\q\n", "re:(?P<falcon-x>a)\n", "re:[z-a]falcon\n",
                     "Acme Corp\n  allow: README.md line=(?P=falconsecret)\n"):
            with self.subTest(text), self.assertRaises(DenylistError) as ctx:
                self.load(text)
            self.assertNotIn("falcon", str(ctx.exception).lower())
            self.assertIn("line", str(ctx.exception))

    def test_turkish_letters_match_case_insensitively(self):
        cases = [("Yıldız", "YILDIZ"), ("yildiz", "Yıldız"), ("İzmir", "izmir"), ("İzmir", "IZMIR"),
                 ("Işık", "IŞIK"), ("izmir", "İZMİR'de"), ("Şeker", "ŞEKER"), ("ÇAĞRI", "çağrı")]
        for entry, text in cases:
            with self.subTest(entry=entry, text=text):
                dl = self.load(f"{entry}\n")
                self.assertEqual(len(hits(dl, f"see {text} here")), 1)

    def test_fast_path_agrees_with_the_regex_engine(self):
        import random
        import re

        rng = random.Random(7)
        alphabet = "abcIiİıSsſKkK xyzÇçŞş"
        for _ in range(300):
            entry = "".join(rng.choice("abcIiSsKk") for _ in range(3))
            text = "".join(rng.choice(alphabet) for _ in range(40))
            dl = Denylist()
            from prepublish_audit.denylist import Entry, _compile
            e = Entry(number=1, kind="literal", value=entry)
            _compile(e, "test")
            dl.entries.append(e)
            expected = [(m.start(), m.end()) for m in re.finditer(re.escape(entry), text, re.IGNORECASE)]
            got = [(s, t) for _, s, t in dl.find(text)]
            self.assertEqual(got, expected, (entry, text))

    def test_lowercasing_that_changes_length_still_matches(self):
        dl = self.load("falcon\n")
        text = "İNFO desk, falcon here"
        self.assertNotEqual(len(text.lower()), len(text))
        self.assertEqual(hits(dl, text), [(1, "falcon")])

    def test_mask_replaces_matches(self):
        dl = self.load("falcon\n")
        self.assertEqual(dl.mask("docs/falcon-plan.md"), "docs/***-plan.md")

    def test_multiple_files_number_entries_across_files(self):
        a = self.denylist("Acme Internal\n", "a.txt")
        b = self.denylist("Falcon Plan\n", "b.txt")
        dl = Denylist.load([a, b])
        self.assertEqual([e.number for e in dl.entries], [1, 2])
        self.assertIn("denylist 2", dl.entries[1].label)


class EngineAllowTests(TempTestCase):
    def engine(self, deny: str) -> Engine:
        return Engine(Settings(), Denylist.load([self.denylist(deny)]))

    def scan(self, eng: Engine, text: str, path: str):
        return eng.scan_text(text, target="text", match_path=path, display=path, origin="file")

    def test_path_allow_context(self):
        eng = self.engine("Acme Corp\n  allow: LICENSE\n")
        self.assertEqual(self.scan(eng, "Copyright Acme Corp", "LICENSE"), [])
        self.assertEqual(len(self.scan(eng, "Copyright Acme Corp", "src/app.py")), 1)
        self.assertEqual(eng.suppressed["denylist"], 1)

    def test_section_allow_context(self):
        eng = self.engine("Acme Corp\n  allow: README.md section=^About\n")
        text = ("# Tool\n\nAcme Corp in the intro.\n\n## About\n\nBuilt by Acme Corp.\n\n### Credits\n\n"
                "Acme Corp again.\n\n```\n# not a heading\nAcme Corp in code\n```\n\nUsage\n-----\n\nAcme Corp in usage.\n")
        found = self.scan(eng, text, "README.md")
        lines = sorted(f.line for f in found)
        self.assertEqual(lines, [3, 21])

    def test_section_allow_only_applies_to_markdown(self):
        eng = self.engine("Acme Corp\n  allow: notes.txt section=^About\n")
        self.assertEqual(len(self.scan(eng, "# About\nAcme Corp\n", "notes.txt")), 1)

    def test_line_allow_context(self):
        eng = self.engine("Acme Corp\n  allow: **/*.py line=^# Copyright\n")
        found = self.scan(eng, "# Copyright 2026 Acme Corp\nname = 'Acme Corp'\n", "src/a.py")
        self.assertEqual([f.line for f in found], [2])

    def test_inline_pragma_never_suppresses_the_denylist(self):
        eng = self.engine("Acme Corp\n")
        found = self.scan(eng, "x = 'Acme Corp'  # prepublish-audit:allow\n", "a.py")
        self.assertEqual([f.rule_id for f in found], ["denylist"])

    def test_decoded_views(self):
        import base64
        import urllib.parse

        eng = self.engine("Project Falcon\n")
        b64 = base64.b64encode(b"connect: project falcon database").decode()
        pct = urllib.parse.quote("Project Falcon", safe="")
        ent = "".join(f"&#{ord(c)};" for c in "Project Falcon")
        uesc = "".join(f"\\u{ord(c):04x}" for c in "Project Falcon")
        text = f"a = '{b64}'\nb = '{pct}'\nc = '{ent}'\nd = \"{uesc}\"\n"
        found = self.scan(eng, text, "cfg.py")
        details = sorted((f.line, f.detail) for f in found)
        self.assertEqual([d[0] for d in details], [1, 2, 3, 4])
        joined = " ".join(d[1] for d in details)
        for kind in ("base64", "percent", "HTML-entity", "unicode-escape"):
            self.assertIn(kind, joined)

    def test_unicode_normalisation(self):
        eng = self.engine("Şeker Ltd\n")
        nfd = unicodedata.normalize("NFD", "the Şeker Ltd team")
        found = self.scan(eng, nfd, "a.md")
        self.assertEqual(len(found), 1)

    def test_denylist_subsumes_overlapping_heuristics(self):
        eng = self.engine("alice@acme-corp.io\n")
        found = self.scan(eng, "contact = 'alice@acme-corp.io'\n", "a.py")
        self.assertEqual([f.rule_id for f in found], ["denylist"])


class MarkdownSectionTests(unittest.TestCase):
    def test_atx_setext_and_fences(self):
        text = "# A\nx\n## B\ny\n```\n# fake\n```\nC title\n=======\nz\n"
        secs = markdown_sections(text)
        self.assertEqual(secs[2], ("A",))
        self.assertEqual(secs[4], ("A", "B"))
        self.assertEqual(secs[6], ("A", "B"))
        self.assertEqual(secs[8], ("C title",))
        self.assertEqual(secs[10], ("C title",))


if __name__ == "__main__":
    unittest.main()
