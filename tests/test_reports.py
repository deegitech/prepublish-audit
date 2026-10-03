import json
import os
import re
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from prepublish_audit.findings import Finding, assign_fingerprints
from prepublish_audit.report import _gh_data, _gh_prop

from . import builders as B
from .helpers import Fake, TempTestCase, commit_all, has_git, init_repo, run_cli

SECRET_WORDS = ("Project Falcon", "Secret Partner Ltd")


class RedactionTests(TempTestCase):
    """Nothing private may reach a report unless --reveal is given."""

    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.deny = self.denylist("Project Falcon\nSecret Partner Ltd\n  label: partner\n")
        self.token = Fake.github()
        self.key = Fake.aws_key_id()
        self.write("tree/src/config.py", f'TOKEN = "{self.token}"\nAWS = "{self.key}"\n# Project Falcon\n')
        self.write("tree/docs/Secret Partner Ltd/deal.md", "contract with Secret Partner Ltd\n")
        self.write("tree/notes.txt", "mail jane.roe@acme-corp.io from /Users/jane/dev\n")
        self.private_values = [self.token, self.key, *SECRET_WORDS, "jane.roe@acme-corp.io", "/Users/jane"]

    def run_format(self, fmt: str, *extra: str):
        return run_cli("scan", "--format", fmt, "--denylist", str(self.deny), "--gitleaks", "never",
                       "--no-external-tools", *extra, str(self.root), cwd=self.root)

    def assertNoPrivateValues(self, text: str, where: str):
        for value in self.private_values:
            self.assertNotIn(value.lower(), text.lower(), f"{where} leaked a private value")

    def test_every_format_is_redacted(self):
        summary = self.tmp / "summary.md"
        sarif = self.tmp / "out.sarif"
        out_json = self.tmp / "out.json"
        for fmt in ("human", "json", "sarif", "github"):
            with self.subTest(fmt):
                res = self.run_format(fmt, "--summary-markdown", str(summary), "--sarif-output", str(sarif),
                                      "--json-output", str(out_json))
                self.assertEqual(res.code, 1, res.err)
                self.assertNoPrivateValues(res.out + res.err, fmt)
        self.assertNoPrivateValues(summary.read_text(), "markdown summary")
        self.assertNoPrivateValues(out_json.read_text(), "json output")

    def test_sarif_masks_paths_unless_asked(self):
        res = self.run_format("sarif")
        self.assertNoPrivateValues(res.out, "sarif")
        data = json.loads(res.out)
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in data["runs"][0]["results"]}
        self.assertIn("docs/***/deal.md", uris)
        self.assertTrue(data["runs"][0]["properties"]["pathsMasked"])
        res = self.run_format("sarif", "--sarif-real-paths")
        data = json.loads(res.out)
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in data["runs"][0]["results"]}
        self.assertIn("docs/Secret%20Partner%20Ltd/deal.md", uris)
        texts = json.dumps([r["message"] for r in data["runs"][0]["results"]])
        self.assertNoPrivateValues(texts, "sarif messages")

    def test_reveal_shows_values_locally(self):
        res = self.run_format("json", "--reveal")
        data = json.loads(res.out)
        matches = {f.get("match") for f in data["findings"]}
        self.assertIn(self.token, matches)
        self.assertFalse(data["redacted"])
        human = self.run_format("human", "--reveal")
        self.assertIn(self.token, human.out)

    def test_reveal_is_refused_in_ci(self):
        res = run_cli("scan", "--reveal", "--no-denylist", "--gitleaks", "never", str(self.root), cwd=self.root,
                      env={"CI": "true"})
        self.assertEqual(res.code, 2)
        self.assertIn("refused in CI", res.err)
        res = run_cli("scan", "--reveal", "--no-denylist", "--gitleaks", "never", "-f", "json", str(self.root),
                      cwd=self.root, env={"CI": "true", "PREPUBLISH_AUDIT_ALLOW_REVEAL": "1"})
        self.assertEqual(res.code, 1)
        for var, value in (("JENKINS_URL", "https://ci.example.com/"), ("TEAMCITY_VERSION", "2026.1"),
                           ("CODEBUILD_BUILD_ID", "build:1"), ("DRONE", "true")):
            with self.subTest(var):
                res = run_cli("scan", "--reveal", "--no-denylist", "--gitleaks", "never", str(self.root),
                              cwd=self.root, env={var: value})
                self.assertEqual(res.code, 2)

    def test_reveal_output_inside_the_tree_is_refused(self):
        res = self.run_format("json", "--reveal", "--output", str(self.root / "report.json"))
        self.assertEqual(res.code, 2)
        self.assertFalse((self.root / "report.json").exists())

    @unittest.skipUnless(has_git(), "git")
    def test_history_reports_are_redacted(self):
        repo = init_repo(self.tmp / "repo")
        self.write("repo/a.txt", f"{self.token}\nProject Falcon\n")
        commit_all(repo, "Secret Partner Ltd deal", name="Jane Roe", email="jane.roe@acme-corp.io")
        (repo / "a.txt").unlink()
        commit_all(repo, "cleanup")
        res = run_cli("scan", "--format", "json", "--history", "--denylist", str(self.deny), "--gitleaks", "never",
                      str(repo), cwd=repo)
        self.assertEqual(res.code, 1)
        self.assertNoPrivateValues(res.out, "history json")


class SarifStructureTests(TempTestCase):
    def test_sarif_document(self):
        root = self.tree()
        self.write("tree/a.py", f'TOKEN = "{Fake.github()}"\nhost = "10.20.30.40"\n')
        self.write("tree/pic.jpg", B.jpeg(exif=B.tiff(artist="Kim Lee")))
        res = run_cli("scan", "--format", "sarif", "--no-denylist", "--gitleaks", "never", str(root), cwd=root)
        doc = json.loads(res.out)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["$schema"].endswith("sarif-2.1.0.json"))
        run = doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        self.assertEqual(len(ids), len(set(ids)))
        for r in rules:
            self.assertIn(r["defaultConfiguration"]["level"], ("error", "warning", "note"))
            self.assertRegex(r["properties"]["security-severity"], r"^\d+\.\d$")
            self.assertTrue(r["helpUri"].startswith("https://"))
        self.assertEqual(run["columnKind"], "unicodeCodePoints")
        self.assertTrue(run["results"])
        for result in run["results"]:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
            self.assertIn(result["level"], ("error", "warning", "note"))
            loc = result["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"]
            self.assertFalse(uri.startswith(("/", "file:")))
            self.assertEqual(loc["artifactLocation"]["uriBaseId"], "%SRCROOT%")
            self.assertGreaterEqual(loc["region"]["startLine"], 1)
            self.assertRegex(result["partialFingerprints"]["prepublishAudit/v1"], r"^[0-9a-f]{32}$")

    @unittest.skipUnless(has_git(), "git")
    def test_commit_findings_get_a_logical_location(self):
        repo = init_repo(self.tmp / "repo")
        commit_all(repo, "x", name="Jane Roe", email="jane.roe@acme-corp.io")
        res = run_cli("scan", "--format", "sarif", "--history", "--no-denylist", "--gitleaks", "never", str(repo),
                      cwd=repo)
        result = json.loads(res.out)["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "git.author-identity")
        self.assertTrue(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(".prepublish-audit/git/"))
        self.assertEqual(result["locations"][0]["logicalLocations"][0]["kind"], "object")


class GithubAndMarkdownTests(TempTestCase):
    def test_annotations(self):
        root = self.tree()
        self.write("tree/dir, with: comma/a.py", f'TOKEN = "{Fake.github()}"\n')
        res = run_cli("scan", "--format", "github", "--no-denylist", "--gitleaks", "never", str(root), cwd=root)
        line = [l for l in res.out.splitlines() if l.startswith("::error")][0]
        self.assertIn("file=dir%2C with%3A comma/a.py", line)
        self.assertIn("line=1", line)
        self.assertIn("title=secret.github-token", line)
        self.assertIn("FAILED", res.out)

    def test_escaping_helpers(self):
        self.assertEqual(_gh_data("50%\nnext"), "50%25%0Anext")
        self.assertEqual(_gh_prop("a:b,c"), "a%3Ab%2Cc")

    def test_markdown_summary_appends(self):
        root = self.tree()
        self.write("tree/a.txt", "/Users/alice/x/y\n")
        summary = self.tmp / "summary.md"
        summary.write_text("previous step\n")
        run_cli("scan", "--no-denylist", "--gitleaks", "never", "--summary-markdown", str(summary), str(root), cwd=root)
        text = summary.read_text()
        self.assertTrue(text.startswith("previous step\n"))
        self.assertIn("### prepublish-audit: Failed", text)
        self.assertIn("`leak.home-path`", text)


class MetadataNameMaskingTests(TempTestCase):
    """Field names, details, locations and notes come from scanned content too."""

    def test_every_output_masks_entries_outside_the_path(self):
        import io
        import zipfile

        root = self.tree()
        deny = self.denylist("falconcode\n")
        self.write("tree/a.png", B.png(text=[("tEXt", "falconcode deal", "bob@acme-corp.io")]))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("[Content_Types].xml", "<Types/>")
            zf.writestr("docProps/custom.xml", '<Properties><property fmtid="x" pid="2" name="falconcode deal">'
                                               "<vt:lpwstr>bob@acme-corp.io</vt:lpwstr></property></Properties>")
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:r><w:t>hi</w:t></w:r></w:p></w:body></w:document>")
        self.write("tree/report.docx", buf.getvalue())
        summary = self.tmp / "summary.md"
        outputs = []
        for fmt in ("human", "json", "sarif", "github"):
            res = run_cli("scan", "-f", fmt, "--denylist", str(deny), "--gitleaks", "never", "--no-external-tools",
                          "--summary-markdown", str(summary), str(root), cwd=root)
            self.assertEqual(res.code, 1, res.err)
            outputs.append((fmt, res.out + res.err))
        outputs.append(("markdown", summary.read_text()))
        for fmt, text in outputs:
            with self.subTest(fmt):
                self.assertNotIn("falconcode", text.lower())
        # The names themselves are checked against the denylist.
        report = json.loads(dict(outputs)["json"])
        names = [f for f in report["findings"] if f["rule_id"] == "denylist" and f["detail"] == "metadata field name"]
        self.assertEqual(sorted(f["path"] for f in names), ["a.png", "report.docx"])

    @unittest.skipUnless(has_git(), "git")
    def test_notes_are_masked(self):
        root = init_repo(self.tmp / "falconcode-site")
        self.write("falconcode-site/.gitignore", "*\n")  # git would publish nothing: the scan adds a note
        self.write("falconcode-site/a.txt", "hello\n")
        deny = self.denylist("falconcode\n")
        for fmt in ("json", "human", "github", "sarif"):
            res = run_cli("scan", "-f", fmt, "--git-files", "--denylist", str(deny), "--gitleaks", "never",
                          str(root), cwd=self.tmp)
            with self.subTest(fmt):
                self.assertNotEqual(res.code, 2, res.err)
                self.assertIn("git would publish nothing", res.out)
                self.assertNotIn("falconcode", res.out)


class ControlCharacterTests(TempTestCase):
    @unittest.skipUnless(os.name == "posix", "file names with control characters")
    def test_file_names_cannot_inject_lines_or_escape_sequences(self):
        root = self.tree()
        name = "a\n::error title=x::injected\n\x1b[31mred.txt"
        (root / name).write_text("/Users/alice/x/y\n")
        (root / "::warning::start.txt").write_text("/Users/alice/x/y\n")
        for fmt in ("human", "github"):
            res = run_cli("scan", "-f", fmt, "--no-denylist", "--gitleaks", "never", "--no-external-tools",
                          str(root), cwd=root)
            with self.subTest(fmt):
                self.assertEqual(res.code, 1, res.err)
                self.assertNotIn("\x1b", res.out)
                commands = [l for l in res.out.splitlines() if l.lstrip().startswith("::")]
                if fmt == "human":
                    self.assertEqual(commands, [])
                else:
                    # GitHub only reads "::" at the start of a line; the file= property is percent-encoded.
                    for line in commands:
                        self.assertTrue(line.startswith(("::warning file=", "::notice title=prepublish-audit::")),
                                        line)
                    self.assertEqual(len([l for l in commands if l.startswith("::warning file=")]), 2)
        summary = self.tmp / "s.md"
        run_cli("scan", "--no-denylist", "--gitleaks", "never", "--summary-markdown", str(summary), str(root), cwd=root)
        rows = [l for l in summary.read_text().splitlines() if l.startswith("| warning")]
        self.assertEqual(len(rows), 2)


class OutputFileModeTests(TempTestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_revealed_reports_are_private(self):
        root = self.tree()
        self.write("tree/a.txt", "/Users/alice/x/y\n")
        out = self.tmp / "out"
        out.mkdir()
        existing = out / "report.txt"
        existing.write_text("old\n")
        existing.chmod(0o644)
        res = run_cli("scan", "--no-denylist", "--gitleaks", "never", "--reveal", "-o", str(existing),
                      "--json-output", str(out / "r.json"), "--sarif-output", str(out / "r.sarif"),
                      "--summary-markdown", str(out / "s.md"), str(root), cwd=root)
        self.assertEqual(res.code, 1, res.err)
        for name in ("report.txt", "r.json", "r.sarif", "s.md"):
            with self.subTest(name):
                self.assertEqual(stat.S_IMODE((out / name).stat().st_mode), 0o600)
        self.assertIn("/Users/alice", existing.read_text())


class FingerprintTests(unittest.TestCase):
    def test_short_entries_in_paths_cannot_be_brute_forced(self):
        import hashlib

        from prepublish_audit.denylist import Denylist

        tmp = Path(tempfile.mkdtemp())
        try:
            deny = tmp / "deny.txt"
            deny.write_text("word:4821\n")
            dl = Denylist.load([deny])
        finally:
            shutil.rmtree(tmp)
        f = Finding("denylist", "error", "Denylist match: entry 1 (line 1)", path="docs/4821-plan.md",
                    origin="path", detail="file or directory name")
        assign_fingerprints([f], mask=dl.mask)
        for n in range(10000):
            candidate = f"docs/{n:04d}-plan.md"
            raw = "\x1f".join([f.rule_id, candidate, f.detail, f.origin, "", "1"])
            self.assertNotEqual(hashlib.sha256(raw.encode()).hexdigest()[:32], f.fingerprint)
        g = Finding("denylist", "error", "Denylist match: entry 1 (line 1)", path="docs/1234-plan.md",
                    origin="path", detail="file or directory name")
        assign_fingerprints([g], mask=lambda s: s.replace("1234", "***"))
        self.assertEqual(f.fingerprint, g.fingerprint)  # only the masked form is hashed

    def test_fingerprints_do_not_depend_on_the_secret(self):
        a = Finding("secret.github-token", "error", "m", path="a.py", line=3, column=1)
        a.match = "one-secret-value"
        b = Finding("secret.github-token", "error", "m", path="a.py", line=3, column=1)
        b.match = "another-secret-value"
        assign_fingerprints([a])
        assign_fingerprints([b])
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_fingerprints_distinguish_occurrences(self):
        fs = [Finding("leak.email", "warning", "m", path="a.py", line=i) for i in (1, 2)]
        assign_fingerprints(fs)
        self.assertNotEqual(fs[0].fingerprint, fs[1].fingerprint)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{32}", f.fingerprint) for f in fs))


if __name__ == "__main__":
    unittest.main()
