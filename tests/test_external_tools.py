"""External helpers (exiftool, ffprobe, pdfinfo, gitleaks) replaced by local fakes."""

import json
import os
import shutil
import textwrap
import unittest

from . import builders as B
from .helpers import POSIX, PY, Fake, TempTestCase, findings_for, rules_of, run_cli

EXIFTOOL = r'''
import json, os, sys
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as fh:
        fh.write("exiftool " + str(len([a for a in sys.argv[1:] if a.startswith("/")])) + "\n")
if os.environ.get("FAKE_EXIFTOOL_FAIL"):
    sys.exit(2)
out = []
for arg in sys.argv[1:]:
    if not arg.startswith("/"):
        continue
    item = {"SourceFile": arg, "System:FileName": os.path.basename(arg), "IFD0:Artist": "Alice Smith",
            "XMP-dc:Creator": "Alice Smith", "GPS:GPSLatitude": 48.8584, "GPS:GPSLongitude": 2.2945,
            "PDF:Creator": "Word Processor 16", "XMP-x:XMPToolkit": "Image::ExifTool 13.0",
            "IFD0:ImageDescription": "made for Project Falcon"}
    out.append(item)
print(json.dumps(out))
'''

FFPROBE = r'''
import json, os, sys
log = os.environ.get("FAKE_LOG")
target = sys.argv[-1]
if log:
    with open(log, "a") as fh:
        fh.write("ffprobe " + target.split(":", 1)[0] + "\n")
print(json.dumps({"format": {"filename": target, "tags": {"artist": "Bob Stone", "location": "+48.8584+002.2945/",
                                                           "encoder": "Lavf61.1.100"}},
                  "streams": [{"tags": {"handler_name": "VideoHandler"}}]}))
'''

PDFINFO = r'''
print("Title:          Q3 notes")
print("Author:         Carol White")
print("Creator:        Writer")
'''

GITLEAKS = r'''
import json, os, sys
args = sys.argv[1:]
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "a") as fh:
        fh.write("gitleaks " + " ".join(a for a in args if not a.startswith("/")) + "\n")
if args[:1] == ["version"]:
    print("8.30.1")
    sys.exit(0)
if os.environ.get("FAKE_GITLEAKS_FAIL"):
    sys.exit(3)
report = args[args.index("--report-path") + 1]
items = [
    {"RuleID": "generic-api-key", "File": "src/conf.py", "StartLine": 3, "StartColumn": 9, "Match": "REDACTED",
     "Secret": "REDACTED", "Commit": ""},
    {"RuleID": "github-pat", "File": "src/conf.py", "StartLine": 1, "StartColumn": 10, "Match": "REDACTED",
     "Secret": "REDACTED", "Commit": ""},
    {"RuleID": "generic-api-key", "File": "node_modules/x/index.js", "StartLine": 1, "StartColumn": 1,
     "Match": "REDACTED", "Secret": "REDACTED", "Commit": ""},
]
if args[0] == "git":
    items = [{"RuleID": "aws-access-token", "File": "old/creds.txt", "StartLine": 1, "StartColumn": 1,
              "Commit": "0123456789abcdef0123456789abcdef01234567", "Match": "REDACTED", "Secret": "REDACTED"}]
with open(report, "w") as fh:
    json.dump(items, fh)
'''


@unittest.skipUnless(POSIX, "fake executables need a POSIX shell")
class ExternalToolTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "_bin"
        self.bin.mkdir()
        self.log = self.tmp / "_tools.log"
        self.root = self.tree()
        self.deny = self.denylist("Project Falcon\n  label: codename\n")

    def tool(self, name: str, source: str) -> None:
        path = self.bin / name
        path.write_text(f"#!{PY}\n" + textwrap.dedent(source), encoding="utf-8")
        path.chmod(0o755)

    def run_scan(self, *args: str, extra_env=None):
        # Only the fakes are on PATH, so real tools installed on the machine cannot interfere.
        env = {"PATH": str(self.bin), "FAKE_LOG": str(self.log)}
        env.update(extra_env or {})
        res = run_cli("scan", "--format", "json", "--denylist", str(self.deny), *args, str(self.root),
                      cwd=self.root, env=env)
        data = json.loads(res.out) if res.out.strip().startswith("{") else {}
        return res, data

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_exiftool_fields_are_classified(self):
        self.tool("exiftool", EXIFTOOL)
        self.write("tree/a.jpg", B.jpeg())
        self.write("tree/b.pdf", B.pdf("Alice Smith", "y", ["z"]))
        res, report = self.run_scan("--gitleaks", "never")
        self.assertEqual(res.code, 1)
        authors = findings_for(report, "metadata.author")
        self.assertEqual(sorted(f["path"] for f in authors), ["a.jpg", "b.pdf"])  # deduplicated per file
        self.assertFalse(any("PDF:Creator" in f["detail"] for f in authors))
        self.assertEqual(len(findings_for(report, "metadata.location")), 2)
        self.assertEqual(len(findings_for(report, "denylist")), 2)
        self.assertEqual(self.calls(), ["exiftool 2"])
        self.assertIn("exiftool", report["scanned"]["helpers"])

    def test_exiftool_failure_falls_back_to_builtin_parsers(self):
        self.tool("exiftool", EXIFTOOL)
        self.write("tree/a.jpg", B.jpeg(exif=B.tiff(artist="Dana Grey")))
        res, report = self.run_scan("--gitleaks", "never", extra_env={"FAKE_EXIFTOOL_FAIL": "1"})
        self.assertEqual(rules_of(report), ["metadata.author"])
        self.assertTrue(any("exiftool failed" in n for n in report["notes"]))

    def test_ffprobe_tags(self):
        self.tool("ffprobe", FFPROBE)
        self.write("tree/clip.mov", B.mp4())
        res, report = self.run_scan("--gitleaks", "never")
        self.assertEqual(sorted(rules_of(report)), ["metadata.author", "metadata.location"])
        self.assertEqual(self.calls(), ["ffprobe file"])

    def test_pdfinfo_when_exiftool_is_missing(self):
        self.tool("pdfinfo", PDFINFO)
        self.write("tree/doc.pdf", B.pdf("Someone Else", "Title", ["text"]))
        res, report = self.run_scan("--gitleaks", "never")
        details = sorted(f["detail"] for f in findings_for(report, "metadata.author"))
        self.assertEqual(details, ["PDF Author", "pdfinfo Author"])

    def test_no_external_tools_flag(self):
        self.tool("exiftool", EXIFTOOL)
        self.write("tree/a.jpg", B.jpeg())
        res, report = self.run_scan("--gitleaks", "never", "--no-external-tools")
        self.assertEqual(self.calls(), [])
        self.assertEqual(report["findings"], [])

    def test_gitleaks_results_are_merged(self):
        self.tool("gitleaks", GITLEAKS)
        self.write("tree/src/conf.py", f'TOKEN = "{Fake.github()}"\nx = 1\nAPI = "something"\n')
        self.write("tree/node_modules/x/index.js", "module.exports = 1\n")
        res, report = self.run_scan("--gitleaks", "auto", "--no-external-tools")
        rules = rules_of(report)
        self.assertIn("secret.github-token", rules)
        self.assertIn("gitleaks.generic-api-key", rules)
        self.assertNotIn("gitleaks.github-pat", rules)  # same line as our own finding
        merged = findings_for(report, "gitleaks.generic-api-key")
        self.assertEqual([f["path"] for f in merged], ["src/conf.py"])  # excluded paths dropped
        self.assertTrue(any("gitleaks 8.30.1" in n for n in report["notes"]))
        self.assertTrue(any(c.startswith("gitleaks dir . --redact") for c in self.calls()))

    def test_gitleaks_history_mode(self):
        from .helpers import commit_all, has_git, init_repo

        if not has_git():
            self.skipTest("git")
        self.tool("gitleaks", GITLEAKS)
        self.root = init_repo(self.tmp / "tree")
        self.write("tree/a.txt", "hello\n")
        commit_all(self.root, "init")
        git_dir = os.path.dirname(shutil.which("git"))
        res, report = self.run_scan("--gitleaks", "auto", "--history", "--no-external-tools",
                                    extra_env={"PATH": str(self.bin) + os.pathsep + git_dir})
        hist = findings_for(report, "gitleaks.aws-access-token")
        self.assertEqual(hist[0]["origin"], "history")
        self.assertEqual(hist[0]["commit"], "0123456789abcdef0123456789abcdef01234567")
        self.assertTrue(any("--log-opts=--all" in c for c in self.calls()))

    def test_gitleaks_failure_and_always_mode(self):
        self.tool("gitleaks", GITLEAKS)
        res, report = self.run_scan("--gitleaks", "auto", extra_env={"FAKE_GITLEAKS_FAIL": "1"})
        self.assertEqual(res.code, 0)
        self.assertTrue(any("gitleaks did not complete" in n for n in report["notes"]))
        res, _ = self.run_scan("--gitleaks", "always", extra_env={"FAKE_GITLEAKS_FAIL": "1"})
        self.assertEqual(res.code, 2)

    def test_gitleaks_always_requires_the_binary(self):
        res, _ = self.run_scan("--gitleaks", "always", extra_env={"PATH": str(self.bin)})
        self.assertEqual(res.code, 2)
        self.assertIn("not on PATH", res.err)


if __name__ == "__main__":
    unittest.main()
