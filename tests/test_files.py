import gzip
import os
import unittest

from . import builders as B
from .helpers import POSIX, Fake, TempTestCase, findings_for, rules_of, scan_json

DENY = "Project Falcon\n  label: codename\nAcme Corp\n  label: company\n  allow: LICENSE\n"


class TreeTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.deny = self.denylist(DENY)

    def scan(self, *args):
        return scan_json(self.root, "--denylist", str(self.deny), *args)

    def test_clean_tree_passes(self):
        self.write("tree/README.md", "# Hello\n\nNothing to see.\n")
        report = self.scan()
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["_exit"], 0)
        self.assertEqual(report["result"], "pass")

    def test_text_findings_have_positions(self):
        self.write("tree/docs/plan.md", "intro\nThe Project Falcon launch.\n")
        report = self.scan()
        f = findings_for(report, "denylist")[0]
        self.assertEqual((f["path"], f["line"], f["column"]), ("docs/plan.md", 2, 5))
        self.assertEqual(f["message"], "Denylist match: codename")
        self.assertEqual(report["_exit"], 1)

    def test_allow_context_in_license(self):
        self.write("tree/LICENSE", "Copyright 2026 Acme Corp\n")
        self.write("tree/NOTICE", "Acme Corp\n")
        report = self.scan()
        self.assertEqual([f["path"] for f in findings_for(report, "denylist")], ["NOTICE"])
        self.assertEqual(report["summary"]["suppressed"], 1)

    def test_file_names_are_scanned(self):
        self.write("tree/project-falcon/notes.txt", "hello\n")
        self.write("tree/project falcon.txt", "hello\n")
        report = scan_json(self.root, "--denylist", str(self.deny), "--loose-denylist")
        paths = sorted(f["path"] for f in findings_for(report, "denylist"))
        # Reports mask denylist matches inside paths unless --reveal is given.
        self.assertEqual(paths, ["***.txt", "***/"])

    def test_denylist_inside_tree_is_an_error_and_not_scanned(self):
        inside = self.write("tree/private/deny.txt", "Secret Codename X\n", mode=0o600)
        report = scan_json(self.root, "--denylist", str(inside))
        self.assertEqual(rules_of(report), ["config.denylist-in-tree"])

    def test_utf16_text(self):
        self.write("tree/notes.txt", "﻿hello Project Falcon\n".encode("utf-16-le"))
        report = self.scan()
        self.assertEqual(findings_for(report, "denylist")[0]["line"], 1)

    def test_binary_strings(self):
        data = b"\x00\x01\x02ELF" + b"\x00" * 20 + b"/Users/alice/build/app.o" + b"\x00" * 8 + \
            "Project Falcon".encode("utf-16-le") + b"\x00\x00"
        self.write("tree/bin/app", data)
        report = self.scan()
        home = findings_for(report, "leak.home-path")[0]
        self.assertEqual(home["origin"], "binary")
        self.assertIn("byte offset", home["detail"])
        self.assertIsNone(home["line"])
        self.assertEqual(len(findings_for(report, "denylist")), 1)

    @unittest.skipUnless(POSIX, "symlinks")
    def test_symlink_targets(self):
        os.symlink("/Users/alice/private/keys", self.root / "keys")
        report = self.scan()
        f = findings_for(report, "leak.home-path")[0]
        self.assertEqual(f["origin"], "symlink")
        self.assertEqual(f["path"], "keys")

    def test_os_metadata_and_sensitive_files(self):
        self.write("tree/.DS_Store", B.ds_store(["project-falcon-budget.xlsx", "photos"]))
        self.write("tree/keys/AuthKey_Q7K2M9X4LP.p8", Fake.private_key())
        self.write("tree/.env", "DEBUG=1\n")
        self.write("tree/.env.example", "DEBUG=0\n")
        self.write("tree/ssh/id_ed25519", "not really a key\n")
        report = scan_json(self.root, "--denylist", str(self.deny), "--loose-denylist")
        rules = rules_of(report)
        self.assertIn("leak.os-metadata-file", rules)
        self.assertEqual(len(findings_for(report, "denylist")), 1)  # name inside .DS_Store
        sensitive = {f["path"]: f["severity"] for f in findings_for(report, "secret.sensitive-file")}
        self.assertEqual(sensitive, {"keys/AuthKey_Q7K2M9X4LP.p8": "error", ".env": "warning",
                                     "ssh/id_ed25519": "error"})
        self.assertIn("secret.private-key", rules)
        self.assertIn("leak.apple-developer-id", rules)

    def test_default_and_configured_excludes(self):
        self.write("tree/node_modules/pkg/index.js", "// Project Falcon\n")
        self.write("tree/build/out.txt", "Project Falcon\n")
        report = self.scan("--exclude", "build/**")
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["scanned"]["default_excluded_dirs"], 1)
        self.assertEqual(report["scanned"]["excluded"], 1)
        self.assertIn({"path": "node_modules/", "reason": "default-excluded directory (scan it with "
                                                          "--no-default-excludes)"}, report["skipped"])
        self.assertTrue(any("--no-default-excludes" in n for n in report["notes"]))
        report = self.scan("--no-default-excludes")
        self.assertEqual([f["path"] for f in report["findings"]], ["build/out.txt", "node_modules/pkg/index.js"])

    def test_large_binaries_are_checked_completely(self):
        """More than 4 MiB of printable strings: the end of the file is checked too."""
        filler = b"abcdefgh\x00" * (6 * 1024 * 1024 // 9)
        self.write("tree/lib/engine.so", b"\x7fELF" + filler + b"\x00the Project Falcon tail\x00")
        report = self.scan()
        f = findings_for(report, "denylist")[0]
        self.assertEqual(f["path"], "lib/engine.so")
        self.assertIn("byte offset", f["detail"])

    def test_file_arguments_match_globs_from_the_working_directory(self):
        """pre-commit passes staged files: anchored allow globs must mean the same as in a full scan."""
        self.write("tree/README.md", "Project Falcon in the root readme\n")
        self.write("tree/docs/README.md", "Project Falcon in the docs readme\n")
        deny = self.denylist("Project Falcon\n  allow: /README.md\n  allow: docs/legal/*\n", "anchored.txt")
        self.write("tree/docs/legal/notice.md", "Project Falcon notice\n")
        full = scan_json(self.root, "--denylist", str(deny))
        self.assertEqual([f["path"] for f in findings_for(full, "denylist")], ["docs/README.md"])
        for rel, expected in (("docs/README.md", 1), ("README.md", 0), ("docs/legal/notice.md", 0)):
            with self.subTest(rel):
                report = scan_json(self.root / rel, "--denylist", str(deny), cwd=self.root)
                self.assertEqual(len(findings_for(report, "denylist")), expected)

    def test_embedded_git_directory(self):
        self.write("tree/vendor/lib/.git/config", "[core]\n")
        report = self.scan()
        self.assertEqual(findings_for(report, "leak.embedded-git-dir")[0]["path"], "vendor/lib/.git/")

    def test_large_files(self):
        self.write("tree/big.txt", "a" * 5000 + "\nProject Falcon\n")
        self.write("tree/movie.mp4", B.mp4() + b"\x00" * 6000)
        report = self.scan("--max-file-size", "4KiB")
        inc = findings_for(report, "scan.incomplete")
        self.assertEqual([f["path"] for f in inc], ["big.txt"])
        self.assertTrue(any(s["path"] == "movie.mp4" for s in report["skipped"]))

    def test_config_allow_and_severity(self):
        self.write("tree/.prepublish-audit.json",
                   '{"allow": [{"rules": ["leak.email"], "paths": ["docs/**"]}], "severity": {"leak.home-path": "note"}}')
        self.write("tree/docs/team.md", "mail alice.smith@acme-corp.io\n")
        self.write("tree/src/a.py", "LOG = '/Users/alice/x/y'\n")
        report = self.scan()
        self.assertEqual(rules_of(report), ["leak.home-path"])
        self.assertEqual(report["findings"][0]["severity"], "note")
        self.assertEqual(report["_exit"], 0)


class ArchiveTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.deny = self.denylist(DENY)

    def scan(self, *args):
        return scan_json(self.root, "--denylist", str(self.deny), *args)

    def test_nested_zip(self):
        inner = B.zip_bytes({"docs/plan.txt": b"The Project Falcon plan\n"})
        self.write("tree/bundle.zip", B.zip_bytes({"inner.zip": inner, "readme.txt": b"hi"}))
        report = self.scan()
        f = findings_for(report, "denylist")[0]
        self.assertEqual(f["path"], "bundle.zip!/inner.zip!/docs/plan.txt")
        self.assertEqual(f["line"], 1)
        self.assertEqual(f["origin"], "archive")

    def test_zip_with_git_dir_ds_store_and_keys(self):
        self.write("tree/site.zip", B.zip_bytes({".git/config": b"[core]", "__MACOSX/._index.html": b"x",
                                                 "keys/release.p12": b"\x30\x82\x01"}))
        rules = rules_of(self.scan())
        self.assertIn("leak.embedded-git-dir", rules)
        self.assertIn("leak.os-metadata-file", rules)
        self.assertIn("secret.sensitive-file", rules)

    def test_encrypted_member(self):
        data = B.mark_zip_member_encrypted(B.zip_bytes({"secret.txt": b"hello"}))
        self.write("tree/locked.zip", data)
        f = findings_for(self.scan(), "scan.incomplete")[0]
        self.assertEqual(f["path"], "locked.zip!/secret.txt")
        self.assertIn("encrypted", f["detail"])

    def test_decompression_bomb_guard(self):
        self.write("tree/bomb.zip", B.zip_bytes({"zeros.bin": b"\x00" * (3 * 1024 * 1024)}))
        f = findings_for(self.scan(), "scan.incomplete")[0]
        self.assertIn("bomb", f["detail"])

    def test_tar_gz_members_and_symlinks(self):
        data = B.tar_gz({"pkg/config.py": f'TOKEN = "{Fake.github()}"\n'.encode()},
                        symlinks={"pkg/link": "/Users/alice/secrets"})
        self.write("tree/release.tar.gz", data)
        report = self.scan()
        self.assertEqual(findings_for(report, "secret.github-token")[0]["path"], "release.tar.gz!/pkg/config.py")
        self.assertEqual(findings_for(report, "leak.home-path")[0]["path"], "release.tar.gz!/pkg/link")

    def test_single_gzip_file(self):
        self.write("tree/dump.sql.gz", gzip.compress(b"insert into t values ('Project Falcon');\n"))
        f = findings_for(self.scan(), "denylist")[0]
        self.assertEqual(f["path"], "dump.sql.gz!/dump.sql")

    def test_unsupported_container_is_reported(self):
        self.write("tree/backup.7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 32)
        self.assertEqual(rules_of(self.scan()), ["scan.incomplete"])

    def test_archives_can_be_disabled(self):
        self.write("tree/bundle.zip", B.zip_bytes({"a.txt": b"Project Falcon"}))
        report = self.scan("--no-archives")
        self.assertEqual(rules_of(report), ["scan.incomplete"])


class MetadataTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.root = self.tree()
        self.deny = self.denylist(DENY)

    def scan(self, *args):
        return scan_json(self.root, "--denylist", str(self.deny), *args)

    def test_jpeg_exif_author_gps_serial_and_comment(self):
        exif = B.tiff(artist="Alice Smith", owner="Alice Smith", serial="CAM-889911", gps=(48.8584, 2.2945))
        self.write("tree/photo.jpg", B.jpeg(exif=exif, comment="shot for Project Falcon"))
        report = self.scan()
        rules = rules_of(report)
        self.assertEqual(rules.count("metadata.author"), 1)  # Artist and owner carry the same value
        loc = findings_for(report, "metadata.location")[0]
        self.assertEqual(loc["severity"], "error")
        self.assertEqual(loc["detail"], "EXIF GPS position")
        self.assertIn("metadata.serial", rules)
        self.assertEqual(findings_for(report, "denylist")[0]["detail"], "JPEG comment")

    def test_jpeg_xmp_packet(self):
        self.write("tree/a.jpg", B.jpeg(xmp_packet=B.xmp("Bob Jones", "<stRef:filePath>/Users/bob/art/a.psd</stRef:filePath>")))
        report = self.scan()
        self.assertIn("metadata.author", rules_of(report))
        self.assertIn("leak.home-path", rules_of(report))

    def test_placeholder_authors_are_ignored(self):
        self.write("tree/a.jpg", B.jpeg(exif=B.tiff(artist="Microsoft Office User")))
        self.assertEqual(self.scan()["findings"], [])

    def test_png_text_chunks_and_exif(self):
        data = B.png(text=[("tEXt", "Author", "Carol White"), ("iTXt", "Comment", "draft for Project Falcon"),
                           ("zTXt", "Source", "/home/carol/work/icon.svg")], exif=B.tiff(gps=(-33.86, 151.21)))
        self.write("tree/icon.png", data)
        rules = rules_of(self.scan())
        for rule in ("metadata.author", "denylist", "leak.home-path", "metadata.location"):
            self.assertIn(rule, rules)

    def test_webp_exif(self):
        self.write("tree/a.webp", B.webp(B.tiff(artist="Dana Grey")))
        self.assertEqual(rules_of(self.scan()), ["metadata.author"])

    def test_mp4_location_and_artist(self):
        self.write("tree/clip.mp4", B.mp4(location="+48.8584+002.2945/", artist="Erin Black"))
        rules = rules_of(self.scan())
        self.assertIn("metadata.location", rules)
        self.assertIn("metadata.author", rules)

    def test_pdf_info_and_page_text(self):
        self.write("tree/doc.pdf", B.pdf(author="Frank Green", title="Project Falcon roadmap",
                                         page_text=["Pro", "ject Fal", "con budget"]))
        report = self.scan()
        details = sorted(f["detail"] for f in findings_for(report, "denylist"))
        self.assertEqual(details, ["PDF Title", "PDF text (best effort)"])
        self.assertEqual(findings_for(report, "metadata.author")[0]["detail"], "PDF Author")

    def test_office_document(self):
        data = B.docx(creator="Gina Hall", modified_by="Hank Ives", company="Acme Corp",
                      runs=["Status of Proj", "ect Falcon"], comment_author="Ivy Jones",
                      comment_text="see /Users/ivy/notes/x.txt")
        self.write("tree/report.docx", data)
        report = self.scan()
        authors = sorted(f["detail"] for f in findings_for(report, "metadata.author"))
        self.assertEqual(authors, ["docProps/app.xml Company", "docProps/core.xml cp:lastModifiedBy",
                                   "docProps/core.xml dc:creator", "word/comments.xml author"])
        deny = findings_for(report, "denylist")
        self.assertEqual(sorted(f["path"] for f in deny), ["report.docx", "report.docx!/word/document.xml"])
        self.assertEqual(findings_for(report, "leak.home-path")[0]["path"], "report.docx!/word/comments.xml")

    def test_every_office_property_is_checked(self):
        def office(**parts: str) -> bytes:
            members = {"[Content_Types].xml": b"<Types/>",
                       "xl/workbook.xml": b"<workbook><sheets><sheet name='Q3'/></sheets></workbook>"}
            members.update({k.replace("__", "/").replace("_xml", ".xml"): v.encode() for k, v in parts.items()})
            return B.zip_bytes(members)

        self.write("tree/custom-name.xlsx", office(docProps__custom_xml=(
            '<Properties><property fmtid="{D5CDD505}" pid="2" name="Project Falcon">'
            "<vt:lpwstr>yes</vt:lpwstr></property></Properties>")))
        self.write("tree/titles.xlsx", office(docProps__app_xml=(
            "<Properties><TitlesOfParts><vt:vector size='1'><vt:lpstr>Project Falcon budget</vt:lpstr>"
            "</vt:vector></TitlesOfParts></Properties>")))
        self.write("tree/identifier.xlsx", office(docProps__core_xml=(
            "<cp:coreProperties><dc:identifier>Project Falcon</dc:identifier></cp:coreProperties>")))
        self.write("tree/odf.ods", B.zip_bytes({"mimetype": b"application/vnd.oasis.opendocument.spreadsheet",
                                                "meta.xml": b'<office:meta><meta:user-defined meta:name="Project '
                                                            b'Falcon">1</meta:user-defined></office:meta>'}))
        self.write("tree/alt-text.docx", office(word__document_xml=(
            '<w:document><w:body><w:p><w:r><wp:docPr id="1" descr="screenshot of Project Falcon"/>'
            "<w:t>hello</w:t></w:r></w:p></w:body></w:document>")))
        report = self.scan()
        found = {f["path"].split("!")[0] for f in findings_for(report, "denylist")}
        self.assertEqual(found, {"custom-name.xlsx", "titles.xlsx", "identifier.xlsx", "odf.ods", "alt-text.docx"})

    def test_metadata_rules_can_be_allowed(self):
        self.write("tree/.prepublish-audit.json", '{"allow": [{"rules": ["metadata.author"], "paths": ["press/**"]}]}')
        self.write("tree/press/a.jpg", B.jpeg(exif=B.tiff(artist="Press Office")))
        self.assertEqual(self.scan()["findings"], [])


if __name__ == "__main__":
    unittest.main()
