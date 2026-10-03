import unittest

from . import builders as B
from .helpers import (
    Fake,
    TempTestCase,
    commit_all,
    findings_for,
    git,
    has_git,
    init_repo,
    rules_of,
    run_cli,
    scan_json,
)

DENY = "Project Falcon\n  label: codename\nSecret Partner Ltd\n  label: partner\n"


@unittest.skipUnless(has_git(), "git is required")
class HistoryTests(TempTestCase):
    def setUp(self):
        super().setUp()
        self.repo = init_repo(self.tmp / "repo")
        self.deny = self.denylist(DENY)

    def scan(self, *args):
        return scan_json(self.repo, "--denylist", str(self.deny), "--history", *args)

    def test_deleted_file_is_found_only_in_history(self):
        token = Fake.github()
        self.write("repo/config.py", f'TOKEN = "{token}"\n# Project Falcon\n')
        first = commit_all(self.repo, "add config")
        (self.repo / "config.py").unlink()
        self.write("repo/README.md", "# Clean\n")
        commit_all(self.repo, "remove config")

        tree_only = scan_json(self.repo, "--denylist", str(self.deny))
        self.assertEqual(tree_only["findings"], [])

        report = self.scan()
        gh = findings_for(report, "secret.github-token")[0]
        self.assertEqual(gh["origin"], "history")
        self.assertEqual(gh["path"], "config.py")
        self.assertEqual(gh["commit"], first)
        self.assertTrue(gh["blob"])
        self.assertEqual(len(findings_for(report, "denylist")), 1)
        self.assertGreaterEqual(report["summary"]["history_only"], 2)
        self.assertEqual(report["scanned"]["commits"], 2)
        self.assertEqual(report["_exit"], 1)

    def test_versions_are_collapsed_and_current_issues_not_repeated(self):
        for i in range(3):
            self.write("repo/notes.md", f"v{i}\nProject Falcon\n")
            commit_all(self.repo, f"edit {i}")
        report = self.scan()
        deny = findings_for(report, "denylist")
        self.assertEqual([f["origin"] for f in deny], ["file"])
        self.assertTrue(any("not listed again" in n for n in report["notes"]))

        self.write("repo/notes.md", "clean now\n")
        commit_all(self.repo, "clean")
        report = self.scan()
        deny = findings_for(report, "denylist")
        self.assertEqual(len(deny), 1)
        self.assertEqual(deny[0]["origin"], "history")
        self.assertIn("in 3 versions", deny[0]["detail"])

    def test_author_identity(self):
        self.write("repo/a.txt", "a\n")
        commit_all(self.repo, "one", name="Jane Roe", email="jane.roe@acme-corp.io")
        self.write("repo/b.txt", "b\n")
        commit_all(self.repo, "two")
        report = self.scan()
        ident = findings_for(report, "git.author-identity")
        self.assertEqual(len(ident), 1)
        self.assertEqual(ident[0]["origin"], "commit")
        self.assertTrue(ident[0]["location"].startswith("commit "))
        self.assertNotIn("jane", str(report).lower())

    def test_company_domain_can_be_allowed_for_identities(self):
        self.write("repo/.prepublish-audit.json", '{"heuristics": {"git-identity-domains": ["acme-corp.io"]}}')
        commit_all(self.repo, "one", name="Jane Roe", email="jane.roe@acme-corp.io")
        self.assertEqual(findings_for(self.scan(), "git.author-identity"), [])

    def test_denylist_in_names_messages_branches_and_tags(self):
        self.write("repo/a.txt", "a\n")
        commit_all(self.repo, "Prepare the Project Falcon release", name="Secret Partner Ltd")
        git(self.repo, "branch", "deal/secret-partner-ltd")
        git(self.repo, "tag", "-a", "v1.0", "-m", "Release for Secret Partner Ltd")
        report = scan_json(self.repo, "--denylist", str(self.deny), "--history", "--loose-denylist")
        origins = sorted((f["origin"], f["detail"]) for f in findings_for(report, "denylist"))
        self.assertIn(("commit", "commit message"), origins)
        self.assertIn(("commit", "author/committer identity"), origins)
        self.assertIn(("commit", "tag message"), origins)
        self.assertIn(("ref", "ref name"), origins)
        ref = [f for f in findings_for(report, "denylist") if f["origin"] == "ref"][0]
        self.assertNotIn("partner", ref["location"].lower())

    def test_reveal_shows_ref_names_locally(self):
        self.write("repo/a.txt", "a\n")
        commit_all(self.repo, "init")
        git(self.repo, "branch", "project-falcon")
        res = run_cli("scan", "--denylist", str(self.deny), "--history", "--loose-denylist", "--reveal",
                      "--gitleaks", "never", "--no-external-tools", str(self.repo), cwd=self.repo)
        self.assertIn("project-falcon", res.out)

    def test_deleted_path_names(self):
        self.write("repo/project-falcon-plan.txt", "nothing secret inside\n")
        commit_all(self.repo, "add")
        git(self.repo, "rm", "-q", "project-falcon-plan.txt")
        commit_all(self.repo, "rm")
        report = scan_json(self.repo, "--denylist", str(self.deny), "--history", "--loose-denylist")
        paths = [f for f in findings_for(report, "denylist") if f["origin"] == "history-path"]
        self.assertEqual(len(paths), 1)

    def test_old_names_of_renamed_files(self):
        """'git mv' keeps the blob, so rev-list names it only once; the old name is still in history."""
        self.write("repo/project-falcon-notes.txt", "nothing secret inside\n")
        commit_all(self.repo, "add")
        git(self.repo, "mv", "project-falcon-notes.txt", "notes.txt")
        commit_all(self.repo, "rename")
        report = scan_json(self.repo, "--denylist", str(self.deny), "--history", "--loose-denylist")
        paths = [f["path"] for f in findings_for(report, "denylist") if f["origin"] == "history-path"]
        self.assertEqual(paths, ["***-notes.txt"])
        self.assertEqual(report["_exit"], 1)

    def test_excludes_apply_to_history(self):
        self.write("repo/.prepublish-audit.json", '{"exclude": ["vendor/**"]}')
        self.write("repo/vendor/notes.txt", "mail jane.roe@acme-corp.io\n")
        commit_all(self.repo, "vendor")
        tree = scan_json(self.repo, "--no-denylist")
        hist = scan_json(self.repo, "--no-denylist", "--history")
        self.assertEqual(tree["findings"], [])
        self.assertEqual(hist["findings"], [])
        self.assertEqual(hist["summary"]["history_only"], 0)
        # The same through a command-line exclude, relative to the scanned folder.
        (self.repo / ".prepublish-audit.json").unlink()
        commit_all(self.repo, "drop config")
        hist = scan_json(self.repo, "--no-denylist", "--history", "--exclude", "vendor/**")
        self.assertEqual(hist["findings"], [])

    def test_stash_is_scanned(self):
        self.write("repo/a.txt", "a\n")
        commit_all(self.repo, "init")
        self.write("repo/a.txt", f"key = {Fake.aws_key_id()}\n")
        git(self.repo, "stash", "-q")
        report = self.scan()
        self.assertIn("secret.aws-access-key-id", rules_of(report))

    def test_binary_blob_metadata_in_history(self):
        self.write("repo/img/photo.jpg", B.jpeg(exif=B.tiff(gps=(48.8584, 2.2945))))
        commit_all(self.repo, "photo")
        git(self.repo, "rm", "-q", "img/photo.jpg")
        commit_all(self.repo, "remove photo")
        loc = findings_for(self.scan(), "metadata.location")
        self.assertEqual(len(loc), 1)
        self.assertEqual(loc[0]["origin"], "history")

    def test_shallow_clone_is_reported(self):
        for i in range(3):
            self.write("repo/f.txt", f"{i}\n")
            commit_all(self.repo, f"c{i}")
        clone = self.tmp / "clone"
        git(self.tmp, "clone", "-q", "--depth", "1", "file://" + str(self.repo), str(clone))
        report = scan_json(clone, "--denylist", str(self.deny), "--history")
        self.assertIn("git.shallow-clone", rules_of(report))

    def test_git_files_mode(self):
        self.write("repo/.gitignore", "secret.txt\n")
        self.write("repo/secret.txt", "Project Falcon\n")
        self.write("repo/untracked.txt", "Project Falcon\n")
        commit_all(self.repo, "init")
        (self.repo / "untracked.txt").write_text("Project Falcon\n")
        report = scan_json(self.repo, "--denylist", str(self.deny), "--git-files")
        self.assertEqual([f["path"] for f in findings_for(report, "denylist")], ["untracked.txt"])
        report = scan_json(self.repo, "--denylist", str(self.deny))
        self.assertEqual(sorted(f["path"] for f in findings_for(report, "denylist")), ["secret.txt", "untracked.txt"])

    def test_ignored_folder_with_git_files_is_never_reported_clean(self):
        # A gitignored build folder scanned with --git-files --history: history blobs are read,
        # but nothing under the folder is, so the report must not say that nothing was found.
        self.write("repo/.gitignore", "dist/\n")
        self.write("repo/a.txt", "hello\n")
        commit_all(self.repo, "init")
        self.write("repo/dist/app.js", "var name = 'Project Falcon';\n")
        res = run_cli("scan", "--denylist", str(self.deny), "--gitleaks", "never", "--git-files", "--history",
                      "dist", cwd=self.repo)
        self.assertEqual(res.code, 0, res.err)
        self.assertIn("Warning: nothing under dist was scanned, because git would not publish it (--git-files)",
                      res.out)
        self.assertNotIn("No secrets or internal information found", res.out)
        quiet = run_cli("scan", "--denylist", str(self.deny), "--gitleaks", "never", "--git-files", "--history",
                        "-q", "dist", cwd=self.repo)
        self.assertIn("Warning: nothing under dist was scanned", quiet.out)
        report = scan_json(self.repo / "dist", "--denylist", str(self.deny), cwd=self.repo)  # without --git-files
        self.assertEqual(len(findings_for(report, "denylist")), 1)

    def test_history_outside_a_repository_is_an_error(self):
        plain = self.tree("plain")
        res = run_cli("scan", "--history", "--no-denylist", "--gitleaks", "never", str(plain), cwd=plain)
        self.assertEqual(res.code, 2)
        self.assertIn("git repository", res.err)

    def test_sha256_repository(self):
        repo = self.tmp / "repo256"
        repo.mkdir()
        try:
            git(repo, "init", "-q", "--object-format=sha256")
        except AssertionError:
            self.skipTest("git without sha256 support")
        self.write("repo256/a.txt", "Project Falcon\n")
        commit_all(repo, "init")
        report = scan_json(repo, "--denylist", str(self.deny), "--history")
        self.assertEqual([f["origin"] for f in findings_for(report, "denylist")], ["file"])


if __name__ == "__main__":
    unittest.main()
