"""prepublish-audit doctor: each check, its fix, the exit code, and that nothing private is printed."""

import io
import os
import shutil
import unittest

from prepublish_audit.doctor import ASCII_SYMBOLS, SYMBOLS, Doctor, render, symbols_for

from .helpers import POSIX, PY, TempTestCase, commit_all, git, has_git, init_repo, run_cli


@unittest.skipUnless(POSIX, "fake executables need a POSIX shell")
class DoctorTestCase(TempTestCase):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "_bin"
        self.bin.mkdir()
        self.root = self.tree()
        self.write("tree/a.txt", "hello\n")

    def tool(self, name: str, first_line: str, stream: str = "stdout") -> None:
        path = self.bin / name
        path.write_text(f"#!{PY}\nimport sys\nsys.{stream}.write({first_line + chr(10)!r})\n", encoding="utf-8")
        path.chmod(0o755)

    def all_tools(self) -> None:
        self.tool("exiftool", "13.10")
        self.tool("ffprobe", "ffprobe version 7.1.1 Copyright (c) 2007-2030 the FFmpeg developers")
        self.tool("pdfinfo", "pdfinfo version 24.02.0", stream="stderr")
        self.tool("gitleaks", "8.30.1")

    def private_denylist(self, text: str = "Project Falcon\n  label: codename\n"):
        folder = self.home / ".config" / "prepublish-audit"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / "denylist.txt"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return path

    def doctor(self, *args: str, with_git: bool = False, env=None, cwd=None):
        dirs = [str(self.bin)]
        if with_git:
            dirs.append(os.path.dirname(shutil.which("git")))
        full_env = {"PATH": os.pathsep.join(dirs)}
        full_env.update(env or {})
        return run_cli("doctor", "--color", "never", *args, cwd=cwd or self.root, env=full_env)


class ReadySetupTests(DoctorTestCase):
    def test_everything_in_place_exits_zero(self):
        self.private_denylist()
        self.all_tools()
        res = self.doctor()
        self.assertEqual(res.code, 0, res.out)
        self.assertIn("✓ Denylist found: ~/.config/prepublish-audit/denylist.txt (default location)", res.out)
        self.assertIn("✓ Denylist is valid: 1 entry (1 literal), 1 labelled", res.out)
        self.assertIn("✓ Denylist is private (mode 600)", res.out)
        self.assertIn("✓ Denylist is outside the path(s) to scan: .", res.out)
        self.assertIn("✓ gitleaks 8.30.1", res.out)
        self.assertIn("✓ exiftool 13.10", res.out)
        self.assertIn("✓ ffprobe 7.1.1", res.out)
        self.assertIn("✓ pdfinfo 24.02.0", res.out)
        self.assertNotIn("✗", res.out)
        self.assertIn("Ready. Next: prepublish-audit scan .", res.out)

    def test_optional_items_warn_but_pass_unless_strict(self):
        self.private_denylist()
        res = self.doctor()
        self.assertEqual(res.code, 0, res.out)
        self.assertIn("! gitleaks not found (optional", res.out)
        self.assertIn("fix: brew install exiftool", res.out)
        self.assertIn("fix: brew install poppler", res.out)
        self.assertIn("! git not found", res.out)
        res = self.doctor("--strict")
        self.assertEqual(res.code, 1)
        self.assertIn("items to review count as failures", res.out)

    def test_order_of_checks(self):
        self.private_denylist()
        self.all_tools()
        out = self.doctor().out
        positions = [out.index(word) for word in ("Python", "Denylist found", "Denylist is valid",
                                                    "Denylist is private", "Public config", "gitleaks", "exiftool")]
        self.assertEqual(positions, sorted(positions))


class DenylistCheckTests(DoctorTestCase):
    def test_missing_denylist_fails_with_init_fix(self):
        res = self.doctor()
        self.assertEqual(res.code, 1)
        self.assertIn("✗ No private denylist found", res.out)
        self.assertIn("fix: prepublish-audit init, then add your own strings to "
                      "~/.config/prepublish-audit/denylist.txt", res.out)
        self.assertIn("Not ready", res.out)

    def test_readable_by_others(self):
        self.private_denylist().chmod(0o644)
        res = self.doctor()
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Denylist can be read by other users (mode 644)", res.out)
        self.assertIn("fix: chmod 600 ~/.config/prepublish-audit/denylist.txt", res.out)

    def test_inside_the_scanned_tree(self):
        inside = self.write("tree/private/deny.txt", "Project Falcon\n", mode=0o600)
        res = self.doctor("--denylist", str(inside))
        self.assertEqual(res.code, 1)
        self.assertIn("✗ The denylist is inside the tree you are going to scan (.)", res.out)
        # Moved to the default name, so that scan finds it without options.
        self.assertIn("fix: mkdir -p -m 700 ~/.config/prepublish-audit && mv private/deny.txt "
                      "~/.config/prepublish-audit/denylist.txt && chmod 600 ~/.config/prepublish-audit/denylist.txt, "
                      "then drop --denylist", res.out)
        self.private_denylist()  # the default name is taken: keep the name, pass the path
        res = self.doctor("--denylist", str(inside))
        self.assertIn("fix: move it outside every repository (for example mv private/deny.txt "
                      "~/.config/prepublish-audit/, then chmod 600 it) and pass the new path with --denylist", res.out)

    def test_scanning_the_home_folder_only_warns(self):
        self.private_denylist()
        res = self.doctor(str(self.home))
        self.assertEqual(res.code, 0, res.out)
        self.assertIn("! The denylist is inside ~, which contains your home folder", res.out)
        self.assertNotIn("✗ The denylist is inside", res.out)
        self.assertNotIn("Ready", res.out)  # never suggest scanning the whole home folder
        self.assertIn("Do not scan there: it contains your home folder. Next: cd into the repository", res.out)

    def test_home_folder_with_a_streamed_denylist(self):
        read_end, write_end = os.pipe()
        try:
            os.write(write_end, b"Project Falcon\n")
            os.close(write_end)
            res = self.doctor("--denylist", f"/dev/fd/{read_end}", cwd=self.home)
        finally:
            os.close(read_end)
        self.assertIn("! ~ is your home folder or contains it, so a scan would read everything in it", res.out)
        self.assertNotIn("Ready", res.out)

    def test_invalid_denylist_shows_the_fix_but_not_the_pattern(self):
        bad = self.denylist("re:(heron-unclosed\n")
        res = self.doctor("--denylist", str(bad))
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Denylist cannot be used: denylist 1 line 1: invalid regular expression", res.out)
        self.assertIn("fix: Escape characters that are special in regular expressions", res.out)
        self.assertNotIn("heron", res.out.lower())

    def test_empty_denylist(self):
        self.private_denylist("# only comments\n")
        res = self.doctor()
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Denylist has no entries yet", res.out)

    def test_environment_variable_pointing_nowhere(self):
        res = self.doctor(env={"PREPUBLISH_AUDIT_DENYLIST": str(self.tmp / "nowhere" / "deny.txt")})
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Denylist not found:", res.out)
        self.assertIn("(from $PREPUBLISH_AUDIT_DENYLIST)", res.out)
        self.assertNotIn("outside the path(s) to scan", res.out)
        self.assertIn("fix: export PREPUBLISH_AUDIT_DENYLIST=~/.config/prepublish-audit/denylist.txt", res.out)

    def test_duplicate_entries_are_listed_to_review(self):
        self.private_denylist("Project Falcon\nproject falcon\n")
        res = self.doctor()
        self.assertIn("! Denylist: denylist 1 line 2: duplicate of entry 1", res.out)
        self.assertIn("fix: remove the duplicate line", res.out)

    def test_streamed_denylist_is_not_a_permission_problem(self):
        read_end, write_end = os.pipe()
        try:
            os.write(write_end, b"Project Falcon\n")
            os.close(write_end)
            res = self.doctor("--denylist", f"/dev/fd/{read_end}")
        finally:
            os.close(read_end)
        self.assertIn("✓ Denylist is streamed (a pipe, not a file on disk)", res.out)
        self.assertIn("✓ Denylist is valid: 1 entry", res.out)
        self.assertNotIn("other users", res.out)
        # The next command cannot reuse the pipe: it says so, and an empty one would stop the scan.
        self.assertIn("Ready. Next: prepublish-audit scan --require-denylist --denylist <(...) .", res.out)
        self.assertIn("a pipe can be read only once", res.out)

    def test_nothing_private_is_printed(self):
        folder = self.tmp / "Project Falcon keys"
        folder.mkdir()
        deny = folder / "deny.txt"
        deny.write_text("Project Falcon\n", encoding="utf-8")
        deny.chmod(0o644)  # a failing check prints the path in its fix
        tree = self.tree("Project Falcon site")
        res = self.doctor("--denylist", str(deny), str(tree), cwd=self.tmp)
        self.assertEqual(res.code, 1)
        self.assertIn("***", res.out)
        self.assertNotIn("falcon", res.out.lower())


class ConfigAndHelperTests(DoctorTestCase):
    def test_invalid_config(self):
        self.private_denylist()
        self.write("tree/.prepublish-audit.json", '{"fial-on": "warning"}')
        res = self.doctor()
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Public config is invalid: unknown config key(s)", res.out)
        self.assertIn("fix: Check the spelling against README", res.out)

    def test_config_found_and_no_config(self):
        self.private_denylist()
        self.write("tree/.prepublish-audit.json", '{"fail-on": "warning"}')
        self.assertIn("✓ Public config: .prepublish-audit.json", self.doctor().out)
        self.assertIn("- Public config: ignored (--no-config)", self.doctor("--no-config").out)

    def test_gitleaks_required_by_config(self):
        self.private_denylist()
        self.write("tree/.prepublish-audit.json", '{"gitleaks": "always"}')
        res = self.doctor()
        self.assertEqual(res.code, 1)
        self.assertIn('✗ gitleaks not found, but the config requires it (gitleaks = "always")', res.out)
        self.write("tree/.prepublish-audit.json", '{"gitleaks": "never"}')
        self.assertIn("- gitleaks: turned off in the config", self.doctor().out)

    def test_external_tools_off_is_ignored_while_a_denylist_is_loaded(self):
        self.write("tree/.prepublish-audit.json", '{"external-tools": false}')
        self.assertIn("- exiftool, ffprobe and pdfinfo: turned off", self.doctor().out)
        self.private_denylist()
        self.assertIn("! exiftool not found", self.doctor().out)  # the scan would not apply the setting either

    def test_next_command_repeats_the_options_and_quotes_paths(self):
        deny = self.denylist("Project Falcon\n")
        site = self.tree("my site")
        (site / "index.html").write_text("<p>hi</p>\n")
        res = self.doctor("--denylist", str(deny), "--no-config", "my site", cwd=self.tmp)
        self.assertEqual(res.code, 0, res.out)
        self.assertIn(f"Ready. Next: prepublish-audit scan --require-denylist --denylist {deny} --no-config "
                      "'my site'\n", res.out)
        self.private_denylist()
        config = self.write("tree/ci.json", '{"fail-on": "warning"}')
        res = self.doctor("-c", str(config))
        self.assertIn(f"Ready. Next: prepublish-audit scan -c {config} .", res.out)

    def test_missing_path(self):
        self.private_denylist()
        res = self.doctor(str(self.tmp / "missing"))
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Path to scan not found", res.out)

    def test_ascii_output_when_the_terminal_cannot_show_symbols(self):
        self.assertEqual(symbols_for(io.TextIOWrapper(io.BytesIO(), encoding="ascii")), ASCII_SYMBOLS)
        self.assertEqual(symbols_for(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")), SYMBOLS)
        self.private_denylist()
        doctor = Doctor([self.root])
        doctor.run()
        stream = io.TextIOWrapper(io.BytesIO(), encoding="ascii")
        render(doctor, stream)
        stream.flush()
        text = stream.buffer.getvalue().decode("ascii")
        self.assertIn("[ok]   Denylist is valid", text)


@unittest.skipUnless(POSIX and has_git(), "needs git and a POSIX shell")
class GitCheckTests(DoctorTestCase):
    def setUp(self):
        super().setUp()
        self.private_denylist()
        self.all_tools()
        self.repo = init_repo(self.root)
        commit_all(self.repo, "init")

    def test_repository_ready(self):
        res = self.doctor(with_git=True)
        self.assertEqual(res.code, 0, res.out)
        self.assertIn("✓ Full git history available", res.out)
        self.assertIn("✓ New commits here use a no-reply email address", res.out)
        self.assertIn("- No prepublish-audit hook in .pre-commit-config.yaml", res.out)
        self.assertIn("Ready. Next: prepublish-audit scan --git-files --history .", res.out)

    def test_personal_commit_email_is_flagged_but_not_printed(self):
        res = self.doctor(with_git=True, env={"GIT_AUTHOR_EMAIL": "jane.roe@acme-corp.io",
                                              "GIT_COMMITTER_EMAIL": "jane.roe@acme-corp.io"})
        self.assertIn("! New commits here would carry a personal email address (not shown)", res.out)
        self.assertIn("users.noreply.github.com", res.out)
        self.assertNotIn("jane", res.out.lower())
        self.assertNotIn("acme", res.out.lower())

    def test_hooks_configured_but_not_installed(self):
        self.write("tree/.pre-commit-config.yaml",
                   "repos:\n  - repo: https://github.com/deegitech/prepublish-audit\n    rev: v0.1.0\n    hooks:\n"
                   "      - id: prepublish-audit            # staged files\n"
                   "      - id: prepublish-audit-history\n")
        res = self.doctor(with_git=True)
        self.assertIn("! pre-commit hook not installed", res.out)
        self.assertIn("! pre-push hook not installed", res.out)
        self.assertIn("fix: pre-commit install --hook-type pre-push", res.out)
        hooks = self.repo / ".git" / "hooks"
        hooks.mkdir(exist_ok=True)
        for name in ("pre-commit", "pre-push"):
            (hooks / name).write_text("#!/bin/sh\n# File generated by pre-commit\n")
        res = self.doctor(with_git=True)
        self.assertIn("✓ pre-commit hook installed (pre-commit)", res.out)
        self.assertIn("✓ pre-push hook installed (pre-commit)", res.out)

    def test_keychain_hook_from_the_setup_guide_counts_as_pre_push(self):
        self.write("tree/.pre-commit-config.yaml",
                   "repos:\n  - repo: local\n    hooks:\n      - id: prepublish-audit-keychain\n"
                   "        language: system\n        stages: [pre-push]\n")
        res = self.doctor(with_git=True)
        self.assertIn("! pre-push hook not installed", res.out)
        self.assertNotIn("pre-commit hook not installed", res.out)

    def test_shallow_clone(self):
        commit_all(self.repo, "second")
        clone = self.tmp / "clone"
        git(self.tmp, "clone", "-q", "--depth", "1", self.repo.as_uri(), str(clone))
        res = self.doctor(with_git=True, cwd=clone)
        self.assertIn("! Shallow clone: a --history scan would miss older commits", res.out)
        self.assertIn("fix: git fetch --unshallow", res.out)

    def test_denylist_inside_another_working_tree(self):
        notes = init_repo(self.tmp / "notes")
        deny = notes / "deny.txt"
        deny.write_text("Project Falcon\n", encoding="utf-8")
        deny.chmod(0o600)
        res = self.doctor("--denylist", str(deny), with_git=True)
        self.assertIn("! Denylist is inside a git working tree and not ignored", res.out)
        (notes / ".gitignore").write_text("deny.txt\n")
        res = self.doctor("--denylist", str(deny), with_git=True)
        self.assertIn("✓ Denylist is inside a git working tree but ignored by git", res.out)
        git(notes, "add", "-f", "deny.txt")
        res = self.doctor("--denylist", str(deny), with_git=True)
        self.assertEqual(res.code, 1)
        self.assertIn("✗ Denylist is tracked by git in the repository that contains it", res.out)

    def test_ignored_build_folder_is_scanned_without_git_files(self):
        # A gitignored build folder: --git-files would read nothing under it.
        self.write("tree/.gitignore", "dist/\n")
        self.write("tree/dist/app.js", "var x = 1;\n")
        commit_all(self.repo, "ignore dist")
        res = self.doctor("dist", with_git=True)
        self.assertEqual(res.code, 0, res.out)
        self.assertIn("Ready. Next: prepublish-audit scan dist\n", res.out)
        self.assertNotIn("--git-files", res.out)
        res = self.doctor(".", "dist", with_git=True)
        self.assertIn("Ready. Next:\n  prepublish-audit scan --git-files --history .\n"
                      "  prepublish-audit scan dist\n", res.out)

    def test_not_a_repository(self):
        other = self.tree("site")
        (other / "index.html").write_text("<p>hi</p>\n")
        res = self.doctor("site", with_git=True, cwd=self.tmp)
        self.assertIn("- site is not in a git repository", res.out)
        self.assertIn("Ready. Next: prepublish-audit scan site", res.out)


if __name__ == "__main__":
    unittest.main()
