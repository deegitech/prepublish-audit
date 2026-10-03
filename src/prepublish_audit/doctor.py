"""``prepublish-audit doctor``: check the setup before the first scan.

Read-only and offline. It loads the denylist and the public config the way
``scan`` would, asks git and the optional helpers for their versions, and
prints one line per check:

* ``✓`` passed;
* ``✗`` failed: a scan would not protect you, or would stop with an error;
* ``!`` worth fixing, but a scan still works (optional helpers, a shallow
  clone, a personal commit email, a hook that is configured but not installed,
  a path that contains the home folder);
* ``-`` skipped or not applicable.

Every ``✗`` and ``!`` line is followed by the exact fix. The exit code is 0
when nothing failed (with ``--strict``: when nothing is marked ``!`` either)
and 1 otherwise. When nothing failed, the last line is the scan command to
run next, with the doctor's own ``--denylist``, ``-c`` and ``--no-config``
options repeated.

The doctor never prints denylist entries, matched text or the commit email
address. Paths are shown relative to the home folder and masked with the
denylist once it has loaded.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Set, TextIO, Tuple

from . import __version__, doc_url
from . import gitleaks as gl
from . import tomlcompat
from .config import ConfigError, Settings, load_settings
from .denylist import (
    DEFAULT_NAMES,
    ENV_DENYLIST,
    Denylist,
    DenylistError,
    default_denylist_dir,
    locate_denylists,
)
from .gitscan import Repo, identity_allowed
from .hints import hint_for
from .report import printable

OK, FAIL, WARN, SKIP = "ok", "fail", "warn", "skip"
SYMBOLS = {OK: "✓", FAIL: "✗", WARN: "!", SKIP: "-"}
ASCII_SYMBOLS = {OK: "[ok]  ", FAIL: "[FAIL]", WARN: "[warn]", SKIP: "[skip]"}
_COLORS = {OK: "32", FAIL: "1;31", WARN: "1;33", SKIP: "2"}
_TROUBLESHOOTING = doc_url("docs/troubleshooting.md")
_FRESH_HISTORY = "if it was ever committed, publish a fresh history (" + doc_url("docs/release-checklist.md") + ")"

INSTALL = {
    "git": "macOS: xcode-select --install (or brew install git); Debian/Ubuntu: sudo apt-get install git",
    "gitleaks": "brew install gitleaks, or a release binary from github.com/gitleaks/gitleaks/releases",
    "exiftool": "brew install exiftool; Debian/Ubuntu: sudo apt-get install libimage-exiftool-perl",
    "ffprobe": "brew install ffmpeg; Debian/Ubuntu: sudo apt-get install ffmpeg",
    "pdfinfo": "brew install poppler; Debian/Ubuntu: sudo apt-get install poppler-utils",
}

# name, version arguments, what it adds
_HELPERS = (
    ("exiftool", ["-ver"], "more image, PDF and video metadata"),
    ("ffprobe", ["-version"], "video and audio metadata"),
    ("pdfinfo", ["-v"], "PDF metadata when exiftool is missing"),
)


@dataclass
class Check:
    status: str
    text: str
    fix: str = ""


def home_relative(path: Path) -> str:
    """*path* with the home folder shown as ``~`` (keeps the user name out of terminal logs)."""
    try:
        home = Path.home()
    except (RuntimeError, KeyError):  # pragma: no cover - no home directory
        return str(path)
    try:
        resolved = path.resolve() if path.is_absolute() else path
    except OSError:  # pragma: no cover
        resolved = path
    for candidate in (path, resolved):
        if candidate == home:
            return "~"
        if home in candidate.parents:
            return "~/" + candidate.relative_to(home).as_posix()
    return str(path)


def shell_word(shown: str) -> str:
    """A path as printed by the doctor, quoted for a POSIX shell; a leading ``~/`` stays unquoted."""
    if shown == "~":
        return shown
    if shown.startswith("~/"):
        return "~/" + shlex.quote(shown[2:])
    return shlex.quote(shown)


def _contains(root: Path, path: Path) -> bool:
    """True when the resolved *path* is *root* or below it."""
    return path == root or root in path.parents


def tool_version(exe: str, args: Sequence[str]) -> Optional[str]:
    """The first version number in the first line a helper prints, or ``None``."""
    try:
        p = subprocess.run([exe, *args], capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = ((p.stdout or b"").decode("utf-8", "replace").strip()
            or (p.stderr or b"").decode("utf-8", "replace").strip())
    first = text.splitlines()[0] if text else ""
    m = re.search(r"\d+\.\d+(?:\.\d+)?", first)
    return m.group(0) if m else None


def _toml_available() -> bool:
    try:
        tomlcompat.loads("")
    except tomlcompat.TomlUnavailable:
        return False
    return True


def _git(cwd: Path, *args: str) -> Optional[bytes]:
    """Run a read-only git command; ``None`` when it fails."""
    return Repo.git_at(cwd, *args, check=False)


class Doctor:
    """Runs the checks in order; :meth:`run` returns them."""

    def __init__(self, paths: Sequence[Path] = (), *, denylist: Optional[Sequence[str]] = None,
                 config: Optional[str] = None, use_config: bool = True) -> None:
        self.paths = [Path(p) for p in paths] or [Path(".")]
        self.denylist_args = list(denylist) if denylist else None
        self.config = config
        self.use_config = use_config
        self.checks: List[Check] = []
        self.denylist: Optional[Denylist] = None
        self.denylist_paths: List[Path] = []
        self.settings = Settings()
        self.repo_top: Optional[Path] = None
        self.denylist_source = ""
        self.streamed: Set[str] = set()
        """Denylist arguments that are pipes, such as ``--denylist <(...)``: they cannot be read twice."""
        self.home_target = False
        """A path to scan is the home folder or contains it."""
        self._mask: Callable[[str], str] = lambda s: s
        self._default_planned = False

    # -- helpers -------------------------------------------------------------
    def add(self, status: str, text: str, fix: str = "") -> None:
        self.checks.append(Check(status, text, fix))

    def shown(self, path: Path) -> str:
        """A path as the doctor prints it: home-relative and masked with the denylist."""
        return self._mask(home_relative(path))

    def shown_arg(self, path: Path) -> str:
        """A path the user typed: as typed when relative, else home-relative; masked with the denylist."""
        return self._mask(str(path) if not path.is_absolute() else home_relative(path))

    def shell_arg(self, path: Path) -> str:
        """:meth:`shown_arg`, quoted for the shell (a masked path stays masked)."""
        return shell_word(self.shown_arg(path))

    def shown_local(self, path: Path) -> str:
        """A path relative to the working directory when it is below it, else like :meth:`shown`."""
        try:
            return self._mask(path.resolve().relative_to(Path.cwd().resolve()).as_posix())
        except (ValueError, OSError):
            return self.shown(path)

    # -- checks --------------------------------------------------------------
    def run(self) -> List[Check]:
        self.check_python()
        self.check_denylist()
        self.check_targets()
        self.check_config()
        self.check_git()
        self.check_helpers()
        return self.checks

    def check_python(self) -> None:
        v = sys.version_info
        text = f"Python {v.major}.{v.minor}.{v.micro}, prepublish-audit {__version__}"
        if _toml_available():
            self.add(OK, text + " (TOML support)")
        else:
            self.add(WARN, text + ": no TOML parser, so .toml configs and denylists cannot be read",
                     "pipx inject prepublish-audit tomli (or pip install tomli), or use .json and .txt files")

    def check_denylist(self) -> None:
        source, paths = locate_denylists(self.denylist_args)
        self.denylist_source = source
        self.denylist_paths = paths
        if not paths:
            folder = default_denylist_dir()
            where = home_relative(folder / "denylist.txt") if folder else "~/.config/prepublish-audit/denylist.txt"
            self.add(FAIL, "No private denylist found, so a scan would run the built-in rules only",
                     f"prepublish-audit init, then add your own strings to {where} "
                     f"(or pass --denylist FILE, or set {ENV_DENYLIST})")
            return
        error = None
        try:
            denylist = Denylist.load(paths)
        except DenylistError as exc:
            error = str(exc)
        else:
            self.denylist = denylist
            if denylist:
                self._mask = denylist.mask

        missing = [p for p in paths if not p.exists()]
        names = ", ".join(self.shown_local(p) for p in paths)
        if missing:
            fix = (f"export {ENV_DENYLIST}=~/.config/prepublish-audit/denylist.txt (or unset it to use the "
                   "default location)" if source.startswith("$")
                   else "check the path, or create the default file with prepublish-audit init")
            where = ", ".join(self.shown_local(p) for p in missing)
            self.add(FAIL, f"Denylist not found: {where} (from {source})", fix)
            return
        self.add(OK, f"Denylist found: {names} ({source})")

        if error is not None:
            self.add(FAIL, f"Denylist cannot be used: {error}",
                     hint_for(error) or "run prepublish-audit check-denylist and see " + _TROUBLESHOOTING)
        elif not self.denylist:
            self.add(FAIL, "Denylist has no entries yet, so it protects nothing",
                     "add one value per line: account and customer IDs, internal hostnames, people's names, "
                     f"codenames (step 3 of {doc_url('docs/setup.md')}), then run prepublish-audit check-denylist; "
                     "for a pipe such as <(pa_denylist), check that its command prints the list")
        else:
            dl = self.denylist
            kinds = Counter(e.kind for e in dl.entries)
            labelled = sum(1 for e in dl.entries if not e.label.startswith("entry "))
            detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
            self.add(OK, f"Denylist is valid: {len(dl)} {'entry' if len(dl) == 1 else 'entries'} ({detail}), "
                         f"{labelled} labelled")
            for message in dl.warnings:
                if "readable by other users" in message:
                    continue  # reported by the permission check below
                self.add(WARN, f"Denylist: {message}",
                         "remove the duplicate line" if "duplicate" in message
                         else "use a longer value, or word: so that it only matches whole words")

        for i, path in enumerate(paths, 1):
            self._check_permissions(i, path, len(paths) > 1)
            self._check_version_control(i, path, len(paths) > 1)

    def _check_permissions(self, number: int, path: Path, many: bool) -> None:
        which = f"Denylist {number}" if many else "Denylist"
        try:
            mode = path.stat().st_mode
        except OSError:
            return  # reported by the load
        if stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISSOCK(mode):
            self.streamed.add(str(path))
            self.add(OK, f"{which} is streamed (a pipe, not a file on disk)")
        elif not stat.S_ISREG(mode):
            return  # a folder or similar: the load already failed
        elif os.name != "posix":
            self.add(SKIP, f"{which} permissions: not checked on this operating system")
        elif mode & (stat.S_IRWXG | stat.S_IRWXO):
            self.add(FAIL, f"{which} can be read by other users (mode {stat.S_IMODE(mode):o})",
                     f"chmod 600 {self.shown_local(path)}")
        else:
            self.add(OK, f"{which} is private (mode {stat.S_IMODE(mode):o})")

    def _check_version_control(self, number: int, path: Path, many: bool) -> None:
        which = f"Denylist {number}" if many else "Denylist"
        try:
            if not path.is_file() or not shutil.which("git"):
                return
            folder = path.resolve().parent
        except OSError:  # pragma: no cover
            return
        top = _git(folder, "rev-parse", "--show-toplevel")
        if top is None:
            self.add(OK, f"{which} is not inside a git working tree")
            return
        name = path.resolve().name
        if _git(folder, "ls-files", "--error-unmatch", "--", name) is not None:
            self.add(FAIL, f"{which} is tracked by git in the repository that contains it",
                     f"git rm --cached {self.shown_local(path)}, add it to that repository's .gitignore and move "
                     "it to ~/.config/prepublish-audit/; if that repository was ever pushed, treat the entries as "
                     "exposed")
        elif _git(folder, "check-ignore", "-q", "--", name) is not None:
            self.add(OK, f"{which} is inside a git working tree but ignored by git")
        else:
            self.add(WARN, f"{which} is inside a git working tree and not ignored, so 'git add -A' would commit it",
                     "move it to ~/.config/prepublish-audit/, or add it to that repository's .gitignore")

    def check_targets(self) -> None:
        roots: List[Tuple[Path, Path]] = []
        for p in self.paths:
            if p.exists() or p.is_symlink():
                roots.append((p, p.resolve()))
            else:
                self.add(FAIL, f"Path to scan not found: {self.shown_arg(p)}",
                         "pass the folder or file you are going to publish, e.g. prepublish-audit doctor ~/src/myrepo")
        try:
            home: Optional[Path] = Path.home().resolve()
        except (RuntimeError, KeyError, OSError):  # pragma: no cover
            home = None
        files = []
        for path in self.denylist_paths:
            try:
                if path.is_file():
                    files.append((path, path.resolve()))
            except OSError:  # pragma: no cover
                continue
        problems = 0
        for given, root in roots:
            if home is None or not _contains(root, home):
                continue
            # A scan here reads everything the user owns, and finds the default denylist in it.
            self.home_target = True
            inside = sum(1 for _, resolved in files if _contains(root, resolved))
            problems += inside
            if inside:
                text = f"The denylist is inside {self.shown(root)}, which contains your home folder"
            else:
                text = f"{self.shown(root)} is your home folder or contains it, so a scan would read everything in it"
            self.add(WARN, text, "run the doctor inside the repository you are going to publish, or pass its path: "
                                 "prepublish-audit doctor PATH")
        if not files or not roots:
            return
        for path, resolved in files:
            for given, root in roots:
                if not _contains(root, resolved) or (home is not None and _contains(root, home)):
                    continue  # outside, or reported above
                problems += 1
                self.add(FAIL, f"The denylist is inside the tree you are going to scan ({self.shown_arg(given)})",
                         self._move_out_fix(path, [r for _, r in roots]))
        if not problems:
            where = ", ".join(self.shown_arg(given) for given, _ in roots)
            self.add(OK, f"Denylist is outside the path(s) to scan: {where}")

    def _move_out_fix(self, path: Path, roots: Sequence[Path]) -> str:
        """Commands that move *path* to where ``scan`` finds it without options, when that place is free."""
        src = shell_word(self.shown_local(path))
        folder = default_denylist_dir()
        try:
            folder_resolved = folder.resolve() if folder is not None else None
        except OSError:  # pragma: no cover
            folder_resolved = None
        if (folder is None or folder_resolved is None or self._default_planned
                or any((folder / name).exists() for name in DEFAULT_NAMES)
                or any(_contains(root, folder_resolved) for root in roots)):
            return (f"move it outside every repository (for example mv {src} ~/.config/prepublish-audit/, then "
                    f"chmod 600 it) and pass the new path with --denylist or {ENV_DENYLIST}; {_FRESH_HISTORY}")
        self._default_planned = True
        suffix = path.suffix.lower()
        dest_path = folder / ("denylist" + (suffix if suffix in (".toml", ".json") else ".txt"))
        dest = shell_word(self.shown(dest_path))
        then = ""
        if self.denylist_source == "--denylist":
            then = ", then drop --denylist (scan finds the default location)"
        elif self.denylist_source.startswith("$"):
            then = f", then unset {ENV_DENYLIST} (scan finds the default location)"
        return (f"mkdir -p -m 700 {shell_word(self.shown(folder))} && mv {src} {dest} && chmod 600 {dest}{then}; "
                f"{_FRESH_HISTORY}")

    def next_commands(self) -> List[str]:
        """The scan command(s) to run next: the doctor's own options repeated, paths quoted for the shell.

        ``--git-files --history`` only for the top of a git work tree: a gitignored build folder
        scanned with ``--git-files`` would have nothing to read.
        """
        options = ["prepublish-audit", "scan"]
        if self.denylist_args:
            options.append("--require-denylist")  # an empty pipe must stop the scan, not pass it
            for path in self.denylist_paths:
                options.append("--denylist " + ("<(...)" if str(path) in self.streamed else self.shell_arg(path)))
        if self.config:
            options.append("-c " + self.shell_arg(Path(self.config)))
        if not self.use_config:
            options.append("--no-config")
        prefix = " ".join(options)
        top = None
        if self.repo_top is not None:
            try:
                top = self.repo_top.resolve()
            except OSError:  # pragma: no cover
                top = None
        first, rest = self.paths[0], self.paths[1:]
        try:
            first_is_top = top is not None and first.resolve() == top
        except OSError:  # pragma: no cover
            first_is_top = False
        if not first_is_top:
            return [f"{prefix} " + " ".join(self.shell_arg(p) for p in self.paths)]
        commands = [f"{prefix} --git-files --history {self.shell_arg(first)}"]
        if rest:
            commands.append(f"{prefix} " + " ".join(self.shell_arg(p) for p in rest))
        return commands

    def check_config(self) -> None:
        start = self.paths[0]
        try:
            settings = load_settings(Path(self.config) if self.config else None, discover_from=start,
                                     use_config=self.use_config)
        except ConfigError as exc:
            message = str(exc)
            self.add(FAIL, f"Public config is invalid: {self._mask(message)}",
                     hint_for(message) or "see README, 'Configuration reference'")
            settings = Settings()
        else:
            if settings.config_path is not None:
                self.add(OK, f"Public config: {self.shown_local(settings.config_path)}")
            elif not self.use_config:
                self.add(SKIP, "Public config: ignored (--no-config)")
            else:
                self.add(OK, "Public config: none found, built-in defaults apply "
                             "(prepublish-audit init writes a starter .prepublish-audit.toml)")
        if self.denylist:
            settings.keep_denylist_coverage()
        self.settings = settings

    def check_git(self) -> None:
        exe = shutil.which("git")
        if not exe:
            self.add(WARN, "git not found: --git-files and --history need it", INSTALL["git"])
            return
        version = tool_version(exe, ["--version"])
        self.add(OK, f"git {version}" if version else "git found")
        start = self.paths[0]
        if not start.exists():
            return  # already reported by the path check
        try:
            folder = start.resolve() if start.is_dir() else start.resolve().parent
        except OSError:  # pragma: no cover
            return
        out = _git(folder, "rev-parse", "--show-toplevel")
        if out is None:
            self.add(SKIP, f"{self.shown_arg(start)} is not in a git repository: history, commit email and hook "
                           "checks skipped (fine for a site build or a bundle)")
            return
        top = Path(out.decode("utf-8", "surrogateescape").strip())
        self.repo_top = top
        shallow = _git(top, "rev-parse", "--is-shallow-repository")
        if shallow is not None and shallow.strip() == b"true":
            self.add(WARN, "Shallow clone: a --history scan would miss older commits",
                     "git fetch --unshallow (in GitHub Actions: actions/checkout with fetch-depth: 0)")
        else:
            self.add(OK, "Full git history available (not a shallow clone)")
        self._check_identity(top)
        self._check_hooks(top)

    def _check_identity(self, top: Path) -> None:
        emails = set()
        for var in ("GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"):
            out = _git(top, "var", var)
            m = re.search(rb"<([^>]*)>", out or b"")
            if m:
                emails.add(m.group(1).decode("utf-8", "replace").strip().lower())
        if not emails:
            self.add(SKIP, "No commit identity configured in this repository")
        elif all(identity_allowed(e, self.settings) for e in emails):
            self.add(OK, "New commits here use a no-reply email address")
        else:
            self.add(WARN, "New commits here would carry a personal email address (not shown)",
                     "git config user.email \"<id>+<login>@users.noreply.github.com\" (GitHub > Settings > Emails "
                     "shows yours), and turn on 'Block command line pushes that expose my email' there")

    def _check_hooks(self, top: Path) -> None:
        try:
            text = (top / ".pre-commit-config.yaml").read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        wanted = []
        if re.search(r"id:\s*['\"]?prepublish-audit(?![\w-])", text):
            wanted.append(("pre-commit", "pre-commit install"))
        # prepublish-audit-keychain: the local hook from docs/setup.md, step 7 (denylist in the macOS Keychain)
        if re.search(r"id:\s*['\"]?prepublish-audit-(?:history|keychain)\b", text):
            wanted.append(("pre-push", "pre-commit install --hook-type pre-push"))
        if not wanted:
            self.add(SKIP, "No prepublish-audit hook in .pre-commit-config.yaml (optional: "
                           f"{doc_url('examples/pre-commit-config.yaml')})")
            return
        for hook, command in wanted:
            rel = _git(top, "rev-parse", "--git-path", f"hooks/{hook}")
            installed = False
            if rel is not None:
                hook_path = top / rel.decode("utf-8", "surrogateescape").strip()
                try:
                    installed = hook_path.is_file() and "pre-commit" in hook_path.read_text(errors="replace")
                except OSError:  # pragma: no cover
                    installed = False
            if installed:
                self.add(OK, f"{hook} hook installed (pre-commit)")
            else:
                self.add(WARN, f"{hook} hook not installed: .pre-commit-config.yaml lists prepublish-audit, "
                               "but git will not run it", command)

    def check_helpers(self) -> None:
        settings = self.settings
        if settings.gitleaks == "never":
            self.add(SKIP, "gitleaks: turned off in the config (gitleaks = \"never\")")
        else:
            exe = gl.find()
            if exe:
                ver = gl.version(exe)
                self.add(OK, "gitleaks " + (".".join(map(str, ver)) if ver else "found (version unknown)"))
            elif settings.gitleaks == "always":
                self.add(FAIL, "gitleaks not found, but the config requires it (gitleaks = \"always\")",
                         INSTALL["gitleaks"] + "; or set gitleaks = \"auto\"")
            else:
                self.add(WARN, "gitleaks not found (optional: a second secret scanner)", INSTALL["gitleaks"])
        if not settings.external_tools:
            self.add(SKIP, "exiftool, ffprobe and pdfinfo: turned off in the config (external-tools = false)")
            return
        for name, args, purpose in _HELPERS:
            exe = shutil.which(name)
            if exe:
                version = tool_version(exe, args)
                self.add(OK, f"{name} {version}" if version else f"{name} found")
            else:
                self.add(WARN, f"{name} not found (optional: {purpose})", INSTALL[name])


# ---------------------------------------------------------------------------
# Output


def symbols_for(stream: TextIO) -> Dict[str, str]:
    """✓/✗ where the stream can encode them, ASCII labels otherwise."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        "".join(SYMBOLS.values()).encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return ASCII_SYMBOLS
    return SYMBOLS


def render(doctor: Doctor, stream: TextIO, *, color: bool = False, strict: bool = False) -> int:
    """Print the checks; return the exit code (0 = ready, 1 = something to fix)."""
    symbols = symbols_for(stream)
    encoding = getattr(stream, "encoding", None) or "utf-8"

    def paint(text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if color else text

    def w(text: str) -> None:
        if symbols is ASCII_SYMBOLS:  # e.g. a Windows code page: never fail on a path with other letters
            text = text.encode(encoding, "backslashreplace").decode(encoding)
        stream.write(text)

    w(paint(f"prepublish-audit doctor {__version__}", "1") + " (read-only, offline)\n\n")
    for c in doctor.checks:
        w(f"{paint(symbols[c.status], _COLORS[c.status])} {printable(c.text)}\n")
        if c.fix and c.status in (FAIL, WARN):
            w(f"    fix: {printable(c.fix)}\n")
    counts = Counter(c.status for c in doctor.checks)
    failed = counts[FAIL] + (counts[WARN] if strict else 0)
    w(f"\n{counts[OK]} passed, {counts[FAIL]} failed, {counts[WARN]} to review, {counts[SKIP]} skipped")
    w(" (--strict: items to review count as failures)\n" if strict else "\n")
    if failed:
        marks = symbols[FAIL].strip() + (" and " + symbols[WARN].strip() if strict and counts[WARN] else "")
        w(f"Not ready: fix the items marked {marks} and run the doctor again. "
          f"Every message and its fix: {_TROUBLESHOOTING}\n")
        return 1
    if doctor.home_target:
        w("Do not scan there: it contains your home folder. Next: cd into the repository you are going to "
          "publish and run prepublish-audit doctor again.\n")
        return 0
    commands = doctor.next_commands()
    if len(commands) == 1:
        w(f"Ready. Next: {printable(commands[0])}\n")
    else:
        w("Ready. Next:\n" + "".join(f"  {printable(c)}\n" for c in commands))
    if doctor.streamed:
        w("Stream the denylist again the way you did for the doctor: a pipe can be read only once.\n")
    return 0
