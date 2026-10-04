"""Git history mode.

Scans what a push would publish besides the current files:

* every blob reachable from any ref (``git rev-list --all --objects``),
  including files that were deleted or renamed long ago;
* every path that ever existed, including the old names of renamed and
  copied files (``git log --all --name-only --no-renames``);
* commit and tag messages;
* author, committer and tagger names and emails;
* branch, tag and other ref names.

Exclude globs apply to history as they do to the working tree: paths
excluded on the command line are skipped, and paths excluded by the public
config are checked against the denylist only.

Git is only ever run with read-only commands. Lazy fetching in partial
clones is disabled, and repository-configured fsmonitor hooks are switched
off for these calls.
"""

from __future__ import annotations

import os
import subprocess
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from .findings import Finding
from .formats import is_media, sniff
from .rules import COMMIT, REF
from .scanner import DENYLIST_ONLY, EXCLUDED
from .util import human_size

_GIT_CONFIG = ["-c", "core.quotePath=false", "-c", "core.fsmonitor=false", "-c", "log.showSignature=false",
               "-c", "core.pager=cat"]


class GitError(RuntimeError):
    pass


def _env() -> Dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
                "LC_ALL": "C", "LANG": "C", "GIT_PAGER": "cat"})
    return env


@dataclass
class Commit:
    sha: str
    author_name: str
    author_email: str
    committer_name: str
    committer_email: str
    message: str


@dataclass
class Tag:
    ref: str
    tagger_name: str
    tagger_email: str
    message: str


@dataclass
class Identity:
    name: str
    email: str
    roles: Set[str] = field(default_factory=set)
    seen_in: Set[str] = field(default_factory=set)
    first: str = ""


class Repo:
    def __init__(self, path: Path) -> None:
        start = path if path.is_dir() else path.parent
        out = self.git_at(start, "rev-parse", "--show-toplevel", check=False)
        if out is None:
            raise GitError("--history needs a git repository (and git on PATH)")
        self.top = Path(out.decode("utf-8", "surrogateescape").strip())

    @staticmethod
    def git_at(cwd: Path, *args: str, check: bool = True, input: Optional[bytes] = None) -> Optional[bytes]:
        try:
            p = subprocess.run(["git", *_GIT_CONFIG, *args], cwd=cwd, input=input, capture_output=True,
                               env=_env(), timeout=3600, stdin=None if input is not None else subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            if check:
                raise GitError(f"git {args[0]} failed: {exc}") from None
            return None
        if p.returncode != 0:
            if check:
                msg = p.stderr.decode("utf-8", "replace").strip().splitlines()
                raise GitError(f"git {args[0]} failed: {msg[-1] if msg else 'exit ' + str(p.returncode)}")
            return None
        return p.stdout

    def git(self, *args: str, check: bool = True, input: Optional[bytes] = None) -> Optional[bytes]:
        return self.git_at(self.top, *args, check=check, input=input)

    def object_format(self) -> str:
        out = self.git("rev-parse", "--show-object-format", check=False)
        value = out.decode().strip() if out else ""
        return value if value in ("sha1", "sha256") else "sha1"

    def is_shallow(self) -> bool:
        out = self.git("rev-parse", "--is-shallow-repository", check=False)
        return bool(out) and out.decode().strip() == "true"

    def refs(self) -> List[str]:
        out = self.git("for-each-ref", "--format=%(refname)", check=False) or b""
        return [r for r in out.decode("utf-8", "replace").splitlines() if r]

    def commits(self) -> Iterator[Commit]:
        out = self.git("log", "--all", "-z", "--no-color", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B",
                       check=False)
        if not out:
            return
        for record in out.decode("utf-8", "replace").split("\x00"):
            parts = record.split("\x1f", 5)
            if len(parts) != 6:
                continue
            yield Commit(parts[0].strip(), parts[1], parts[2], parts[3], parts[4], parts[5])

    def tags(self) -> Iterator[Tag]:
        out = self.git("for-each-ref", "--format=%(objecttype)%1f%(refname)%1f%(taggername)%1f%(taggeremail)%1f%(contents)%00",
                       "refs/tags", check=False)
        if not out:
            return
        for record in out.decode("utf-8", "replace").split("\x00"):
            parts = record.lstrip("\n").split("\x1f", 4)
            if len(parts) != 5 or parts[0] != "tag":
                continue
            yield Tag(parts[1], parts[2], parts[3].strip("<>"), parts[4])

    def objects(self) -> Tuple["OrderedDict[str, str]", Set[str]]:
        out = self.git("rev-list", "--all", "--objects", "--missing=print", check=False)
        if out is None:
            out = self.git("rev-list", "--all", "--objects", check=False) or b""
        objects: "OrderedDict[str, str]" = OrderedDict()
        paths: Set[str] = set()
        for line in out.decode("utf-8", "surrogateescape").splitlines():
            sha, _, path = line.partition(" ")
            sha = sha.lstrip("?")
            if path:
                paths.add(path)
                objects.setdefault(sha, path)
        return objects, paths

    def all_paths(self) -> Set[str]:
        """Every file path that any commit added, changed, renamed, copied or deleted.

        ``rev-list --objects`` names each blob only once, so the old name of a
        file renamed without changes ("git mv") would be missed. With
        ``--no-renames`` a rename shows up as a deletion of the old name and
        an addition of the new one; ``-m`` covers merge commits and ``--root``
        the first commit, whatever ``log.showRoot`` says.
        """
        out = self.git("log", "--all", "-m", "--root", "--no-renames", "--format=", "--name-only", "-z",
                       check=False) or b""
        return {p.strip("\n") for p in out.decode("utf-8", "surrogateescape").split("\x00") if p.strip("\n")}

    def batch_check(self, shas: Sequence[str]) -> Dict[str, Tuple[str, int]]:
        if not shas:
            return {}
        data = ("\n".join(shas) + "\n").encode()
        out = self.git("cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)", input=data,
                       check=False) or b""
        info: Dict[str, Tuple[str, int]] = {}
        for line in out.decode("utf-8", "replace").splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2].isdigit():
                info[parts[0]] = (parts[1], int(parts[2]))
        return info

    def iter_blobs(self, shas: Sequence[str]) -> Iterator[Tuple[str, Optional[bytes]]]:
        if not shas:
            return
        proc = subprocess.Popen(["git", *_GIT_CONFIG, "cat-file", "--batch"], cwd=self.top, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=_env())

        def feed() -> None:
            try:
                for sha in shas:
                    proc.stdin.write(sha.encode() + b"\n")  # type: ignore[union-attr]
            except (BrokenPipeError, OSError):
                pass  # git stopped reading; the reader loop below ends on EOF
            finally:
                try:
                    proc.stdin.close()  # type: ignore[union-attr]
                except OSError:
                    pass  # already closed

        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        stdout = proc.stdout
        assert stdout is not None
        try:
            for sha in shas:
                header = stdout.readline()
                if not header:
                    break
                parts = header.split()
                if len(parts) < 3:
                    yield sha, None
                    continue
                size = int(parts[2])
                data = stdout.read(size)
                stdout.read(1)
                yield sha, data
        finally:
            stdout.close()
            proc.wait()
            writer.join(timeout=5)

    def first_commits(self, blobs: Set[str]) -> Dict[str, str]:
        """For each blob, the oldest commit whose diff adds or changes it."""
        if not blobs:
            return {}
        proc = subprocess.Popen(["git", *_GIT_CONFIG, "log", "--all", "--no-renames", "--raw", "--no-abbrev", "-m",
                                 "--format=%x00%H"], cwd=self.top, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=_env())
        mapping: Dict[str, str] = {}
        current = ""
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if line.startswith("\x00"):
                current = line[1:].strip()
            elif line.startswith(":") and current:
                parts = line.split("\t", 1)[0].split()
                if len(parts) >= 4 and parts[3] in blobs:
                    mapping[parts[3]] = current
        proc.wait()
        return mapping


def prepare(path: Path) -> Repo:
    return Repo(path.resolve())


def identity_allowed(email: str, settings) -> bool:
    """True for a commit email that is fine to publish (by default only GitHub no-reply addresses)."""
    email = email.strip().lower()
    domain = email.rpartition("@")[2]
    if email in {e.lower() for e in settings.git_identity_emails}:
        return True
    return any(domain == d or domain.endswith("." + d)
               for d in (x.lower().lstrip("*.") for x in settings.git_identity_domains))


def _split_ref(ref: str) -> Tuple[str, str]:
    for ns in ("refs/heads/", "refs/tags/", "refs/remotes/", "refs/notes/", "refs/"):
        if ref.startswith(ns):
            return ns, ref[len(ns):]
    return "", ref


def scan_history(scanner, repo: Repo) -> None:  # noqa: C901 - one linear pass
    """Scan the whole history of *repo* and add findings to *scanner*."""
    engine = scanner.engine
    settings = scanner.settings
    stats = scanner.stats
    reveal = engine.reveal

    if repo.is_shallow():
        rid = "git.shallow-clone"
        if not settings.rule_disabled(rid):
            scanner.add([Finding(rule_id=rid, severity=engine.severity(rid, "warning"),
                                 message="Shallow clone: older history was not scanned (fetch with full depth)",
                                 location="repository", origin="commit")])

    # Ref names
    for i, ref in enumerate(repo.refs(), 1):
        stats.refs += 1
        ns, name = _split_ref(ref)
        shown = ref if reveal else f"{ns}<ref name, {len(name)} chars>"
        for f in engine.scan_text(name, target=REF, match_path=None, display=None, origin="ref",
                                  location=shown, detail="ref name", positions=False):
            f.snippet = ref
            scanner.add([f])

    # Commit and tag messages, identities
    identities: "OrderedDict[Tuple[str, str], Identity]" = OrderedDict()

    def note(name: str, email: str, role: str, where: str) -> None:
        key = (name, email.lower())
        ident = identities.get(key)
        if ident is None:
            ident = identities[key] = Identity(name=name, email=email, first=where)
        ident.roles.add(role)
        ident.seen_in.add(where)
        ident.first = where  # log order is newest first, so the last write is the oldest

    for commit in repo.commits():
        stats.commits += 1
        short = commit.sha[:12]
        for f in engine.scan_text(commit.message, target=COMMIT, match_path=None, display=None, origin="commit",
                                  location=f"commit {short}", detail="commit message"):
            f.commit = commit.sha
            scanner.add([f])
        note(commit.author_name, commit.author_email, "author", commit.sha)
        note(commit.committer_name, commit.committer_email, "committer", commit.sha)
    for n, tag in enumerate(repo.tags(), 1):
        ns, name = _split_ref(tag.ref)
        where = tag.ref if reveal else f"{ns}<tag name, {len(name)} chars>"
        for f in engine.scan_text(tag.message, target=COMMIT, match_path=None, display=None, origin="commit",
                                  location=where, detail="tag message"):
            scanner.add([f])
        if tag.tagger_email or tag.tagger_name:
            note(tag.tagger_name, tag.tagger_email, "tagger", tag.ref)

    for ident in identities.values():
        first = ident.first[:12] if len(ident.first) >= 40 else ident.first
        where = f"commit {first}" if len(ident.first) >= 40 else (ident.first if reveal else "tag")
        roles = "/".join(sorted(ident.roles))
        for f in engine.scan_text(f"{ident.name} <{ident.email}>", target="identity", match_path=None, display=None,
                                  origin="commit", location=where, detail=f"{roles} identity", positions=False):
            scanner.add([f])
        email = ident.email.strip().lower()
        rid = "git.author-identity"
        if (not identity_allowed(email, settings) and not settings.rule_disabled(rid)
                and not engine.allowed(rid, None, None, email)):
            f = Finding(rule_id=rid, severity=engine.severity(rid, "warning"),
                        message=f"{roles.capitalize()} email is not a no-reply address "
                                f"(in {len(ident.seen_in)} commit(s) or tag(s))",
                        location=where, origin="commit", detail=f"{roles} email")
            f.match = ident.email
            f.snippet = f"{ident.name} <{ident.email}>"
            scanner.add([f])

    # Every path that ever existed, and every reachable blob. Paths from git
    # are relative to the repository root; globs and the working-tree paths
    # use the scan's base directory, so convert before comparing.
    top = repo.top.resolve()
    objects, paths = repo.objects()
    paths |= repo.all_paths()
    known = scanner.scanned_paths
    for path in sorted(paths):
        mp = scanner.history_match_path(top, path)
        if mp in known:
            continue
        how = scanner.exclusion(mp)
        if how == EXCLUDED:
            continue
        stats.history_paths += 1
        with scanner.denylist_only(how == DENYLIST_ONLY):
            for f in engine.scan_path(mp, path, origin="history-path", text=path):
                scanner.add([f])
    info = repo.batch_check(list(objects))
    todo: List[str] = []
    for sha, path in objects.items():
        typ, size = info.get(sha, ("missing", 0))
        if typ != "blob":
            continue
        if sha in scanner.blob_ids:
            continue
        mp = scanner.history_match_path(top, path)
        how = scanner.exclusion(mp)
        if how == EXCLUDED:
            continue
        if size > settings.max_file_size:
            if is_media(sniff(b"", path), path):
                stats.skipped.append({"path": f"{path} (history)", "reason": f"blob larger than max-file-size ({human_size(size)})"})
            else:
                scanner.add(scanner.incomplete(f"{path}", f"history blob larger than max-file-size ({human_size(size)})",
                                               mp, "history"))
            continue
        todo.append(sha)
    found: List[Finding] = []
    for sha, data in repo.iter_blobs(todo):
        path = objects.get(sha, sha)
        mp = scanner.history_match_path(top, path)
        if data is None:
            scanner.add(scanner.incomplete(path, "history blob missing (partial clone?)", mp, "history"))
            continue
        stats.history_blobs += 1
        with scanner.denylist_only(scanner.exclusion(mp) == DENYLIST_ONLY):
            blob_findings = scanner.scan_bytes(data, name=path.rsplit("/", 1)[-1], match_path=mp, display=path,
                                               origin="history", depth=0)
        for f in blob_findings:
            f.blob = sha
            f.origin = "history"
            found.append(f)
    found = _collapse(scanner, found)
    if found:
        mapping = repo.first_commits({f.blob for f in found if f.blob})
        for f in found:
            f.commit = mapping.get(f.blob or "")
        scanner.history_findings = len(found)
    scanner.add(found)


def _key(f: Finding) -> Tuple[str, str, str]:
    what = f.message if f.rule_id == "denylist" else f.rule_id
    return (f.path or "", what, (f.match or "").lower())


def _collapse(scanner, found: List[Finding]) -> List[Finding]:
    """One finding per (path, rule, value) across all old versions of a file.

    Issues that the current version of the same file still has are already
    reported for the working tree and are not repeated here; they come back
    as history findings once the file itself is fixed.
    """
    current = {_key(f) for f in scanner.findings if f.origin not in ("history", "history-path", "commit", "ref")}
    kept: "OrderedDict[Tuple[str, str, str], Finding]" = OrderedDict()
    versions: Dict[Tuple[str, str, str], Set[str]] = {}
    repeated = 0
    for f in found:
        key = _key(f)
        if key in current:
            repeated += 1
            continue
        versions.setdefault(key, set()).add(f.blob or "")
        kept.setdefault(key, f)
    for key, f in kept.items():
        n = len(versions.get(key, ()))
        if n > 1:
            f.detail = "; ".join(p for p in (f.detail, f"in {n} versions of this file") if p)
    if repeated:
        scanner.notes.append(
            f"{repeated} history match(es) repeat issues already reported for the current files and are not listed "
            "again. Fixing the files does not remove them from history."
        )
    return list(kept.values())
