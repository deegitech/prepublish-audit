"""Walks trees, reads files and archives, and feeds the engine."""

from __future__ import annotations

import bz2
import contextlib
import gzip
import io
import lzma
import os
import stat
import subprocess
import tarfile
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

from .config import DEFAULT_EXCLUDED_DIRS, Settings
from .denylist import Denylist
from .engine import Engine
from .findings import Finding, assign_fingerprints
from .formats import (
    IMAGE_EXTENSIONS,
    IMAGE_KINDS,
    MEDIA_EXTENSIONS,
    MEDIA_KINDS,
    OFFICE_EXTENSIONS,
    TEXT_KINDS,
    UNSUPPORTED_CONTAINERS,
    UNSUPPORTED_EXTENSIONS,
    decode_text,
    extension,
    is_media,
    iter_strings,
    metadata_region,
    sniff,
    strip_compression_suffix,
)
from .globs import GlobSet
from .metadata import (
    AUTHOR,
    LOCATION,
    OFFICE_TEXT_PARTS,
    SERIAL,
    MetaField,
    Tools,
    builtin_fields,
    is_placeholder_author,
    meaningful_location,
    office_fields,
    pdf_extract,
    xml_attribute_text,
    xml_property_text,
    xml_text,
)
from .rules import BINARY, META, TEXT
from .util import git_blob_id, human_size

_META_RULES = {AUTHOR: "metadata.author", LOCATION: "metadata.location", SERIAL: "metadata.serial"}
_COMPRESSED = ("gzip", "bzip2", "xz")
_HEAD_TAIL = 8 * 1024 * 1024
_ONE_PER_FILE = {"metadata.location", "metadata.serial"}
_OFFICE_PROPERTY_PARTS = {"docProps/core.xml", "docProps/app.xml", "docProps/custom.xml", "meta.xml"}

# How an exclude glob applies to a path.
EXCLUDED = "excluded"            # skipped completely (command line, or config without a denylist)
DENYLIST_ONLY = "denylist-only"  # excluded by the public config: checked against the denylist only


@dataclass
class Stats:
    files: int = 0
    text_files: int = 0
    binary_files: int = 0
    archives: int = 0
    archive_members: int = 0
    metadata_files: int = 0
    bytes: int = 0
    history_blobs: int = 0
    history_paths: int = 0
    commits: int = 0
    refs: int = 0
    excluded: int = 0
    """Files and directories skipped by exclude globs."""
    denylist_only: int = 0
    """Files excluded by the public config that were checked against the denylist only."""
    default_excluded: int = 0
    """Directories skipped by the default excludes (node_modules, virtualenvs, caches...)."""
    skipped: List[Dict[str, str]] = field(default_factory=list)


class ScanError(RuntimeError):
    """A problem that stops the scan (exit code 2)."""


class Scanner:
    def __init__(self, settings: Settings, denylist: Denylist, *, reveal: bool = False,
                 cwd: Optional[Path] = None) -> None:
        self.settings = settings
        self.denylist = denylist
        self.engine = Engine(settings, denylist, reveal=reveal)
        self.findings: List[Finding] = []
        self.notes: List[str] = []
        self.stats = Stats()
        self.tools = Tools(settings.external_tools)
        self.object_format = "sha1"
        self.blob_ids: Set[str] = set()
        self.cwd = (cwd or Path.cwd()).resolve()
        # Command-line excludes are trusted and skip everything. Excludes from
        # the public config narrow the built-in rules only: with a denylist
        # loaded, those paths are still checked against it.
        soft = list(settings.exclude) if denylist else []
        hard = list(settings.cli_exclude) + ([] if denylist else list(settings.exclude))
        self._excludes = GlobSet(hard)
        self._soft_excludes = GlobSet(soft)
        self._skip: Set[Path] = set()
        self._queue: List[Tuple[str, str, str, str, bool]] = []
        self._seen: Dict[str, Set[Tuple[str, str, str]]] = {}
        self._git_dirs: Set[str] = set()
        self.roots: List[str] = []
        self.empty_git_roots: List[str] = []
        """Roots with content where --git-files found nothing git would publish (so nothing was read)."""
        self.scanned_paths: Set[str] = set()
        self.denylist_only_paths: Set[str] = set()
        self.history_findings = 0
        self.history_base: Optional[Path] = None

    # -- helpers -----------------------------------------------------------
    def add(self, findings: Sequence[Finding]) -> None:
        self.findings.extend(findings)

    def exclusion(self, match_path: str) -> Optional[str]:
        """``EXCLUDED``, ``DENYLIST_ONLY`` or ``None`` for a match path."""
        if self._excludes and self._excludes.match(match_path):
            return EXCLUDED
        if self._soft_excludes and self._soft_excludes.match(match_path):
            return DENYLIST_ONLY
        return None

    @contextlib.contextmanager
    def denylist_only(self, active: bool = True) -> Iterator[None]:
        """Check content against the denylist only while the block runs."""
        if not active:
            yield
            return
        previous = self.engine.builtin
        self.engine.builtin = False
        try:
            yield
        finally:
            self.engine.builtin = previous

    def _scan_one(self, match_path: str, scan: Callable[[], None]) -> None:
        """Apply the exclude globs to one file, then run *scan* in the right mode."""
        how = self.exclusion(match_path)
        if how == EXCLUDED:
            self.stats.excluded += 1
            return
        if how == DENYLIST_ONLY:
            self.stats.denylist_only += 1
            self.denylist_only_paths.add(match_path)
        with self.denylist_only(how == DENYLIST_ONLY):
            scan()

    def display_for(self, path: Path, root: Path) -> str:
        try:
            return path.relative_to(self.cwd).as_posix() or "."
        except ValueError:
            pass
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            return path.name
        prefix = root.name if root.name else ""
        if rel in ("", "."):
            return prefix or "."
        return f"{prefix}/{rel}" if prefix else rel

    def match_path_for(self, path: Path, root: Path) -> str:
        """The path that globs (exclude, allow, denylist allow contexts) are matched against.

        Relative to the config file's directory when there is one, otherwise
        to *root* (the scanned folder, or the working directory for files
        named on the command line).
        """
        base = self.settings.base_dir
        if base is not None:
            try:
                return path.relative_to(base).as_posix()
            except ValueError:
                pass
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        return rel if rel not in ("", ".") else path.name

    def history_match_path(self, top: Path, path: str) -> str:
        """Match path for *path* from git history (which is relative to the repository root *top*).

        Converted to the same base as the files on disk, so that one exclude
        or allow glob means the same file in the tree and in history.
        """
        base = self.settings.base_dir or self.history_base
        if base is not None:
            try:
                rel = (top / path).relative_to(base).as_posix()
                return rel if rel not in ("", ".") else path
            except ValueError:
                pass
        return path

    def incomplete(self, display: str, reason: str, match_path: Optional[str] = None,
                   origin: str = "scan") -> List[Finding]:
        rid = "scan.incomplete"
        self.stats.skipped.append({"path": display, "reason": reason})
        if self.settings.rule_disabled(rid) or self.engine.allowed(rid, match_path, None, None):
            return []
        return [Finding(rule_id=rid, severity=self.engine.severity(rid, "warning"),
                        message=f"Not fully scanned: {reason}", path=display, origin=origin, detail=reason)]

    def _embedded_git(self, display: str, match_path: Optional[str], origin: str = "file") -> List[Finding]:
        rid = "leak.embedded-git-dir"
        if not self.engine.builtin or display in self._git_dirs or self.settings.rule_disabled(rid):
            return []
        self._git_dirs.add(display)
        if self.engine.allowed(rid, match_path, None, None):
            return []
        return [Finding(rule_id=rid, severity=self.engine.severity(rid, "warning"),
                        message="Embedded .git directory: it ships the whole history of that repository",
                        path=display, origin=origin)]

    def _binaryish(self, display: Optional[str], findings: List[Finding]) -> List[Finding]:
        """One finding per (place, rule, value) for content without line numbers.

        Binary strings, metadata fields and external tools often see the same
        value several times (EXIF and XMP both carry the author, for example).
        Findings with line numbers are never merged: every occurrence in a
        text file has to be fixed.
        """
        out = []
        for f in findings:
            if f.line is not None:
                out.append(f)
                continue
            seen = self._seen.setdefault(f.path or display or "", set())
            view = "text" if (f.detail or "").startswith(("PDF text", "document text")) else "meta"
            value = "" if f.rule_id in _ONE_PER_FILE else (f.match or "").lower()
            k = (f.rule_id if f.rule_id != "denylist" else f.message, value, view)
            if k in seen:
                continue
            seen.add(k)
            out.append(f)
        return out

    # -- roots ---------------------------------------------------------------
    def check_denylist_location(self, root: Path) -> None:
        for path in self.denylist.files:
            try:
                resolved = Path(path).resolve()
            except OSError:  # pragma: no cover
                continue
            try:
                resolved.relative_to(root)
            except ValueError:
                if resolved != root:
                    continue
            self._skip.add(resolved)
            rid = "config.denylist-in-tree"
            self.add([Finding(rule_id=rid, severity="error",
                              message="The private denylist is inside the scanned tree; move it outside every repository",
                              path=self.display_for(resolved, root), origin="config")])

    def scan_root(self, root: Path, *, git_files: bool = False) -> None:
        root = root.resolve()
        if not root.exists():
            raise ScanError(f"path not found: {self.display_for(root, root.parent)}")
        self.roots.append(self.display_for(root, root.parent))
        if self.history_base is None:
            self.history_base = root if root.is_dir() else root.parent
        self.check_denylist_location(root)
        if root.is_file() or root.is_symlink():
            if root in self._skip:
                return
            # A file named on the command line (pre-commit passes staged files)
            # is matched relative to the working directory, like the files of a
            # directory scan started there, so anchored globs mean the same.
            base = self.cwd if self.cwd in root.parents else root.parent
            mp = self.match_path_for(root, base)
            self._scan_one(mp, lambda: self.scan_file(root, mp, self.display_for(root, base)))
            return
        if git_files:
            self._scan_git_files(root)
        else:
            self._walk(root)

    def _default_excluded(self, display: str) -> None:
        self.stats.default_excluded += 1
        self.stats.skipped.append({"path": display, "reason": "default-excluded directory (scan it with "
                                                              "--no-default-excludes)"})

    def _walk(self, root: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(root):
            here = Path(dirpath)
            keep = []
            for d in sorted(dirnames):
                full = here / d
                mp = self.match_path_for(full, root)
                disp = self.display_for(full, root)
                how = self.exclusion(mp)
                if how == EXCLUDED:
                    self.stats.excluded += 1
                    continue
                if full.is_symlink():
                    with self.denylist_only(how == DENYLIST_ONLY):
                        self._scan_symlink(full, mp, disp)
                    continue
                if d == ".git":
                    if here != root:
                        with self.denylist_only(how == DENYLIST_ONLY):
                            self.add(self._embedded_git(disp + "/", mp))
                    continue
                if self.settings.default_excludes and d in DEFAULT_EXCLUDED_DIRS:
                    self._default_excluded(disp + "/")
                    continue
                keep.append(d)
            dirnames[:] = keep
            for name in sorted(filenames):
                full = here / name
                if name == ".git" and here == root:
                    continue
                if full.resolve() in self._skip:
                    continue
                mp = self.match_path_for(full, root)
                self._scan_one(mp, lambda: self.scan_file(full, mp, self.display_for(full, root)))

    def _scan_git_files(self, root: Path) -> None:
        try:
            out = subprocess.run(
                ["git", "-c", "core.quotePath=false", "-c", "core.fsmonitor=false", "ls-files", "-z",
                 "--cached", "--others", "--exclude-standard"],
                cwd=root, stdin=subprocess.DEVNULL, capture_output=True, timeout=600,
                env=_git_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScanError(f"--git-files needs git: {exc}") from None
        if out.returncode != 0:
            raise ScanError("--git-files: not inside a git work tree (or git failed)")
        names = sorted({n for n in out.stdout.decode("utf-8", "surrogateescape").split("\x00") if n})
        if not names and any(root.iterdir()):
            shown = self.display_for(root, root.parent)
            self.empty_git_roots.append(shown)
            self.notes.append(
                f"--git-files: git would publish nothing under {shown} "
                "(ignored or outside the work tree); run without --git-files to scan what is on disk."
            )
        for rel in names:
            full = root / rel
            if not full.exists() and not full.is_symlink():
                continue
            if full.is_dir() and not full.is_symlink():
                continue  # submodule
            if full.resolve() in self._skip:
                continue
            mp = self.match_path_for(full, root)
            self._scan_one(mp, lambda: self.scan_file(full, mp, self.display_for(full, root)))

    # -- files -------------------------------------------------------------------
    def _scan_symlink(self, path: Path, match_path: str, display: str) -> None:
        self.stats.files += 1
        self.scanned_paths.add(match_path)
        self.add(self.engine.scan_path(match_path, display))
        self._symlink_target(path, match_path, display)

    def _symlink_target(self, path: Path, match_path: str, display: str) -> None:
        """A symlink is published as its target path (git stores it as the blob)."""
        try:
            target = os.readlink(path)
        except OSError:
            self.add(self.incomplete(display, "symlink could not be read", match_path))
            return
        self.add(self.engine.scan_text(target, target=TEXT, match_path=match_path, display=display,
                                       origin="symlink", detail="symlink target", positions=False))

    def scan_file(self, path: Path, match_path: str, display: str) -> None:
        self.stats.files += 1
        self.scanned_paths.add(match_path)
        self.add(self.engine.scan_path(match_path, display))
        try:
            st = os.lstat(path)
        except OSError:
            self.add(self.incomplete(display, "could not be read", match_path))
            return
        if stat.S_ISLNK(st.st_mode):
            self._symlink_target(path, match_path, display)
            return
        if not stat.S_ISREG(st.st_mode):
            return
        size = st.st_size
        self.stats.bytes += size
        try:
            with open(path, "rb") as fh:
                head = fh.read(65536)
        except OSError:
            self.add(self.incomplete(display, "could not be read (permission denied?)", match_path))
            return
        kind = sniff(head, path.name)
        ext = extension(path.name)
        if kind in UNSUPPORTED_CONTAINERS or ext in UNSUPPORTED_EXTENSIONS:
            self.add(self.incomplete(display, "unsupported archive or disk-image format", match_path))
            return
        if kind in ("zip", "tar") + _COMPRESSED:
            if not self.settings.archives:
                self.add(self.incomplete(display, "archive scanning is disabled", match_path))
                return
            if size > self.settings.max_archive_size:
                self.add(self.incomplete(display, f"archive larger than max-archive-size ({human_size(size)})", match_path))
                return
            self.stats.binary_files += 1
            if size <= self.settings.max_file_size:
                data = path.read_bytes()
                self.blob_ids.add(git_blob_id(data, self.object_format))
                self.add(self._binaryish(display, self._archive(data, kind, path.name, match_path, display, 0, "file")))
            else:
                with open(path, "rb") as fh:
                    self.add(self._binaryish(display, self._archive(fh, kind, path.name, match_path, display, 0, "file")))
            return
        if size > self.settings.max_file_size:
            if is_media(kind, path.name) or kind == "font":
                self._large_media(path, kind, match_path, display, size)
            else:
                self.add(self.incomplete(display, f"larger than max-file-size ({human_size(size)})", match_path))
            return
        try:
            data = path.read_bytes()
        except OSError:
            self.add(self.incomplete(display, "could not be read", match_path))
            return
        self.blob_ids.add(git_blob_id(data, self.object_format))
        self.add(self.scan_bytes(data, name=path.name, match_path=match_path, display=display,
                                 origin="file", depth=0, kind=kind, on_disk=str(path)))

    def _large_media(self, path: Path, kind: str, match_path: str, display: str, size: int) -> None:
        self.stats.binary_files += 1
        fields: List[MetaField] = []
        try:
            with open(path, "rb") as fh:
                head = fh.read(_HEAD_TAIL)
                fh.seek(max(0, size - _HEAD_TAIL))
                tail = fh.read(_HEAD_TAIL)
        except OSError:
            self.add(self.incomplete(display, "could not be read", match_path))
            return
        fields.extend(builtin_fields(head, kind))
        fields.extend(builtin_fields(tail, kind))
        fields.extend(self._tool_fields(str(path), kind, path.name, match_path, display, "file"))
        self.stats.skipped.append({"path": display, "reason": f"content larger than max-file-size ({human_size(size)}); metadata checked"})
        if fields:
            self.stats.metadata_files += 1
        self.add(self._binaryish(display, self.metadata_findings(fields, match_path, display, "file")))

    def _tool_fields(self, on_disk: str, kind: str, name: str, match_path: str, display: str,
                     origin: str) -> List[MetaField]:
        ext = extension(name)
        media = kind in MEDIA_KINDS or ext in MEDIA_EXTENSIONS
        image = kind in IMAGE_KINDS or ext in IMAGE_EXTENSIONS
        fields: List[MetaField] = []
        if self.tools.exiftool and (media or image or kind == "pdf"):
            self._queue.append((on_disk, match_path, display, origin, self.engine.builtin))
        if kind == "pdf" and not self.tools.exiftool and self.tools.pdfinfo:
            fields.extend(self.tools.pdfinfo_fields(on_disk))
        if media and self.tools.ffprobe:
            fields.extend(self.tools.ffprobe_fields(on_disk))
        return fields

    # -- bytes ---------------------------------------------------------------------
    def scan_bytes(self, data: bytes, *, name: str, match_path: str, display: str, origin: str, depth: int,
                   kind: Optional[str] = None, on_disk: Optional[str] = None) -> List[Finding]:
        kind = kind or sniff(data[:65536], name)
        top_level = origin == "file"  # archive members and history blobs have their own counters
        if kind in TEXT_KINDS:
            if top_level:
                self.stats.text_files += 1
            return self.engine.scan_text(decode_text(data, kind), target=TEXT, match_path=match_path,
                                         display=display, origin=origin)
        if top_level:
            self.stats.binary_files += 1
        if kind in ("zip", "tar") + _COMPRESSED:
            return self._binaryish(display, self._archive(data, kind, name, match_path, display, depth, origin))
        if kind in UNSUPPORTED_CONTAINERS:
            return self.incomplete(display, "unsupported archive format", match_path, origin)
        out: List[Finding] = []
        fields: List[MetaField] = []
        if kind == "pdf":
            pdf_fields, pdf_text = pdf_extract(data)
            fields.extend(pdf_fields)
            if pdf_text:
                out.extend(self.engine.scan_text(pdf_text, target=TEXT, match_path=match_path, display=display,
                                                 origin=origin, detail="PDF text (best effort)", positions=False))
        fields.extend(builtin_fields(data, kind))
        if on_disk:
            fields.extend(self._tool_fields(on_disk, kind, name, match_path, display, origin))
        if fields:
            self.stats.metadata_files += 1
            out.extend(self.metadata_findings(fields, match_path, display, origin))
        # Every printable run is checked, in chunks, however large the file.
        for strings, offsets in iter_strings(metadata_region(data, kind)):
            found = self.engine.scan_text(strings, target=BINARY, match_path=match_path, display=display,
                                          origin=origin if origin == "history" else "binary")
            for f in found:
                if f.line:
                    offset = offsets[f.line - 1] if f.line - 1 < len(offsets) else None
                    extra = f"byte offset {offset}" if offset is not None else None
                    f.detail = "; ".join(p for p in (f.detail, extra) if p) or None
                f.line = f.column = f.end_column = None
            out.extend(found)
        return self._binaryish(display, out)

    def metadata_findings(self, fields: Sequence[MetaField], match_path: str, display: str,
                          origin: str) -> List[Finding]:
        meta_origin = "history" if origin == "history" else "metadata"
        out: List[Finding] = []
        seen: Set[Tuple[str, str]] = set()
        names: Set[str] = set()
        for fld in fields:
            if fld.name not in names:
                # Field names come from the file as well (PNG keywords, custom
                # document properties, ffprobe tag keys), so check them too.
                names.add(fld.name)
                out.extend(self.engine.scan_text(fld.name, target=META, match_path=match_path, display=display,
                                                 origin=meta_origin, detail="metadata field name",
                                                 positions=False))
            value = fld.value.strip()
            if not value:
                continue
            rid = _META_RULES.get(fld.kind) if self.engine.builtin else None
            if rid and (fld.kind, value.lower()) not in seen:
                seen.add((fld.kind, value.lower()))
                skip = (fld.kind == AUTHOR and is_placeholder_author(value)) or \
                       (fld.kind == LOCATION and not meaningful_location(value))
                if not skip and not self.settings.rule_disabled(rid) and \
                        not self.engine.allowed(rid, match_path, fld.name, value):
                    rule = self.engine.catalogue[rid]
                    f = Finding(rule_id=rid, severity=self.engine.severity(rid, rule.severity),
                                message=f"{rule.title} ({fld.name})", path=display, origin=meta_origin,
                                detail=fld.name)
                    f.match = value
                    f.snippet = f"{fld.name}: {value}"
                    out.append(f)
            out.extend(self.engine.scan_text(value, target=META, match_path=match_path, display=display,
                                             origin=meta_origin, detail=fld.name, positions=False))
        return out

    # -- archives ------------------------------------------------------------------
    def _archive(self, source: Union[bytes, BinaryIO], kind: str, name: str, match_path: str, display: str,
                 depth: int, origin: str) -> List[Finding]:
        if depth >= self.settings.max_archive_depth:
            return self.incomplete(display, "nested deeper than max-archive-depth", match_path, origin)
        self.stats.archives += 1
        stream: BinaryIO = io.BytesIO(source) if isinstance(source, (bytes, bytearray)) else source
        if kind == "zip":
            return self._zip(stream, name, match_path, display, depth + 1, origin)
        try:
            stream.seek(0)
            tf = tarfile.open(fileobj=stream, mode="r:*")
        except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
            tf = None
        if tf is not None:
            with tf:
                return self._tar(tf, match_path, display, depth + 1, origin)
        if kind in _COMPRESSED:
            stream.seek(0)
            inner_name = strip_compression_suffix(name) or (name + ".out")
            cap = self.settings.max_file_size
            try:
                if kind == "gzip":
                    data = gzip.GzipFile(fileobj=stream).read(cap + 1)
                elif kind == "bzip2":
                    data = bz2.BZ2File(stream).read(cap + 1)
                else:
                    data = lzma.LZMAFile(stream).read(cap + 1)
            except (OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
                return self.incomplete(display, "damaged compressed file", match_path, origin)
            if len(data) > cap:
                return self.incomplete(display, "decompressed size exceeds max-file-size", match_path, origin)
            inner_origin = origin if origin == "history" else "archive"
            return self.scan_bytes(data, name=inner_name, match_path=f"{match_path}/{inner_name}",
                                   display=f"{display}!/{inner_name}", origin=inner_origin, depth=depth + 1)
        return self.incomplete(display, "damaged tar archive", match_path, origin)

    def _member_limits(self, mname: str, size: int, csize: int, mdisp: str, mmp: str,
                       origin: str) -> Optional[List[Finding]]:
        if size > self.settings.max_file_size:
            if is_media(sniff(b"", mname), mname):
                self.stats.skipped.append({"path": mdisp, "reason": "media member larger than max-file-size"})
                return []
            return self.incomplete(mdisp, "archive member larger than max-file-size", mmp, origin)
        if csize and size > 1024 * 1024 and size / max(1, csize) > 200:
            return self.incomplete(mdisp, "compression ratio suggests a decompression bomb", mmp, origin)
        return None

    def _zip(self, stream: BinaryIO, name: str, match_path: str, display: str, depth: int,
             origin: str) -> List[Finding]:
        out: List[Finding] = []
        member_origin = origin if origin == "history" else "archive"
        try:
            zf = zipfile.ZipFile(stream)
        except (zipfile.BadZipFile, OSError, ValueError, EOFError):
            return self.incomplete(display, "damaged zip archive", match_path, origin)
        with zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            office = ("[Content_Types].xml" in names or "mimetype" in names) and \
                any(n.startswith(("docProps/", "word/", "ppt/", "xl/")) or n in ("meta.xml", "content.xml") for n in names)
            if not office and name.lower().endswith(OFFICE_EXTENSIONS) and "mimetype" in names:
                office = True
            budget = self.settings.max_archive_size

            def read_text(member: str) -> Optional[str]:
                try:
                    info = zf.getinfo(member)
                except KeyError:
                    return None
                if info.file_size > self.settings.max_file_size or info.flag_bits & 0x1:
                    return None
                try:
                    with zf.open(info) as fh:
                        return fh.read(self.settings.max_file_size).decode("utf-8", "replace")
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, OSError, EOFError):
                    return None

            if office:
                fields = office_fields(read_text, names)
                if fields:
                    self.stats.metadata_files += 1
                    out.extend(self.metadata_findings(fields, match_path, display, origin))
            for info in infos:
                mname = info.filename.replace("\\", "/").lstrip("/")
                if not mname:
                    continue
                mmp = f"{match_path}/{mname.rstrip('/')}"
                mdisp = f"{display}!/{mname}"
                parts = mname.rstrip("/").split("/")
                if ".git" in parts:
                    idx = parts.index(".git")
                    out.extend(self._embedded_git(f"{display}!/{'/'.join(parts[:idx + 1])}/", mmp, member_origin))
                    continue
                if mname.endswith("/"):
                    continue
                self.stats.archive_members += 1
                out.extend(self.engine.scan_path(mmp, mdisp, origin=member_origin))
                if info.flag_bits & 0x1:
                    out.extend(self.incomplete(mdisp, "encrypted archive member", mmp, member_origin))
                    continue
                limited = self._member_limits(mname, info.file_size, info.compress_size, mdisp, mmp, member_origin)
                if limited is not None:
                    out.extend(limited)
                    continue
                if budget - info.file_size < 0:
                    out.extend(self.incomplete(display, "archive exceeds max-archive-size; remaining members skipped",
                                               match_path, origin))
                    break
                try:
                    with zf.open(info) as fh:
                        data = fh.read(self.settings.max_file_size + 1)
                except (RuntimeError, NotImplementedError, zipfile.BadZipFile, zlib.error, OSError, EOFError):
                    out.extend(self.incomplete(mdisp, "archive member could not be extracted", mmp, member_origin))
                    continue
                budget -= len(data)
                if office and mname in _OFFICE_PROPERTY_PARTS:
                    # office_fields() classified the known fields above; this
                    # checks everything else in the part: custom property
                    # names, ODF user-defined fields, TitlesOfParts,
                    # dc:identifier... Matches already reported for a field are
                    # merged by _binaryish (same place, rule and value).
                    text = xml_property_text(data.decode("utf-8", "replace"))
                    out.extend(self.engine.scan_text(text, target=META, match_path=match_path, display=display,
                                                     origin="history" if origin == "history" else "metadata",
                                                     detail="document properties", positions=False))
                    continue
                if office and OFFICE_TEXT_PARTS.match(mname):
                    xml = data.decode("utf-8", "replace")
                    out.extend(self.engine.scan_text(xml_text(xml), target=TEXT, match_path=mmp, display=mdisp,
                                                     origin=member_origin, detail="document text"))
                    # Alt text, hyperlink fields and bookmark names are attributes.
                    out.extend(self.engine.scan_text(xml_attribute_text(xml), target=META, match_path=mmp,
                                                     display=mdisp, origin=member_origin,
                                                     detail="document markup", positions=False))
                    continue
                out.extend(self.scan_bytes(data, name=mname, match_path=mmp, display=mdisp,
                                           origin=member_origin, depth=depth))
        return out

    def _tar(self, tf: tarfile.TarFile, match_path: str, display: str, depth: int, origin: str) -> List[Finding]:
        out: List[Finding] = []
        member_origin = origin if origin == "history" else "archive"
        budget = self.settings.max_archive_size
        while True:
            try:
                member = tf.next()
            except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
                out.extend(self.incomplete(display, "damaged tar archive", match_path, origin))
                break
            if member is None:
                break
            mname = member.name.replace("\\", "/").lstrip("/")
            while mname.startswith("./"):
                mname = mname[2:]
            if not mname:
                continue
            mmp = f"{match_path}/{mname}"
            mdisp = f"{display}!/{mname}"
            parts = mname.split("/")
            if ".git" in parts:
                idx = parts.index(".git")
                out.extend(self._embedded_git(f"{display}!/{'/'.join(parts[:idx + 1])}/", mmp, member_origin))
                continue
            if member.isdir():
                continue
            self.stats.archive_members += 1
            out.extend(self.engine.scan_path(mmp, mdisp, origin=member_origin))
            if member.issym() or member.islnk():
                out.extend(self.engine.scan_text(member.linkname, target=TEXT, match_path=mmp, display=mdisp,
                                                 origin=member_origin, detail="link target", positions=False))
                continue
            if not member.isfile():
                continue
            limited = self._member_limits(mname, member.size, 0, mdisp, mmp, member_origin)
            if limited is not None:
                out.extend(limited)
                continue
            if budget - member.size < 0:
                out.extend(self.incomplete(display, "archive exceeds max-archive-size; remaining members skipped",
                                           match_path, origin))
                break
            try:
                fh = tf.extractfile(member)
                data = fh.read(self.settings.max_file_size + 1) if fh else b""
            except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError, ValueError):
                out.extend(self.incomplete(mdisp, "archive member could not be extracted", mmp, member_origin))
                continue
            budget -= len(data)
            out.extend(self.scan_bytes(data, name=mname, match_path=mmp, display=mdisp, origin=member_origin,
                                       depth=depth))
        return out

    # -- finishing -----------------------------------------------------------------
    def flush_external(self) -> None:
        if not self._queue:
            return
        by_path = {item[0]: item for item in self._queue}
        results = self.tools.exiftool_batch(list(by_path))
        for path, fields in results.items():
            item = by_path.get(path)
            if not item or not fields:
                continue
            _, mp, disp, origin, builtin = item
            with self.denylist_only(not builtin):
                self.add(self._binaryish(disp, self.metadata_findings(fields, mp, disp, origin)))
        self._queue.clear()

    def finish(self) -> List[Finding]:
        self.flush_external()
        for tool, count in sorted(self.tools.failures.items()):
            self.notes.append(f"{tool} failed on {count} invocation(s); built-in parsers were used for those files.")
        if self.stats.default_excluded:
            self.notes.append(f"Skipped {self.stats.default_excluded} default-excluded "
                              f"director{'y' if self.stats.default_excluded == 1 else 'ies'} (node_modules, "
                              "virtualenvs, caches, VCS folders); use --no-default-excludes to scan them.")
        if self.stats.denylist_only:
            self.notes.append(f"{self.stats.denylist_only} file(s) excluded by the public config were checked "
                              "against the denylist only. Use --exclude on the command line to skip a path completely.")
        # Fingerprints hash the masked path: a short denylist entry in a file
        # name must not be recoverable from a redacted report by brute force.
        assign_fingerprints(self.findings, mask=self.denylist.mask if self.denylist else None)
        return self.findings


def _git_env() -> Dict[str, str]:
    env = dict(os.environ)
    env.update({"GIT_TERMINAL_PROMPT": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_OPTIONAL_LOCKS": "0",
                "LC_ALL": "C", "LANG": "C"})
    return env
