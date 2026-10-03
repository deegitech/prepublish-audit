"""The private denylist: parsing, matching and allow contexts.

The denylist holds the exact strings and patterns that must never leave your
organisation: account and customer IDs, internal host and product names,
people's names, card digits and so on. It is private by design:

* keep it outside every tree you scan (the scanner reports it as an error if
  it finds it inside one);
* reports never print an entry, not even in error messages. They refer to an
  entry by its label or by its number and line.

Text format (``.txt`` or any other extension), one entry per line::

    # Comments are whole lines that start with '#'. Blank lines are ignored.
    # A plain line is a literal, matched case-insensitively anywhere:
    Acme Internal
    # "re:" starts a Python regular expression (case-insensitive):
    re:\\bacct-\\d{6,}\\b
    # "word:" is a literal that must not touch other letters or digits:
    word:4242
    # "loose:" also matches the entry with spaces, dots, dashes or
    # underscores between its words, or with none at all:
    loose:project falcon
    # "lit:" is the escape hatch for a literal that looks like syntax:
    lit:# not a comment
    # Indented "label:" and "allow:" lines belong to the entry above them:
    Acme Corp
      label: company name
      allow: LICENSE
      allow: README.md section=^About

There are no inline comments: everything after the prefix is the entry.

Structured formats (``.toml`` or ``.json``) carry the same information::

    [[entries]]
    literal = "Acme Corp"
    label = "company name"
    allow = [{ path = "LICENSE" }, { path = "README.md", section = "^About" }]
"""

from __future__ import annotations

import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Pattern, Sequence, Tuple

from . import tomlcompat
from .globs import compile_glob

MIN_ENTRY_LENGTH = 3
ENV_DENYLIST = "PREPUBLISH_AUDIT_DENYLIST"
DEFAULT_NAMES = ("denylist.txt", "denylist.toml", "denylist.json")
_KINDS = ("literal", "regex", "word", "loose")
_PREFIXES = (
    ("re:", "regex"),
    ("regex:", "regex"),
    ("word:", "word"),
    ("loose:", "loose"),
    ("lit:", "literal"),
    ("literal:", "literal"),
)
_SEPARATORS = re.compile(r"([\s._-]+)")
_WHITESPACE = re.compile(r"(\s+)")
_DIRECTIVE = re.compile(r"^(allow|label)\s*:(.*)$", re.IGNORECASE)
_OPTION = re.compile(r"(?:^|\s)(line|section)=")
# The only non-ASCII characters that case-insensitive regular expressions
# treat as equal to ASCII letters: dotted and dotless I (Turkish), long s and
# the Kelvin sign. str.lower() does not fold them the same way, so texts that
# contain one take the regular-expression path.
_FOLDS_TO_ASCII = re.compile("[İıſK]")
# Pieces of a regex error message that can quote the pattern: quoted group
# names, escape sequences and the characters after phrases such as
# "bad character range" or "unknown extension".
_RE_MSG_QUOTED = re.compile(r"'[^']*'|\"[^\"]*\"")
_RE_MSG_ESCAPE = re.compile(r"\\\S*")
_RE_MSG_DETAIL = re.compile(r"\b(bad character range|unknown extension|bad inline flags?|octal escape value)\b.*$")


class DenylistError(ValueError):
    """An unusable denylist. Messages never contain entry text."""


def default_denylist_dir() -> Optional[Path]:
    """``$XDG_CONFIG_HOME/prepublish-audit``, by default ``~/.config/prepublish-audit``."""
    base = os.environ.get("XDG_CONFIG_HOME")
    if base:
        return Path(base) / "prepublish-audit"
    try:
        return Path.home() / ".config" / "prepublish-audit"
    except (RuntimeError, KeyError):  # pragma: no cover - no home directory
        return None


def locate_denylists(explicit: Optional[Sequence[str]] = None) -> Tuple[str, List[Path]]:
    """Where the denylist comes from, first match wins, and the files found there.

    Returns ``(source, paths)`` with *source* one of ``"--denylist"``,
    ``"$PREPUBLISH_AUDIT_DENYLIST"`` or ``"default location"``. Explicit and
    environment paths are returned as given, even when they do not exist, so
    that loading them reports the problem; the default location only returns
    files that exist.
    """
    if explicit:
        return "--denylist", [Path(p).expanduser() for p in explicit]
    env = os.environ.get(ENV_DENYLIST, "")
    if env.strip():
        return f"${ENV_DENYLIST}", [Path(p).expanduser() for p in env.split(os.pathsep) if p.strip()]
    folder = default_denylist_dir()
    if folder is None:
        return "default location", []
    return "default location", [folder / name for name in DEFAULT_NAMES if (folder / name).is_file()]


def _safe_regex_message(exc: re.error) -> str:
    """The error message of *exc* without any part of the pattern."""
    msg = _RE_MSG_QUOTED.sub("<...>", exc.msg or "invalid pattern")
    msg = _RE_MSG_ESCAPE.sub(lambda m: "\\...", msg)
    return _RE_MSG_DETAIL.sub(lambda m: m.group(1), msg).strip()


@dataclass(frozen=True)
class AllowContext:
    """Where an entry may legitimately appear."""

    path: str
    line: Optional[str] = None
    section: Optional[str] = None

    def compile(self) -> "CompiledAllow":
        return CompiledAllow(
            path=compile_glob(self.path),
            line=re.compile(self.line) if self.line else None,
            section=re.compile(self.section, re.IGNORECASE) if self.section else None,
        )


@dataclass(frozen=True)
class CompiledAllow:
    path: Pattern[str]
    line: Optional[Pattern[str]]
    section: Optional[Pattern[str]]


@dataclass
class Entry:
    number: int
    kind: str
    value: str = field(repr=False)
    source: int = 1
    line: Optional[int] = None
    label: str = ""
    allow: List[AllowContext] = field(default_factory=list)
    needle: Optional[str] = field(default=None, repr=False)
    regex: Optional[Pattern[str]] = field(default=None, repr=False)
    fallback: Optional[Pattern[str]] = field(default=None, repr=False)
    compiled_allow: List[CompiledAllow] = field(default_factory=list, repr=False)

    def __str__(self) -> str:  # never reveal the value
        return self.label

    @property
    def needs_sections(self) -> bool:
        return any(a.section is not None for a in self.compiled_allow)

    def find(self, text: str, lower: Optional[str]) -> Iterator[Tuple[int, int]]:
        """Yield (start, end) offsets of every match in *text*.

        *lower* is ``text.lower()`` when a plain substring search in it gives
        the same result as a case-insensitive regular expression (true for
        nearly every input); otherwise ``None``.
        """
        if self.needle is not None and lower is not None:
            needle = self.needle
            size = len(needle)
            i = lower.find(needle)
            while i != -1:
                yield i, i + size
                i = lower.find(needle, i + size)
            return
        rx = self.regex if self.regex is not None else self.fallback
        if rx is None:  # pragma: no cover - compile() always sets one
            return
        for m in rx.finditer(text):
            if m.end() > m.start():
                yield m.start(), m.end()

    def allowed(self, path: Optional[str], line: Optional[str],
                sections: Optional[Sequence[str]]) -> bool:
        for a in self.compiled_allow:
            if path is None or not a.path.match(path):
                continue
            if a.line is not None and (line is None or not a.line.search(line)):
                continue
            if a.section is not None:
                if not sections or not any(a.section.search(s) for s in sections):
                    continue
            return True
        return False


def _literal_pattern(value: str) -> str:
    parts = _WHITESPACE.split(value)
    out = []
    for i, part in enumerate(parts):
        out.append(r"\s+" if i % 2 else re.escape(part))
    return "".join(out)


def _loose_pattern(value: str) -> str:
    parts = _SEPARATORS.split(value)
    out = []
    last = len(parts) - 1
    for i, part in enumerate(parts):
        if i % 2 == 0:
            out.append(re.escape(part))
            continue
        leading = i == 1 and parts[0] == ""
        trailing = i == last - 1 and parts[last] == ""
        out.append(re.escape(part) if (leading or trailing) else r"[\s._-]*")
    return "".join(out)


def _compile(entry: Entry, where: str) -> None:
    value = entry.value
    flags = re.IGNORECASE | re.MULTILINE
    try:
        if entry.kind == "regex":
            entry.regex = re.compile(value, flags)
        elif entry.kind == "word":
            entry.regex = re.compile(r"(?<![^\W_])" + _literal_pattern(value) + r"(?![^\W_])", flags)
        elif entry.kind == "loose" and any(ch.isalnum() for ch in value):
            entry.regex = re.compile(_loose_pattern(value), flags)
        elif re.search(r"\s", value):
            entry.regex = re.compile(_literal_pattern(value), flags)
        elif value.isascii():
            # Fast path: substring search in the lower-cased text.
            entry.needle = value.lower()
            entry.fallback = re.compile(re.escape(value), flags)
        else:
            # str.lower() is not a case-insensitive comparison for every
            # alphabet (Turkish I/ı/İ, for example); the regex engine is.
            entry.regex = re.compile(re.escape(value), flags)
    except re.error as exc:
        position = f" at position {exc.pos}" if exc.pos is not None else ""
        raise DenylistError(f"{where}: invalid regular expression ({_safe_regex_message(exc)}{position})") from None
    if entry.regex is not None and entry.regex.search("") is not None:
        raise DenylistError(f"{where}: pattern matches the empty string")
    try:
        entry.compiled_allow = [a.compile() for a in entry.allow]
    except re.error as exc:
        raise DenylistError(f"{where}: invalid allow regular expression ({_safe_regex_message(exc)})") from None
    except ValueError as exc:
        raise DenylistError(f"{where}: invalid allow path ({exc})") from None


def _split_prefix(raw: str) -> Tuple[str, str]:
    lowered = raw.lower()
    for prefix, kind in _PREFIXES:
        if lowered.startswith(prefix):
            return kind, raw[len(prefix):].strip() if kind != "regex" else raw[len(prefix):]
    return "literal", raw


def _parse_allow(rest: str, where: str) -> AllowContext:
    rest = rest.strip()
    if not rest:
        raise DenylistError(f"{where}: 'allow:' needs a path pattern")
    path, _, options = rest.partition(" ")
    options = options.strip()
    values: Dict[str, str] = {}
    if options:
        found = list(_OPTION.finditer(options))
        if not found or options[: found[0].start()].strip():
            raise DenylistError(f"{where}: unknown 'allow:' option (use line=<regex> or section=<regex>)")
        for i, m in enumerate(found):
            key = m.group(1)
            end = found[i + 1].start() if i + 1 < len(found) else len(options)
            if key in values:
                raise DenylistError(f"{where}: '{key}=' given twice")
            values[key] = options[m.end():end].strip()
            if not values[key]:
                raise DenylistError(f"{where}: '{key}=' needs a regular expression")
    return AllowContext(path=path, line=values.get("line"), section=values.get("section"))


@dataclass
class _Raw:
    kind: str
    value: str
    line: Optional[int]
    label: str = ""
    allow: List[AllowContext] = field(default_factory=list)


def _parse_text(text: str, source: int) -> List[_Raw]:
    items: List[_Raw] = []
    for lineno, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        where = f"denylist {source} line {lineno}"
        if raw_line[:1] in (" ", "\t"):
            m = _DIRECTIVE.match(stripped)
            if m:
                if not items:
                    raise DenylistError(f"{where}: '{m.group(1).lower()}:' must follow an entry")
                key, rest = m.group(1).lower(), m.group(2)
                if key == "label":
                    items[-1].label = rest.strip()[:120]
                else:
                    items[-1].allow.append(_parse_allow(rest, where))
                continue
        if stripped.startswith("#"):
            continue
        kind, value = _split_prefix(stripped)
        if kind == "regex":
            value = value.strip()
        items.append(_Raw(kind=kind, value=value, line=lineno))
    return items


def _parse_mapping(data: Any, source: int) -> List[_Raw]:
    where = f"denylist {source}"
    if not isinstance(data, dict):
        raise DenylistError(f"{where}: expected a table/object with an 'entries' list")
    # Never print unknown keys: a mapping such as {"Acme Corp": "company"}
    # would put every entry into the error message.
    unknown = set(data) - {"entries", "version"}
    if unknown:
        raise DenylistError(f"{where}: {len(unknown)} unknown top-level key(s); only 'entries' and 'version' "
                            "are allowed (entries go in an 'entries' list)")
    entries = data.get("entries", [])
    if not isinstance(entries, list):
        raise DenylistError(f"{where}: 'entries' must be a list")
    items: List[_Raw] = []
    for i, item in enumerate(entries, 1):
        here = f"{where} entry {i}"
        if isinstance(item, str):
            kind, value = _split_prefix(item.strip())
            items.append(_Raw(kind=kind, value=value.strip(), line=None))
            continue
        if not isinstance(item, dict):
            raise DenylistError(f"{here}: must be a string or a table")
        unknown = set(item) - set(_KINDS) - {"label", "allow"}
        if unknown:
            raise DenylistError(f"{here}: {len(unknown)} unknown key(s); allowed keys are "
                                f"{', '.join(_KINDS)}, label and allow")
        kinds = [k for k in _KINDS if k in item]
        if len(kinds) != 1:
            raise DenylistError(f"{here}: give exactly one of {', '.join(_KINDS)}")
        value = item[kinds[0]]
        if not isinstance(value, str):
            raise DenylistError(f"{here}: '{kinds[0]}' must be a string")
        label = item.get("label", "")
        if not isinstance(label, str):
            raise DenylistError(f"{here}: 'label' must be a string")
        allow_items = item.get("allow", [])
        if isinstance(allow_items, dict):
            allow_items = [allow_items]
        if not isinstance(allow_items, list):
            raise DenylistError(f"{here}: 'allow' must be a list")
        allows: List[AllowContext] = []
        for a in allow_items:
            if isinstance(a, str):
                allows.append(AllowContext(path=a))
                continue
            if not isinstance(a, dict) or not isinstance(a.get("path"), str):
                raise DenylistError(f"{here}: every allow item needs a 'path'")
            bad = set(a) - {"path", "line", "section"}
            if bad:
                raise DenylistError(f"{here}: {len(bad)} unknown allow key(s); allowed keys are path, line "
                                    "and section")
            for key in ("line", "section"):
                if key in a and not isinstance(a[key], str):
                    raise DenylistError(f"{here}: allow '{key}' must be a string")
            allows.append(AllowContext(path=a["path"], line=a.get("line"), section=a.get("section")))
        items.append(_Raw(kind=kinds[0], value=value.strip() if kinds[0] != "regex" else value,
                          line=None, label=label.strip()[:120], allow=allows))
    return items


@dataclass
class Denylist:
    entries: List[Entry] = field(default_factory=list)
    files: List[Path] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.entries)

    def __bool__(self) -> bool:
        return bool(self.entries)

    @property
    def needs_sections(self) -> bool:
        return any(e.needs_sections for e in self.entries)

    @classmethod
    def load(cls, paths: Sequence[Path], *, loose: bool = False) -> "Denylist":
        dl = cls()
        seen: Dict[Tuple[str, str], int] = {}
        number = 0
        for source, path in enumerate(paths, 1):
            path = Path(path)
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise DenylistError(f"denylist {source} could not be read ({exc.strerror or 'error'})") from None
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError:
                raise DenylistError(f"denylist {source} is not valid UTF-8") from None
            suffix = path.suffix.lower()
            if suffix == ".json":
                try:
                    items = _parse_mapping(json.loads(text), source)
                except json.JSONDecodeError as exc:
                    raise DenylistError(f"denylist {source}: invalid JSON (line {exc.lineno})") from None
            elif suffix == ".toml":
                try:
                    items = _parse_mapping(tomlcompat.loads(text), source)
                except tomlcompat.TomlUnavailable as exc:
                    raise DenylistError(f"denylist {source}: {exc}") from None
                except ValueError:
                    raise DenylistError(f"denylist {source}: invalid TOML") from None
            else:
                items = _parse_text(text, source)
            dl.files.append(path)
            dl._check_permissions(path, source)
            for index, item in enumerate(items, 1):
                where = f"denylist {source}" + (f" line {item.line}" if item.line else f" entry {index}")
                value = unicodedata.normalize("NFC", item.value)
                if item.kind != "regex":
                    value = value.strip()
                if not value.strip():
                    continue
                if item.kind != "regex" and len(value) < MIN_ENTRY_LENGTH:
                    raise DenylistError(
                        f"{where}: entry is shorter than {MIN_ENTRY_LENGTH} characters and would match almost everything"
                    )
                kind = item.kind
                if kind == "literal" and loose:
                    kind = "loose"
                key = (kind, value.lower())
                if key in seen:
                    dl.warnings.append(f"{where}: duplicate of entry {seen[key]}")
                    continue
                number += 1
                seen[key] = number
                if item.kind != "regex" and len(value) == MIN_ENTRY_LENGTH:
                    dl.warnings.append(f"{where}: entry is only {MIN_ENTRY_LENGTH} characters long and may be noisy")
                entry = Entry(number=number, kind=kind, value=value, source=source, line=item.line,
                              label=item.label, allow=list(item.allow))
                _compile(entry, where)
                dl.entries.append(entry)
        many = len(dl.files) > 1
        for e in dl.entries:
            if not e.label:
                text = f"entry {e.number}"
                if e.line:
                    text += f" (line {e.line}"
                    text += f" of denylist {e.source})" if many else ")"
                elif many:
                    text += f" (denylist {e.source})"
                e.label = text
        return dl

    def _check_permissions(self, path: Path, source: int) -> None:
        if os.name != "posix":
            return
        try:
            mode = path.stat().st_mode
        except OSError:  # pragma: no cover
            return
        # A denylist streamed through a pipe (--denylist <(...), for example
        # from the macOS Keychain) is not a file on disk that others could read.
        if stat.S_ISREG(mode) and mode & (stat.S_IRWXG | stat.S_IRWXO):
            self.warnings.append(
                f"denylist {source} is readable by other users (mode {stat.S_IMODE(mode):o}); run chmod 600 on it"
            )

    def find(self, text: str) -> Iterator[Tuple[Entry, int, int]]:
        """Yield (entry, start, end) for every match in *text*."""
        if not self.entries or not text:
            return
        fast: Optional[str] = None
        if text.isascii() or not _FOLDS_TO_ASCII.search(text):
            lower = text.lower()
            fast = lower if len(lower) == len(text) else None
        for entry in self.entries:
            for start, end in entry.find(text, fast):
                yield entry, start, end

    def mask(self, text: str, replacement: str = "***") -> str:
        """Replace every denylist match in *text* (used for display paths)."""
        spans = sorted({(s, e) for _, s, e in self.find(text)})
        if not spans:
            return text
        out, pos = [], 0
        for s, e in spans:
            if s < pos:
                s = pos
            if s >= e:
                continue
            out.append(text[pos:s])
            out.append(replacement)
            pos = e
        out.append(text[pos:])
        return "".join(out)
