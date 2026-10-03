"""The matching engine: runs the denylist and the built-in rules over text.

Everything the scanner reads ends up here as text: file contents, file
names, strings pulled out of binaries, metadata values, commit messages and
ref names. The engine applies allow contexts, inline pragmas and config
allow rules, drops weaker findings that overlap stronger ones, and decodes
base64 / percent / HTML-entity / ``\\u`` escapes to look inside them.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse
from collections import Counter
from fnmatch import fnmatchcase
from typing import Dict, List, Optional, Sequence, Set, Tuple

from .config import Settings
from .denylist import Denylist
from .findings import Finding
from .rules import (
    ALL,
    DECODED,
    FILE_RULES,
    PATH,
    Rule,
    RuleContext,
    catalogue,
    content_rules,
)
from .util import LineIndex, clip

_PRAGMA = re.compile(r"prepublish-audit:\s*allow\b(?:[ \t]+([A-Za-z0-9_.*,\- \t]+))?", re.IGNORECASE)
_MD_EXT = (".md", ".markdown", ".mdx", ".mkd")
_ATX = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*#*[ \t]*$")
_SETEXT = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
_FENCE = re.compile(r"^ {0,3}(`{3,}|~{3,})")

_B64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{16,}={0,2}(?![A-Za-z0-9+/=_-])")
_UESC = re.compile(r"\\u([0-9A-Fa-f]{4})")

MAX_DECODE_ATTEMPTS = 4000
MAX_DECODED_CHARS = 4 * 1024 * 1024
MAX_DECODE_DEPTH = 2
SUBSUMABLE_PRIORITY = 100


def markdown_sections(text: str) -> List[Tuple[str, ...]]:
    """Heading stack for every line (index 0 is unused)."""
    lines = text.split("\n")
    result: List[Tuple[str, ...]] = [()] * (len(lines) + 1)
    stack: List[Tuple[int, str]] = []
    fence: Optional[str] = None
    prev_text: Optional[str] = None

    def push(level: int, title: str) -> None:
        while stack and stack[-1][0] >= level:
            stack.pop()
        stack.append((level, title))

    for i, line in enumerate(lines, 1):
        fm = _FENCE.match(line)
        if fm:
            marker = fm.group(1)
            if fence is None:
                fence = marker[0] * 3
            elif marker.startswith(fence):
                fence = None
            prev_text = None
        elif fence is None:
            am = _ATX.match(line)
            sm = _SETEXT.match(line)
            if am:
                push(len(am.group(1)), (am.group(2) or "").strip())
                prev_text = None
            elif sm and prev_text:
                push(1 if sm.group(1).startswith("=") else 2, prev_text)
                result[i - 1] = tuple(t for _, t in stack)
                prev_text = None
            else:
                prev_text = line.strip() or None
        result[i] = tuple(t for _, t in stack)
    return result


class _Candidate:
    __slots__ = ("finding", "start", "end", "priority")

    def __init__(self, finding: Finding, start: int, end: int, priority: int) -> None:
        self.finding, self.start, self.end, self.priority = finding, start, end, priority


class Engine:
    def __init__(self, settings: Settings, denylist: Denylist, *, reveal: bool = False) -> None:
        self.settings = settings
        self.denylist = denylist
        self.reveal = reveal
        self.builtin = True
        """False while the scanner checks content against the denylist only
        (paths that the public config excludes)."""
        self.catalogue: Dict[str, Rule] = catalogue(settings)
        rules = content_rules(settings)
        self.rules_by_target: Dict[str, List[Rule]] = {t: [r for r in rules if t in r.targets] for t in ALL}
        self._keyword_rx = {
            id(r): re.compile("|".join(re.escape(k) for k in r.keywords)) for r in rules if r.keywords
        }
        self.suppressed: Counter = Counter()
        self._seen_path_keys: Set[Tuple[str, str, str]] = set()

    # -- bookkeeping -------------------------------------------------------
    def _suppress(self, rule_id: str) -> None:
        self.suppressed[rule_id] += 1

    def severity(self, rule_id: str, default: str) -> str:
        if rule_id == "denylist":
            return "error"
        return self.settings.severity_for(rule_id, default)

    def allowed(self, rule_id: str, path: Optional[str], line: Optional[str], value: Optional[str]) -> bool:
        if rule_id == "denylist":
            return False
        if self.settings.is_allowed(rule_id, path, line, value):
            self._suppress(rule_id)
            return True
        return False

    @staticmethod
    def _pragma_allows(line: str, rule_id: str) -> bool:
        if "prepublish-audit" not in line.lower():
            return False
        for m in _PRAGMA.finditer(line):
            listed = m.group(1)
            if not listed or not listed.strip():
                return True
            for item in re.split(r"[,\s]+", listed.strip()):
                if item and fnmatchcase(rule_id, item):
                    return True
        return False

    # -- public API --------------------------------------------------------
    def scan_text(
        self,
        text: str,
        *,
        target: str,
        match_path: Optional[str],
        display: Optional[str],
        origin: str,
        detail: Optional[str] = None,
        location: Optional[str] = None,
        positions: bool = True,
        depth: int = 0,
    ) -> List[Finding]:
        if not text:
            return []
        index = LineIndex(text)
        candidates: List[_Candidate] = []
        quiet: List[Tuple[int, int, int]] = []  # spans suppressed by allow rules or pragmas
        is_markdown = bool(match_path) and match_path.lower().endswith(_MD_EXT)  # type: ignore[union-attr]
        sections: Optional[List[Tuple[str, ...]]] = None
        reported: Set[Tuple[int, int]] = set()

        def make(rule_id: str, severity: str, message: str, s: int, e: int, value: str,
                 extra: Optional[str] = None, idx: LineIndex = index, src: str = text) -> Finding:
            line_no, col = idx.position(s)
            parts = [p for p in (detail, extra) if p]
            f = Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                path=display,
                line=line_no if positions else None,
                column=col if positions else None,
                end_column=(col + (e - s)) if positions else None,
                origin=origin,
                detail="; ".join(parts) if parts else None,
                location=location,
            )
            f.match = value
            f.snippet = clip(src, s, e)
            return f

        # 1. private denylist
        if self.denylist:
            for entry, s, e in self.denylist.find(text):
                line_no, _ = index.position(s)
                line_text = None
                if any(a.line is not None for a in entry.compiled_allow):
                    lo, hi = index.line_bounds(line_no)
                    line_text = text[lo:hi]
                secs = None
                if entry.needs_sections and is_markdown:
                    if sections is None:
                        sections = markdown_sections(text)
                    secs = sections[line_no] if line_no < len(sections) else ()
                if entry.allowed(match_path, line_text, secs):
                    self._suppress("denylist")
                    quiet.append((s, e, 300))
                    continue
                reported.add((entry.number, line_no))
                f = make("denylist", "error", f"Denylist match: {entry.label}", s, e, text[s:e])
                candidates.append(_Candidate(f, s, e, 300))
            if not unicodedata.is_normalized("NFC", text):
                norm = unicodedata.normalize("NFC", text)
                nidx = LineIndex(norm)
                norm_sections: Optional[List[Tuple[str, ...]]] = None
                for entry, s, e in self.denylist.find(norm):
                    line_no, _ = nidx.position(s)
                    if (entry.number, line_no) in reported:
                        continue
                    secs = None
                    if entry.needs_sections and is_markdown:
                        if norm_sections is None:
                            norm_sections = markdown_sections(norm)
                        secs = norm_sections[line_no] if line_no < len(norm_sections) else ()
                    if entry.allowed(match_path, nidx.line_text(line_no), secs):
                        self._suppress("denylist")
                        continue
                    reported.add((entry.number, line_no))
                    f = make("denylist", "error", f"Denylist match: {entry.label}", s, e, norm[s:e],
                             extra="Unicode-normalised text", idx=nidx, src=norm)
                    # positions refer to the normalised text; keep the line, drop the span for subsumption
                    candidates.append(_Candidate(f, -1, -1, 300))

        # 2. built-in rules
        rules = self.rules_by_target.get(target, []) if self.builtin else []
        if rules:
            ctx = RuleContext(text, index, self.settings, match_path, target)
            lower: Optional[str] = None
            for rule in rules:
                if rule.pattern is None:
                    continue
                if rule.keywords:
                    if lower is None:
                        lower = text.lower()
                    if not self._keyword_rx[id(rule)].search(lower):
                        continue
                for m in rule.pattern.finditer(text):
                    group = rule.group
                    if group == -1:
                        group = next((i for i in range(1, (m.lastindex or 0) + 1) if m.group(i) is not None), 0)
                    value = m.group(group)
                    if not value:
                        continue
                    s, e = m.span(group)
                    ctx.bind(s, e)
                    verdict = rule.validate(value, m, ctx) if rule.validate else True
                    if not verdict:
                        continue
                    line = ctx.line
                    if self._pragma_allows(line, rule.id):
                        self._suppress(rule.id)
                        quiet.append((s, e, rule.priority))
                        continue
                    if self.allowed(rule.id, match_path, line, value):
                        quiet.append((s, e, rule.priority))
                        continue
                    message = rule.title + (f" ({verdict})" if isinstance(verdict, str) else "")
                    f = make(rule.id, self.severity(rule.id, rule.severity), message, s, e, value)
                    candidates.append(_Candidate(f, s, e, rule.priority))

        # 3. encoded content
        if self.settings.decode and depth < MAX_DECODE_DEPTH and target != PATH:
            candidates.extend(self._decoded(text, index, match_path, display, origin, detail, location,
                                            positions, depth))

        return self._subsume(candidates, quiet)

    def scan_path(self, match_path: str, display: str, origin: str = "path",
                  text: Optional[str] = None) -> List[Finding]:
        """File-type rules plus a text scan of the path itself.

        *text* is the path as it is checked (default: *match_path*); history
        passes the full repository path there while globs keep matching
        *match_path*.
        """
        text = match_path if text is None else text
        findings: List[Finding] = []
        for rule in FILE_RULES if self.builtin else ():
            if self.settings.rule_disabled(rule.id) or not rule.match(match_path):
                continue
            if self.allowed(rule.id, match_path, None, None):
                continue
            title = self.catalogue[rule.id].title
            findings.append(Finding(rule_id=rule.id, severity=self.severity(rule.id, rule.severity),
                                    message=f"{title}: {rule.detail}", path=display, origin=origin))
        for f in self.scan_text(text, target=PATH, match_path=match_path, display=display,
                                origin=origin, positions=True):
            # Report each match once, at the directory or file that contains it.
            start = (f.column or 1) - 1
            end = start + f.match_length
            seg_end = text.find("/", max(end, start + 1))
            prefix = text if seg_end == -1 else text[:seg_end]
            key = (f.rule_id, f.message, prefix)
            if key in self._seen_path_keys:
                continue
            self._seen_path_keys.add(key)
            if display.endswith(text):
                f.path = display[: len(display) - len(text) + len(prefix)]
                if seg_end != -1:
                    f.path += "/"
            f.line = f.column = f.end_column = None
            f.detail = "file or directory name"
            findings.append(f)
        return findings

    # -- internals ---------------------------------------------------------
    def _subsume(self, candidates: List[_Candidate], quiet: Sequence[Tuple[int, int, int]] = ()) -> List[Finding]:
        """Drop weak findings that overlap a stronger finding or an allowed span."""
        if quiet:
            remaining = []
            for c in candidates:
                if c.priority <= SUBSUMABLE_PRIORITY and c.start >= 0 and any(
                        p > c.priority and c.start < e and s < c.end for s, e, p in quiet):
                    self._suppress(c.finding.rule_id)
                    continue
                remaining.append(c)
            candidates = remaining
        if len(candidates) <= 1:
            return [c.finding for c in candidates]
        if len(candidates) > 20000:
            return [c.finding for c in candidates]
        ordered = sorted(candidates, key=lambda c: -c.priority)
        kept: List[_Candidate] = []
        seen: Set[Tuple[str, int, int]] = set()
        for c in ordered:
            key = (c.finding.rule_id, c.start, c.end)
            if c.start >= 0 and key in seen:
                continue
            if c.priority <= SUBSUMABLE_PRIORITY and c.start >= 0:
                if any(k.priority > c.priority and k.start >= 0 and c.start < k.end and k.start < c.end
                       for k in kept):
                    continue
            seen.add(key)
            kept.append(c)
        kept.sort(key=lambda c: (c.start, c.finding.rule_id))
        return [c.finding for c in kept]

    def _decoded(self, text: str, index: LineIndex, match_path: Optional[str], display: Optional[str],
                 origin: str, detail: Optional[str], location: Optional[str], positions: bool,
                 depth: int) -> List[_Candidate]:
        out: List[_Candidate] = []
        budget = [MAX_DECODE_ATTEMPTS, MAX_DECODED_CHARS]

        def emit(kind: str, start: int, end: int, decoded: str) -> None:
            if budget[1] <= 0:
                return
            budget[1] -= len(decoded)
            inner = self.scan_text(decoded, target=DECODED, match_path=match_path, display=display,
                                   origin=origin, detail=None, location=location, positions=False,
                                   depth=depth + 1)
            if not inner:
                return
            line_no, col = index.position(start)
            for f in inner:
                if f.rule_id != "denylist":
                    # Line-level allow rules and pragmas apply to the encoded line too.
                    lo, hi = index.line_bounds(line_no)
                    line = text[lo:hi]
                    if self._pragma_allows(line, f.rule_id) or self.allowed(f.rule_id, match_path, line, f.match):
                        continue
                f.line = line_no if positions else None
                f.column = col if positions else None
                f.end_column = (col + (end - start)) if positions else None
                parts = [p for p in (detail, f"inside {kind}-encoded data") if p]
                f.detail = "; ".join(parts)
                f.message = f.message + f" (inside {kind}-encoded data)"
                f.snippet = clip(text, start, end)
                out.append(_Candidate(f, start, end, 300 if f.rule_id == "denylist" else 200))

        for marker, kind, decode in _DECODERS:
            if marker[0] not in text:
                continue
            last_end = -1
            for m in marker[1].finditer(text):
                if m.start() < last_end:
                    continue
                if budget[0] <= 0:
                    break
                budget[0] -= 1
                start, end = _token_bounds(text, m.start(), m.end())
                last_end = end
                tok = text[start:end]
                try:
                    dec = decode(tok)
                except (UnicodeDecodeError, ValueError, OverflowError):
                    continue
                if dec and dec != tok:
                    emit(kind, start, end, dec)
        for m in _B64_CANDIDATE.finditer(text):
            if budget[0] <= 0:
                break
            tok = m.group()
            core = tok.rstrip("=")
            if len(core) % 4 == 1:
                continue
            if not (any(c.isdigit() for c in core) or "+" in core or "/" in core or tok.endswith("=")):
                continue
            if not (any(c.islower() for c in core) and any(c.isupper() for c in core)):
                continue
            budget[0] -= 1
            dec = _b64_text(core)
            if dec is not None:
                emit("base64", m.start(), m.end(), dec)
        return out


_TOKEN_STOP = (" ", "\n", "\t", "\r", '"', "'", "<", ">", "`")


def _token_bounds(text: str, start: int, end: int, window: int = 4096) -> Tuple[int, int]:
    """Expand [start, end) to the surrounding whitespace/quote-delimited token."""
    lo = max(0, start - window)
    left = max(text.rfind(ch, lo, start) for ch in _TOKEN_STOP) + 1
    if left == 0 and lo > 0:
        left = lo
    right = len(text) if end + window >= len(text) else end + window
    stops = [i for i in (text.find(ch, end, right) for ch in _TOKEN_STOP) if i != -1]
    return left, (min(stops) if stops else right)


def _percent(tok: str) -> str:
    return urllib.parse.unquote(tok, errors="strict")


def _uescape(tok: str) -> str:
    return _UESC.sub(lambda u: chr(int(u.group(1), 16)), tok)


_DECODERS = (
    (("%", re.compile(r"%[0-9A-Fa-f]{2}")), "percent", _percent),
    (("&", re.compile(r"&(?:#\d{2,7}|#[xX][0-9A-Fa-f]{2,6}|[A-Za-z]{2,8});")), "HTML-entity", html.unescape),
    (("\\u", re.compile(r"\\u[0-9A-Fa-f]{4}")), "unicode-escape", _uescape),
)


def _b64_text(core: str) -> Optional[str]:
    padded = core + "=" * (-len(core) % 4)
    try:
        if "-" in core or "_" in core:
            raw = base64.urlsafe_b64decode(padded)
        else:
            raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 6:
        return None
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\n\r\t")
    if printable / len(decoded) < 0.9:
        return None
    return decoded
