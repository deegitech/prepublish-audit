"""The finding model, severities and stable fingerprints.

A :class:`Finding` carries the matched text and the source line only so that
``--reveal`` can show them on a developer's own machine. Every reporter leaves
them out by default, and ``repr()`` never includes them.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple

SEVERITIES = ("note", "warning", "error")
_RANK = {"never": 99, "note": 1, "warning": 2, "error": 3}


def severity_rank(level: str) -> int:
    return _RANK.get(level, 0)


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    path: Optional[str] = None
    """Display path: relative, POSIX style; ``None`` for commit and ref findings."""
    line: Optional[int] = None
    column: Optional[int] = None
    end_column: Optional[int] = None
    origin: str = "file"
    """file, path, symlink, binary, metadata, archive, history, history-path,
    commit, ref, config, scan or gitleaks."""
    detail: Optional[str] = None
    """Extra context that never contains the matched text (field name, encoding...)."""
    commit: Optional[str] = None
    blob: Optional[str] = None
    location: Optional[str] = None
    """Human label for findings without a path, such as ``commit 1a2b3c4``."""
    match: Optional[str] = field(default=None, repr=False)
    snippet: Optional[str] = field(default=None, repr=False)
    fingerprint: str = ""
    priority: int = field(default=0, repr=False, compare=False)

    @property
    def match_length(self) -> int:
        return len(self.match) if self.match else 0

    def redacted(self) -> str:
        n = self.match_length
        return f"[redacted, {n} chars]" if n else "[redacted]"

    def where(self) -> str:
        """Short location text for humans."""
        if self.path is not None:
            text = self.path
            if self.line:
                text += f":{self.line}"
                if self.column:
                    text += f":{self.column}"
            return text
        return self.location or "(no location)"

    def sort_key(self) -> Tuple:
        return (
            self.path is None,
            self.path or "",
            self.location or "",
            self.line or 0,
            self.column or 0,
            self.rule_id,
            self.detail or "",
        )


def assign_fingerprints(findings: Iterable[Finding], mask: Optional[Callable[[str], str]] = None) -> None:
    """Give every finding a stable fingerprint.

    The fingerprint never hashes the matched text: a hash of a short secret
    (for example four card digits) could be reversed by trying every value.
    It hashes the rule, the location and the occurrence number instead. For
    the same reason the path, location and detail are hashed in their masked
    form (*mask* is the denylist's ``mask``): a path such as
    ``docs/4821-plan.md`` is shown as ``docs/***-plan.md``, and its
    fingerprint must not let anyone try the 10,000 values of ``***``.
    """
    hide = mask or (lambda s: s)
    counters: Dict[Tuple[str, str, str, str], int] = defaultdict(int)
    for f in sorted(findings, key=lambda x: x.sort_key()):
        anchor = hide(f.path) if f.path is not None else hide(f.location or "")
        detail = hide(f.detail or "")
        key = (f.rule_id, anchor, detail, f.origin)
        counters[key] += 1
        raw = "\x1f".join([f.rule_id, anchor, detail, f.origin, f.blob or "", str(counters[key])])
        f.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def count_by_severity(findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {"error": 0, "warning": 0, "note": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def worst(findings: Iterable[Finding]) -> Optional[str]:
    best: Optional[str] = None
    for f in findings:
        if best is None or severity_rank(f.severity) > severity_rank(best):
            best = f.severity
    return best


def sorted_findings(findings: Iterable[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda x: x.sort_key())
