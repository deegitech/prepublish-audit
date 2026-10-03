"""Small helpers shared by the scanner: entropy, placeholders, numbers, lines."""

from __future__ import annotations

import bisect
import hashlib
import math
import re
from collections import Counter
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Entropy


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in Counter(value).values())


# ---------------------------------------------------------------------------
# Placeholders

_PLACEHOLDER_MARKERS = (
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "replaceme",
    "dummy",
    "redacted",
    "xxxx",
    "****",
    "....",
    "your_",
    "your-",
    "yourtoken",
    "yourkey",
    "notreal",
    "not_real",
    "not-real",
    "not-a-real",
    "<",
    ">",
    "${",
    "{{",
    "%(",
    "%s",
)

_SEQ_UP = "0123456789" * 6
_SEQ_DOWN = "9876543210" * 6
_ALPHA = "abcdefghijklmnopqrstuvwxyz"


def looks_sequential(value: str) -> bool:
    """True for runs such as ``123456789012`` or ``abcdefgh``."""
    v = value.lower()
    if len(v) < 6:
        return False
    if v.isdigit():
        return v in _SEQ_UP or v in _SEQ_DOWN
    if v.isalpha():
        return v in _ALPHA
    return False


def is_placeholder(value: str) -> bool:
    """Heuristic: does *value* look like a documentation placeholder?"""
    v = value.lower()
    if any(marker in v for marker in _PLACEHOLDER_MARKERS):
        return True
    core = re.sub(r"[^0-9a-z]", "", v)
    if not core:
        return True
    if len(set(core)) <= 2:
        return True
    digits = re.sub(r"\D", "", core)
    if len(digits) >= 6 and looks_sequential(digits):
        return True
    if any(looks_sequential(run) for run in re.findall(r"\d{8,}", v)):
        return True
    # the variable part of a prefixed token is filler, e.g. sk_live_000000...
    if any(len(seg) >= 8 and len(set(seg)) <= 2 for seg in re.split(r"[_\-.:/|]", v)):
        return True
    return looks_sequential(core)


def is_placeholder_number(digits: str) -> bool:
    """Numbers such as ``0000000000``, ``1111111111`` or ``123456789012``.

    Also a few significant digits followed by a long run of zeros: documentation
    often keeps an ID's real-looking prefix and zeroes out the rest.
    """
    if len(set(digits)) <= 1:
        return True
    if looks_sequential(digits):
        return True
    return len(digits) - len(digits.rstrip("0")) >= 8


def is_round_number(digits: str) -> bool:
    """Up to three significant digits followed by six or more zeros."""
    return re.fullmatch(r"[1-9]\d{0,2}0{6,}", digits.lstrip("0") or "0") is not None


def _well_known_numbers() -> frozenset:
    nums = set()
    for n in range(28, 129):
        nums.add(str(2 ** n))
        nums.add(str(2 ** n - 1))
    nums.update(
        {
            # hash, PRNG and checksum constants that appear in many codebases
            "2654435761",
            "2654435769",
            "2246822519",
            "3266489917",
            "2166136261",
            "1099511628211",
            "14695981039346656037",
            "11400714819323198485",
            "6364136223846793005",
            "1442695040888963407",
            "1103515245",
            "2891336453",
            "4294967291",
            "18446744073709551557",
            "6700417",
            # leading digits of mathematical constants
            "3141592653",
            "31415926535",
            "314159265358979",
            "3141592653589793",
            "2718281828",
            "27182818284",
            "271828182845904",
            "2718281828459045",
            "1618033988",
            "1414213562",
            "1732050807",
            "6283185307",
            "6283185307179586",
        }
    )
    return frozenset(nums)


WELL_KNOWN_NUMBERS = _well_known_numbers()


# ---------------------------------------------------------------------------
# Payment cards


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------------------
# Sizes

_SIZE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([kmgt]?i?b?)?\s*$", re.IGNORECASE)
_UNITS = {"": 1, "b": 1, "k": 1000, "kb": 1000, "ki": 1024, "kib": 1024,
          "m": 1000 ** 2, "mb": 1000 ** 2, "mi": 1024 ** 2, "mib": 1024 ** 2,
          "g": 1000 ** 3, "gb": 1000 ** 3, "gi": 1024 ** 3, "gib": 1024 ** 3,
          "t": 1000 ** 4, "tb": 1000 ** 4, "ti": 1024 ** 4, "tib": 1024 ** 4}


def parse_size(value: object) -> int:
    """Parse ``10485760``, ``"10MB"`` or ``"10 MiB"`` into bytes."""
    if isinstance(value, bool):
        raise ValueError("size must be a number or a string such as '10MiB'")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("size must not be negative")
        return value
    if not isinstance(value, str):
        raise ValueError("size must be a number or a string such as '10MiB'")
    m = _SIZE.match(value)
    if not m:
        raise ValueError("unrecognised size (use bytes or a unit such as 10MiB)")
    unit = (m.group(2) or "").lower()
    if unit not in _UNITS:
        raise ValueError("unrecognised size unit")
    return int(float(m.group(1)) * _UNITS[unit])


def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n} B"  # pragma: no cover


# ---------------------------------------------------------------------------
# Line index


class LineIndex:
    """Map character offsets in a text to 1-based (line, column)."""

    __slots__ = ("_text", "_starts")

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: Optional[List[int]] = None

    def _build(self) -> List[int]:
        starts = [0]
        find = self._text.find
        i = find("\n")
        while i != -1:
            starts.append(i + 1)
            i = find("\n", i + 1)
        self._starts = starts
        return starts

    def position(self, offset: int) -> Tuple[int, int]:
        starts = self._starts if self._starts is not None else self._build()
        line = bisect.bisect_right(starts, offset) - 1
        return line + 1, offset - starts[line] + 1

    def line_text(self, line: int) -> str:
        starts = self._starts if self._starts is not None else self._build()
        start = starts[line - 1]
        end = starts[line] - 1 if line < len(starts) else len(self._text)
        return self._text[start:end].rstrip("\r")

    def line_bounds(self, line: int) -> Tuple[int, int]:
        starts = self._starts if self._starts is not None else self._build()
        start = starts[line - 1]
        end = starts[line] - 1 if line < len(starts) else len(self._text)
        return start, end


# ---------------------------------------------------------------------------
# Git object ids


def git_blob_id(data: bytes, algorithm: str = "sha1") -> str:
    """The object id git would give *data* as a blob."""
    h = hashlib.new(algorithm)
    h.update(b"blob %d\x00" % len(data))
    h.update(data)
    return h.hexdigest()


def clip(text: str, start: int, end: int, width: int = 160) -> str:
    """A single-line excerpt of *text* around [start, end)."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end == -1:
        line_end = len(text)
    lo = max(line_start, start - width // 2)
    hi = min(line_end, end + width // 2)
    excerpt = text[lo:hi].replace("\t", " ").rstrip("\r")
    if lo > line_start:
        excerpt = "..." + excerpt
    if hi < line_end:
        excerpt = excerpt + "..."
    return excerpt
