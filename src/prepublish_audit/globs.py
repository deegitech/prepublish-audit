"""Gitignore-style path globs.

* ``*`` matches within one path segment, ``?`` one character, ``[abc]`` a set.
* ``**`` matches across segments (``docs/**``, ``**/fixtures/*.json``).
* A pattern without a slash matches at any depth (``LICENSE``, ``*.pem``).
* A pattern with a slash is anchored to the base directory (``/README.md``,
  ``docs/legal/*``).
* A pattern that matches a directory also matches everything below it.

Paths are POSIX-style and relative; matching is case-sensitive, like git.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, List, Pattern


def _translate(pattern: str) -> str:
    out: List[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern.startswith("**", i):
                j = i + 2
                if j < n and pattern[j] == "/":
                    out.append("(?:[^/]*/)*")
                    i = j + 1
                else:
                    out.append(".*")
                    i = j
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i + 1)
            if j == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1 : j]
                if body[:1] in ("!", "^"):
                    body = "^" + body[1:]
                body = body.replace("\\", "\\\\")
                out.append("[" + body + "]")
                i = j + 1
                continue
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


@lru_cache(maxsize=2048)
def compile_glob(pattern: str) -> Pattern[str]:
    p = pattern.strip().replace("\\", "/")
    if not p or p in ("/", "!"):
        raise ValueError("empty path pattern")
    anchored = "/" in p.rstrip("/")
    p = p.strip("/")
    body = _translate(p)
    prefix = "" if anchored else "(?:.*/)?"
    return re.compile("^" + prefix + body + "(?:/.*)?$", re.DOTALL)


def glob_match(pattern: str, path: str) -> bool:
    return compile_glob(pattern).match(path) is not None


class GlobSet:
    """A set of globs; ``match`` is true if any glob matches."""

    def __init__(self, patterns: Iterable[str] = ()) -> None:
        self.patterns: List[str] = [p for p in patterns if p and p.strip()]
        self._compiled = [compile_glob(p) for p in self.patterns]

    def match(self, path: str) -> bool:
        return any(rx.match(path) for rx in self._compiled)

    def __bool__(self) -> bool:
        return bool(self._compiled)

    def __len__(self) -> int:
        return len(self._compiled)
