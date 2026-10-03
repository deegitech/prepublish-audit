"""TOML loading that works on Python 3.10 when ``tomli`` is installed.

Both ``tomllib.TOMLDecodeError`` and ``tomli.TOMLDecodeError`` subclass
``ValueError``, so callers catch ``ValueError`` for malformed input.
"""

from __future__ import annotations

from typing import Any, Dict


class TomlUnavailable(RuntimeError):
    pass


def loads(text: str) -> Dict[str, Any]:
    try:
        import tomllib  # type: ignore[import-not-found]
    except ModuleNotFoundError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[import-not-found,no-redef]
        except ModuleNotFoundError:
            raise TomlUnavailable(
                "reading TOML on Python 3.10 needs the 'tomli' package: install it into the same "
                "environment (pip install tomli), install prepublish-audit[toml], or use a JSON file instead"
            ) from None
    return tomllib.loads(text)

