"""Optional gitleaks integration.

When gitleaks is on PATH (``--gitleaks auto``, the default) it runs with
``--redact`` and a JSON report written to a private temporary directory that
is deleted afterwards. Its findings are merged into ours; a gitleaks finding
on a line where a built-in secret rule already fired is dropped as a
duplicate. The secret text from gitleaks is never read or shown.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .findings import Finding

_VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")


class GitleaksError(RuntimeError):
    pass


def find() -> Optional[str]:
    return shutil.which("gitleaks")


def version(exe: str) -> Optional[Tuple[int, int, int]]:
    try:
        p = subprocess.run([exe, "version"], capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = _VERSION.search(p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace"))
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def command(exe: str, *, history: bool, report: Path, max_mb: int,
            ver: Optional[Tuple[int, int, int]]) -> List[str]:
    modern = ver is None or ver >= (8, 19, 0)
    if history:
        cmd = [exe, "git", "--log-opts=--all", "."] if modern else [exe, "detect", "--source", ".", "--log-opts=--all"]
    else:
        cmd = [exe, "dir", "."] if modern else [exe, "detect", "--no-git", "--source", "."]
    cmd += ["--redact", "--no-banner", "--report-format", "json", "--report-path", str(report),
            "--exit-code", "0", "--log-level", "error"]
    if max_mb > 0:
        cmd += ["--max-target-megabytes", str(max_mb)]
    return cmd


def run(exe: str, target: Path, *, history: bool, max_bytes: int, timeout: int = 3600) -> List[dict]:
    """Run gitleaks on *target* and return its (redacted) JSON findings."""
    ver = version(exe)
    with tempfile.TemporaryDirectory(prefix="prepublish-audit-") as tmp:
        report = Path(tmp) / "gitleaks.json"
        cmd = command(exe, history=history, report=report, max_mb=max(1, max_bytes // (1024 * 1024)), ver=ver)
        try:
            p = subprocess.run(cmd, cwd=target, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise GitleaksError("gitleaks timed out") from None
        except OSError as exc:
            raise GitleaksError(f"gitleaks could not start ({exc.strerror})") from None
        if p.returncode != 0:
            raise GitleaksError(f"gitleaks exited with status {p.returncode}")
        try:
            text = report.read_text(encoding="utf-8")
        except OSError:
            return []
    try:
        data = json.loads(text or "[]")
    except json.JSONDecodeError:
        raise GitleaksError("gitleaks wrote an unreadable report") from None
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def to_findings(items: Sequence[dict], target: Path, locate, history: bool) -> List[Finding]:
    """Convert gitleaks report items.

    *locate* maps an absolute path to ``(display, match_path)`` or ``None`` to
    drop the item (for example a file this scan excluded).
    """
    out: List[Finding] = []
    for item in items:
        rule = str(item.get("RuleID") or "unknown")
        rule = re.sub(r"[^A-Za-z0-9_.-]", "-", rule)[:80]
        raw = str(item.get("File") or "")
        path = Path(raw)
        if not path.is_absolute():
            path = target / raw
        located = locate(path)
        if located is None:
            continue
        display, match_path = located
        line = item.get("StartLine") if isinstance(item.get("StartLine"), int) else None
        column = item.get("StartColumn") if isinstance(item.get("StartColumn"), int) else None
        f = Finding(rule_id=f"gitleaks.{rule}", severity="error",
                    message=f"Secret reported by gitleaks ({rule})", path=display,
                    line=line or None, column=column or None,
                    origin="history" if history else "gitleaks", detail="gitleaks")
        commit = item.get("Commit")
        if isinstance(commit, str) and commit:
            f.commit = commit
        f.location = match_path
        out.append(f)
    return out


def merge(existing: Sequence[Finding], incoming: Sequence[Finding]) -> List[Finding]:
    """Drop gitleaks findings that duplicate a built-in secret or denylist finding."""
    taken = {(f.path, f.line) for f in existing
             if f.rule_id.startswith(("secret.", "denylist")) and f.line is not None}
    taken_hist = {(f.path, f.commit) for f in existing if f.origin == "history" and f.rule_id.startswith("secret.")}
    out = []
    for f in incoming:
        if (f.path, f.line) in taken:
            continue
        if f.commit and (f.path, f.commit) in taken_hist:
            continue
        out.append(f)
    return out
