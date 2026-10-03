"""Reporters: human text, JSON, SARIF 2.1.0, GitHub annotations and a Markdown summary.

Nothing here prints matched text, source lines or denylist entries unless
the report was built with ``reveal=True``. Every free-text field that can
come from scanned content (paths, messages, details, locations, notes) is
masked where it contains a denylist entry, in every format; SARIF paths too,
unless ``sarif_real_paths`` is set. The human, GitHub and Markdown reports
also escape control characters, so a crafted file name cannot inject
workflow commands, table rows or terminal escape sequences.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.parse
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, TextIO

from . import __version__, doc_url
from .config import COVERAGE_RULES
from .findings import Finding, count_by_severity, severity_rank, sorted_findings
from .rules import Rule

INFO_URI = "https://github.com/deegitech/prepublish-audit"
RULES_DOC = INFO_URI + "/blob/main/docs/rules.md"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


@dataclass
class Report:
    findings: List[Finding]
    stats: object
    roots: List[str]
    catalogue: Dict[str, Rule]
    fail_on: str = "warning"
    exit_code: int = 0
    reveal: bool = False
    history: bool = False
    git_files: bool = False
    denylist_entries: int = 0
    denylist_files: int = 0
    suppressed: Counter = field(default_factory=Counter)
    notes: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    mask: Callable[[str], str] = lambda s: s
    sarif_real_paths: bool = False
    empty_git_roots: List[str] = field(default_factory=list)
    """Scanned roots where --git-files found nothing git would publish."""

    @property
    def counts(self) -> Dict[str, int]:
        return count_by_severity(self.findings)

    @property
    def failed(self) -> bool:
        return self.exit_code == 1

    def history_only(self) -> int:
        """Findings that a fix in the working tree cannot remove."""
        return sum(1 for f in self.findings
                   if f.origin in ("history", "history-path", "commit", "ref") and f.rule_id != "git.shallow-clone")

    def shown(self, text: Optional[str]) -> Optional[str]:
        """*text* as a report may show it: denylist matches masked unless --reveal."""
        if text is None:
            return None
        return text if self.reveal else self.mask(text)

    def shown_path(self, f: Finding) -> Optional[str]:
        return self.shown(f.path)

    def shown_notes(self) -> List[str]:
        return [self.shown(n) or "" for n in self.notes]

    def rule(self, rule_id: str) -> Optional[Rule]:
        return self.catalogue.get(rule_id)

    def remediation(self, rule_id: str) -> str:
        """The one-line fix for *rule_id* (fixed text from the rule catalogue)."""
        rule = self.rule(rule_id)
        if rule is None and rule_id.startswith("gitleaks."):
            from .rules import gitleaks_rule

            rule = gitleaks_rule(rule_id.split(".", 1)[1])
        return rule.remediation if rule is not None else f"See {doc_url('docs/rules.md')}."


def compute_exit_code(findings: List[Finding], fail_on: str, coverage_floor: Optional[str] = None) -> int:
    """1 when a finding is at or above *fail_on*, else 0.

    *coverage_floor* (``"warning"`` when a denylist is loaded and fail-on did
    not come from the command line) makes the coverage rules (content that
    could not be checked) fail at that level even when *fail_on* is higher.
    """
    if fail_on == "never":
        return 0
    threshold = severity_rank(fail_on)
    coverage = min(threshold, severity_rank(coverage_floor)) if coverage_floor else threshold
    for f in findings:
        limit = coverage if f.rule_id in COVERAGE_RULES else threshold
        if severity_rank(f.severity) >= limit:
            return 1
    return 0


# ---------------------------------------------------------------------------
# Escaping

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def printable(text: str) -> str:
    """*text* with control characters shown as ``\\xNN`` (no newlines or escape sequences)."""
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def _no_command(line: str) -> str:
    """Neutralise a line that GitHub Actions would read as a workflow command (``::...``)."""
    stripped = line.lstrip()
    if stripped.startswith("::"):
        return line[: len(line) - len(stripped)] + "\\x3a" + stripped[1:]
    return line


# ---------------------------------------------------------------------------
# Human

class _Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text


def use_color(stream: TextIO, mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never" or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


_SEV_COLOR = {"error": "1;31", "warning": "1;33", "note": "36"}


def _origin_label(f: Finding) -> str:
    if f.origin == "history":
        parts = ["history"]
        if f.blob:
            parts.append(f"blob {f.blob[:10]}")
        if f.commit:
            parts.append(f"first added in commit {f.commit[:10]}")
        return "(" + ", ".join(parts) + ")"
    if f.origin == "history-path":
        return "(a path in git history)"
    if f.origin in ("metadata", "binary", "archive", "symlink", "gitleaks"):
        return f"({f.origin})"
    return ""


def _plural(n: int, word: str, plural: Optional[str] = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _coverage_parts(stats: object) -> List[str]:
    parts = []
    excluded = getattr(stats, "excluded", 0)
    if excluded:
        parts.append(f"{excluded} excluded")
    deny_only = getattr(stats, "denylist_only", 0)
    if deny_only:
        parts.append(f"{deny_only} checked against the denylist only")
    default = getattr(stats, "default_excluded", 0)
    if default:
        parts.append(f"{_plural(default, 'default-excluded directory', 'default-excluded directories')}")
    return parts


def _nothing_scanned(report: Report) -> bool:
    stats = report.stats
    return not stats.files and not (report.history and (stats.history_blobs or stats.commits))


def render_human(report: Report, stream: TextIO, *, color: bool = False, quiet: bool = False) -> None:
    st = _Style(color)
    w = stream.write
    stats = report.stats
    if not quiet:
        w(st(f"prepublish-audit {__version__}", "1") + "\n")
        parts = [f"{_plural(stats.files, 'file')} ({stats.text_files} text, {stats.binary_files} binary)"]
        if stats.archives:
            parts.append(f"{stats.archives} archives / {stats.archive_members} members")
        if stats.metadata_files:
            parts.append(f"metadata in {stats.metadata_files}")
        if report.history:
            parts.append(f"{_plural(stats.history_blobs, 'history blob')}, {_plural(stats.commits, 'commit')}, "
                         f"{_plural(stats.refs, 'ref')}")
        parts.extend(_coverage_parts(stats))
        w("Scanned: " + "; ".join(parts) + "\n")
        dl = (f"{_plural(report.denylist_entries, 'entry', 'entries')} from "
              f"{_plural(report.denylist_files, 'file')}"
              if report.denylist_files else "none (built-in rules only)")
        w(f"Denylist: {dl}")
        if report.tools:
            w(f"  |  helpers: {', '.join(report.tools)}")
        w("\n\n")

    groups: Dict[str, List[Finding]] = {}
    for f in sorted_findings(report.findings):
        head = report.shown_path(f) or report.shown(f.location) or "(repository)"
        label = _origin_label(f)
        key = _no_command(printable(f"{head}  {label}".rstrip()))
        groups.setdefault(key, []).append(f)
    for head, items in groups.items():
        w(st(head, "1") + "\n")
        for f in items:
            pos = f"{f.line}:{f.column}" if f.line and f.column else (str(f.line) if f.line else "-")
            sev = st(f"{f.severity:<7}", _SEV_COLOR.get(f.severity, "0"))
            message = report.shown(f.message) or ""
            detail = report.shown(f.detail)
            extra = f" [{detail}]" if detail and detail not in message else ""
            secret = f"  {f.redacted()}" if not report.reveal and f.match_length else ""
            w(printable(f"  {pos:<9} ") + sev + printable(f"  {f.rule_id:<32} {message}{extra}{secret}") + "\n")
            if report.reveal:
                if f.match:
                    w(f"            match: {f.match!r}\n")
                if f.snippet and f.snippet != f.match:
                    w(f"            line:  {printable(f.snippet)}\n")
        w("\n")

    counts = report.counts
    total = len(report.findings)
    supp = sum(report.suppressed.values())
    status = "FAILED" if report.failed else "PASSED"
    status_txt = st(status, "1;31" if report.failed else "1;32")
    w(f"{status_txt}: {counts['error']} error(s), {counts['warning']} warning(s), {counts['note']} note(s)"
      f" (fail-on: {report.fail_on})")
    if supp:
        w(f"; {supp} suppressed by allow rules")
    w("\n")
    if _nothing_scanned(report):
        w("Warning: no files were scanned (everything was excluded, ignored or empty).\n")
    elif report.empty_git_roots:
        # e.g. a gitignored build folder scanned with --git-files: never call that clean.
        for root in report.empty_git_roots:
            w(f"Warning: nothing under {printable(report.shown(root) or '')} was scanned, because git would not "
              "publish it (--git-files); run without --git-files to scan what is on disk.\n")
    elif total == 0 and not quiet:
        w("No secrets or internal information found.\n")
    if quiet and not report.denylist_entries:
        w("Note: no private denylist entries were loaded, so only the built-in rules ran.\n")
    hist = report.history_only()
    if hist:
        w(st("History: ", "1") + f"{hist} finding(s) live only in git history. Deleting the files is not enough: "
          f"publish a fresh single-commit history or rewrite history ({doc_url('docs/release-checklist.md')}).\n")
    if total and not quiet:
        _render_fixes(report, w, st)
    if not report.reveal and total and not quiet:
        w("Matched text is redacted. Re-run locally with --reveal to see it (never in CI logs).\n")
    if report.notes and not quiet:
        w("Notes:\n")
        for note in report.shown_notes():
            w(f"  - {printable(note)}\n")


def _render_fixes(report: Report, w: Callable[[str], object], st: _Style) -> None:
    """One line per rule that fired: what to do about it (rule remediations are fixed text)."""
    rule_ids: List[str] = []
    for f in sorted_findings(report.findings):
        if f.rule_id not in rule_ids:
            rule_ids.append(f.rule_id)
    width = min(max(len(r) for r in rule_ids), 32)
    w(st("How to fix:", "1") + "\n")
    for rid in rule_ids:
        w(printable(f"  {rid:<{width}}  {report.remediation(rid)}") + "\n")
    w("  A finding that is fine to publish: allow it (README, 'Allowing known-good findings'). "
      f"Errors and fixes: {doc_url('docs/troubleshooting.md')}\n")


# ---------------------------------------------------------------------------
# JSON

def finding_dict(f: Finding, report: Report) -> Dict[str, object]:
    d: Dict[str, object] = {
        "rule_id": f.rule_id,
        "severity": f.severity,
        "message": report.shown(f.message),
        "path": report.shown_path(f),
        "line": f.line,
        "column": f.column,
        "end_column": f.end_column,
        "origin": f.origin,
        "detail": report.shown(f.detail),
        "location": report.shown(f.location),
        "commit": f.commit,
        "blob": f.blob,
        "match_length": f.match_length,
        "fingerprint": f.fingerprint,
    }
    if report.reveal:
        d["match"] = f.match
        d["snippet"] = f.snippet
    return d


def to_json(report: Report) -> Dict[str, object]:
    stats = report.stats
    return {
        "tool": {"name": "prepublish-audit", "version": __version__, "information_uri": INFO_URI},
        "schema": "prepublish-audit/report/v1",
        "result": "fail" if report.failed else "pass",
        "exit_code": report.exit_code,
        "fail_on": report.fail_on,
        "redacted": not report.reveal,
        "summary": dict(report.counts, total=len(report.findings), suppressed=sum(report.suppressed.values()),
                        history_only=report.history_only()),
        "scanned": {
            "roots": [report.shown(r) for r in report.roots],
            "files": stats.files,
            "text_files": stats.text_files,
            "binary_files": stats.binary_files,
            "archives": stats.archives,
            "archive_members": stats.archive_members,
            "metadata_files": stats.metadata_files,
            "bytes": stats.bytes,
            "excluded": getattr(stats, "excluded", 0),
            "denylist_only": getattr(stats, "denylist_only", 0),
            "default_excluded_dirs": getattr(stats, "default_excluded", 0),
            "history": report.history,
            "git_files": report.git_files,
            "history_blobs": stats.history_blobs,
            "history_paths": stats.history_paths,
            "commits": stats.commits,
            "refs": stats.refs,
            "denylist_entries": report.denylist_entries,
            "denylist_files": report.denylist_files,
            "helpers": report.tools,
        },
        "suppressed_by_rule": dict(sorted(report.suppressed.items())),
        "findings": [finding_dict(f, report) for f in sorted_findings(report.findings)],
        "skipped": [{"path": report.shown(s["path"]), "reason": s["reason"]} for s in stats.skipped],
        "notes": report.shown_notes(),
    }


def render_json(report: Report, stream: TextIO) -> None:
    json.dump(to_json(report), stream, indent=2, ensure_ascii=False)
    stream.write("\n")


# ---------------------------------------------------------------------------
# SARIF 2.1.0

_SECURITY_SEVERITY = {"error": "8.0", "warning": "5.0", "note": "2.0"}


def _anchor(rule_id: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", rule_id.lower().replace(".", ""))


def _camel(title: str) -> str:
    return "".join(w[:1].upper() + w[1:] for w in re.findall(r"[A-Za-z0-9]+", title))


def _sarif_rule(rule: Rule) -> Dict[str, object]:
    severity = rule.severity
    sec = "9.0" if rule.id.startswith(("secret.", "gitleaks.")) and severity == "error" else _SECURITY_SEVERITY[severity]
    return {
        "id": rule.id,
        "name": _camel(rule.title) or rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {"text": rule.remediation, "markdown": f"**{rule.title}**\n\n{rule.description}\n\n**Fix:** {rule.remediation}"},
        "helpUri": f"{RULES_DOC}#{_anchor(rule.id)}",
        "defaultConfiguration": {"level": severity},
        "properties": {
            "tags": ["security", rule.category],
            "precision": "medium" if rule.id in ("secret.high-entropy-string", "leak.numeric-id",
                                                 "leak.identifier-assignment") else "high",
            "security-severity": sec,
        },
    }


def _sarif_uri(path: str) -> str:
    return urllib.parse.quote(path, safe="/!~*'()@:$&+,;=-._")


def to_sarif(report: Report) -> Dict[str, object]:
    from .rules import gitleaks_rule

    used = sorted({f.rule_id for f in report.findings})
    rules: Dict[str, Rule] = dict(report.catalogue)
    for rid in used:
        if rid not in rules and rid.startswith("gitleaks."):
            rules[rid] = gitleaks_rule(rid.split(".", 1)[1])
    ordered = sorted(rules)
    index = {rid: i for i, rid in enumerate(ordered)}
    results = []
    for f in sorted_findings(report.findings):
        location_text = report.shown(f.location)
        if f.path is not None:
            # Masked like every other report, so a path that contains a
            # denylist entry does not end up in code scanning. With
            # --sarif-real-paths code scanning can link such alerts to files.
            uri = f.path if (report.reveal or report.sarif_real_paths) else report.mask(f.path)
        else:
            uri = ".prepublish-audit/git/" + re.sub(r"[^A-Za-z0-9._-]+", "-", location_text or "repository").strip("-")
        physical: Dict[str, object] = {"artifactLocation": {"uri": _sarif_uri(uri), "uriBaseId": "%SRCROOT%"}}
        # Code scanning wants a start line; file-level findings (names, metadata,
        # binary content, commits) are anchored at line 1.
        region: Dict[str, object] = {"startLine": f.line or 1}
        if f.line and f.column:
            region["startColumn"] = f.column
            if f.end_column and f.end_column > f.column:
                region["endColumn"] = f.end_column
        if report.reveal and f.snippet:
            region["snippet"] = {"text": f.snippet}
        physical["region"] = region
        location: Dict[str, object] = {"physicalLocation": physical}
        if f.path is None:
            location["logicalLocations"] = [{"name": location_text or "repository", "kind": "object"}]
        message_text = report.shown(f.message) or ""
        detail = report.shown(f.detail)
        message = message_text + (f" [{detail}]" if detail and detail not in message_text else "")
        result: Dict[str, object] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": f.severity,
            "message": {"text": message},
            "locations": [location],
            "partialFingerprints": {"prepublishAudit/v1": f.fingerprint},
            "properties": {k: v for k, v in (("origin", f.origin), ("commit", f.commit), ("blob", f.blob),
                                             ("detail", detail), ("fileLevel", not f.line)) if v},
        }
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "prepublish-audit",
                "version": __version__,
                "semanticVersion": __version__,
                "informationUri": INFO_URI,
                "rules": [_sarif_rule(rules[rid]) for rid in ordered],
            }},
            "automationDetails": {"id": "prepublish-audit/"},
            "columnKind": "unicodeCodePoints",
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "toolExecutionNotifications": [{"level": "note", "message": {"text": n}}
                                               for n in report.shown_notes()],
            }],
            "properties": {"redacted": not report.reveal, "historyScanned": report.history,
                           "pathsMasked": not (report.reveal or report.sarif_real_paths)},
        }],
    }


def render_sarif(report: Report, stream: TextIO) -> None:
    json.dump(to_sarif(report), stream, indent=2, ensure_ascii=False)
    stream.write("\n")


# ---------------------------------------------------------------------------
# GitHub Actions annotations

def _gh_data(text: str) -> str:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return printable(text)


def _gh_prop(text: str) -> str:
    return _gh_data(text).replace(":", "%3A").replace(",", "%2C")


def render_github(report: Report, stream: TextIO) -> None:
    w = stream.write
    command = {"error": "error", "warning": "warning", "note": "notice"}
    for f in sorted_findings(report.findings):
        props = [f"title={_gh_prop(f.rule_id)}"]
        path = report.shown_path(f)
        if path is not None and f.origin not in ("history", "history-path"):
            props.insert(0, f"file={_gh_prop(path)}")
            if f.line:
                props.insert(1, f"line={f.line}")
                if f.column:
                    props.insert(2, f"col={f.column}")
        where = path or report.shown(f.location) or "repository"
        label = _origin_label(f)
        message_text = report.shown(f.message) or ""
        message = f"{message_text} at {where}{' ' + label if label else ''}"
        detail = report.shown(f.detail)
        if detail and detail not in message_text:
            message += f" [{detail}]"
        w(f"::{command[f.severity]} {','.join(props)}::{_gh_data(message)}\n")
    counts = report.counts
    status = "FAILED" if report.failed else "PASSED"
    w(f"prepublish-audit {__version__}: {status}: {counts['error']} error(s), {counts['warning']} warning(s), "
      f"{counts['note']} note(s); scanned {report.stats.files} files"
      + (f", {report.stats.commits} commits" if report.history else "")
      + "".join(f"; {p}" for p in _coverage_parts(report.stats)) + "\n")
    if _nothing_scanned(report):
        w("::warning title=prepublish-audit::No files were scanned (everything was excluded, ignored or empty).\n")
    hist = report.history_only()
    if hist:
        w(f"::warning title=prepublish-audit history::{hist} finding(s) live only in git history; "
          "publish a fresh history or rewrite it before going public.\n")
    for note in report.shown_notes():
        w(f"::notice title=prepublish-audit::{_gh_data(note)}\n")


# ---------------------------------------------------------------------------
# Markdown summary (GITHUB_STEP_SUMMARY)

def _md_cell(text: str) -> str:
    return printable(text).replace("|", "\\|")


def render_markdown(report: Report, stream: TextIO, limit: int = 100) -> None:
    w = stream.write
    counts = report.counts
    status = "Failed" if report.failed else "Passed"
    w(f"### prepublish-audit: {status}\n\n")
    w(f"{counts['error']} error(s), {counts['warning']} warning(s), {counts['note']} note(s) "
      f"(fail-on: `{report.fail_on}`). Scanned {report.stats.files} files")
    if report.history:
        w(f", {report.stats.history_blobs} history blobs and {report.stats.commits} commits")
    coverage = _coverage_parts(report.stats)
    if coverage:
        w(" (" + "; ".join(coverage) + ")")
    w(".\n\n")
    if _nothing_scanned(report):
        w("**Warning:** no files were scanned.\n\n")
    if report.findings:
        w("| Severity | Rule | Location | Message |\n|---|---|---|---|\n")
        for f in sorted_findings(report.findings)[:limit]:
            where = report.shown_path(f) or report.shown(f.location) or "repository"
            if f.line:
                where += f":{f.line}"
            label = _origin_label(f)
            msg = _md_cell(report.shown(f.message) or "")
            w(f"| {f.severity} | `{f.rule_id}` | `{_md_cell(where).replace('`', '')}` {label} | {msg} |\n")
        if len(report.findings) > limit:
            w(f"\n…and {len(report.findings) - limit} more. See the job log or the SARIF/JSON report.\n")
    w("\nMatched text is never shown in CI output.\n")


def open_report(path: str, report: Report, append: bool = False) -> TextIO:
    """Open a report file; revealed reports (matched text in clear) get mode 0600."""
    if not report.reveal:
        return open(path, "a" if append else "w", encoding="utf-8")
    flags = os.O_WRONLY | os.O_CREAT | (os.O_APPEND if append else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)  # an existing file keeps its old mode otherwise
        return os.fdopen(fd, "a" if append else "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise


def write_text(path: str, render: Callable[[Report, TextIO], None], report: Report, append: bool = False) -> None:
    with open_report(path, report, append=append) as fh:
        render(report, fh)


def stdout() -> TextIO:
    return sys.stdout
