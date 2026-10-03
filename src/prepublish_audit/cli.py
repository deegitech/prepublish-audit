"""Command-line interface.

Exit codes: 0 = no findings at or above --fail-on; 1 = findings;
2 = usage, configuration or runtime error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from . import gitleaks as gl
from . import gitscan
from . import tomlcompat
from .config import AllowRule, ConfigError, Settings, load_settings, parse_cli_allow
from .denylist import ENV_DENYLIST, Denylist, DenylistError, default_denylist_dir, locate_denylists
from .doctor import Doctor
from .doctor import render as render_doctor
from .globs import GlobSet
from .hints import hint_for
from .report import (
    Report,
    compute_exit_code,
    open_report,
    render_github,
    render_human,
    render_json,
    render_markdown,
    render_sarif,
    use_color,
    write_text,
)
from .rules import catalogue
from .scanner import Scanner, ScanError
from .util import parse_size

COMMANDS = ("scan", "rules", "check-denylist", "init", "doctor")
ENV_ALLOW_REVEAL = "PREPUBLISH_AUDIT_ALLOW_REVEAL"

EXAMPLE_CONFIG = """\
# prepublish-audit settings for this repository.
# This file is PUBLIC: never put private names, IDs or emails here.
# Private strings belong in your denylist (default:
# ~/.config/prepublish-audit/denylist.txt), which must stay outside the repo.

fail-on = "warning"
exclude = []

[heuristics]
numeric-id-min-length = 10
allowed-email-domains = []

# Allow known-good findings of built-in rules, for example test fixtures:
# [[allow]]
# rules = ["leak.*"]
# paths = ["tests/fixtures/**"]
# reason = "fake data used by the tests"
"""

# Written instead of the TOML file when no TOML parser is available
# (Python 3.10 without the 'tomli' package). JSON has no comments.
EXAMPLE_CONFIG_JSON = """\
{
  "fail-on": "warning",
  "exclude": [],
  "heuristics": {
    "numeric-id-min-length": 10,
    "allowed-email-domains": []
  }
}
"""

EXAMPLE_DENYLIST = """\
# Private denylist for prepublish-audit. Keep this file outside every
# repository and readable only by you (chmod 600).
#
# One entry per line, matched case-insensitively. Lines starting with '#'
# are comments. Prefixes: re: (regex), word: (whole word), loose: (ignore
# spaces, dots, dashes and underscores between words), lit: (escape hatch).
# Indented 'label:' and 'allow:' lines belong to the entry above them.
#
# Examples (replace them with your own):
# Acme Internal Tools
# re:\\bacme-(?:prod|staging)-[a-z0-9-]+\\b
# Acme Corp
#   label: company name
#   allow: LICENSE
#   allow: README.md section=^About
"""


def _add_scan_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("paths", nargs="*", metavar="PATH", help="files or directories to scan (default: .)")
    g = p.add_argument_group("denylist")
    g.add_argument("-d", "--denylist", action="append", metavar="FILE",
                   help=f"private denylist (repeatable). Default: ${ENV_DENYLIST}, then "
                        "~/.config/prepublish-audit/denylist.{txt,toml,json}")
    g.add_argument("--no-denylist", action="store_true", help="do not load any denylist")
    g.add_argument("--require-denylist", action="store_true", help="fail (exit 2) when no denylist is loaded")
    g.add_argument("--loose-denylist", action="store_true",
                   help="match plain entries with or without spaces, dots, dashes and underscores")
    g = p.add_argument_group("what to scan")
    g.add_argument("--git-files", action="store_true",
                   help="scan only files git would publish (tracked + untracked, not ignored)")
    g.add_argument("--history", action="store_true",
                   help="also scan every blob, path, message, identity and ref in git history")
    g.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths (repeatable)")
    g.add_argument("--no-default-excludes", action="store_true",
                   help="also scan node_modules, virtualenvs, caches and VCS folders")
    g.add_argument("--max-file-size", metavar="SIZE", help="largest file whose content is scanned (default 32MiB)")
    g.add_argument("--no-archives", action="store_true", help="do not look inside zip/tar/gz archives")
    g.add_argument("--no-decode", action="store_true", help="do not decode base64/percent/entity-encoded text")
    g.add_argument("--no-external-tools", action="store_true",
                   help="do not run exiftool, ffprobe or pdfinfo even when installed")
    g.add_argument("--gitleaks", choices=("auto", "always", "never"),
                   help="run gitleaks too: auto = when installed (default), always = required, never")
    g = p.add_argument_group("rules")
    g.add_argument("-c", "--config", metavar="FILE", help="config file (default: discovered from the first PATH)")
    g.add_argument("--no-config", action="store_true", help="ignore config files")
    g.add_argument("--disable", action="append", default=[], metavar="RULE", help="disable a rule id or glob")
    g.add_argument("--allow", action="append", default=[], metavar="RULE:GLOB",
                   help="allow a built-in rule under a path glob, e.g. leak.email:docs/**")
    g.add_argument("--fail-on", choices=("error", "warning", "note", "never"),
                   help="lowest severity that fails the run (default: warning)")
    g = p.add_argument_group("output")
    g.add_argument("-f", "--format", choices=("human", "json", "sarif", "github"), default="human",
                   help="report format (default: human)")
    g.add_argument("-o", "--output", metavar="FILE", help="write the main report to FILE instead of stdout")
    g.add_argument("--json-output", metavar="FILE", help="also write a JSON report")
    g.add_argument("--sarif-output", metavar="FILE", help="also write a SARIF 2.1.0 report")
    g.add_argument("--sarif-real-paths", action="store_true",
                   help="keep unmasked paths in SARIF so code scanning can link every alert to its file "
                        "(a path that contains a denylist entry then shows it; private repositories only)")
    g.add_argument("--summary-markdown", metavar="FILE", help="append a Markdown summary (e.g. $GITHUB_STEP_SUMMARY)")
    g.add_argument("--reveal", action="store_true",
                   help="show matched text and source lines (local use only; refused in CI)")
    g.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="colour the human report (default: auto; NO_COLOR is respected)")
    g.add_argument("-q", "--quiet", action="store_true", help="print findings and the verdict only")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prepublish-audit",
        description="Stop secrets and internal information from leaving: scan a repo, site or bundle before you publish it.",
        epilog="Run 'prepublish-audit <command> --help' for details. 'scan' is the default command.",
    )
    parser.add_argument("--version", action="version", version=f"prepublish-audit {__version__}")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="scan files, archives, metadata and (optionally) git history")
    _add_scan_args(scan)
    rules = sub.add_parser("rules", help="list the built-in rules")
    rules.add_argument("-f", "--format", choices=("text", "json", "markdown"), default="text",
                       help="output format (default: text)")
    check = sub.add_parser("check-denylist", help="validate denylist files without printing their entries")
    check.add_argument("files", nargs="*", metavar="FILE",
                       help="denylist files to check (default: the same lookup as scan)")
    init = sub.add_parser("init", help="write a starter config here and a private denylist template")
    init.add_argument("--force", action="store_true", help="overwrite an existing config")
    init.add_argument("--no-denylist", action="store_true", help="do not create the private denylist template")
    doctor = sub.add_parser("doctor", help="check the setup (denylist, config, git, helpers) and print a fix for "
                                           "every problem")
    doctor.add_argument("paths", nargs="*", metavar="PATH", help="what you are going to scan (default: .)")
    doctor.add_argument("-d", "--denylist", action="append", metavar="FILE",
                        help="denylist to check (repeatable; default: the same lookup as scan)")
    doctor.add_argument("-c", "--config", metavar="FILE", help="config file (default: discovered from the first PATH)")
    doctor.add_argument("--no-config", action="store_true", help="ignore config files")
    doctor.add_argument("--strict", action="store_true",
                        help="also fail (exit 1) on items marked '!': optional helpers, shallow clone, commit email, "
                             "hooks")
    doctor.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                        help="colour the output (default: auto; NO_COLOR is respected)")
    return parser


def _err(message: str) -> int:
    """Print an error and, for a known one, the fix on the next line (see hints.py)."""
    sys.stderr.write(f"prepublish-audit: error: {message}\n")
    fix = hint_for(message)
    if fix:
        sys.stderr.write(f"prepublish-audit: fix: {fix}\n")
    return 2


def _warn(message: str) -> None:
    sys.stderr.write(f"prepublish-audit: warning: {message}\n")


def resolve_denylists(explicit: Optional[Sequence[str]], disabled: bool) -> List[Path]:
    """--denylist, then $PREPUBLISH_AUDIT_DENYLIST, then the default location (first match wins)."""
    if disabled:
        return []
    return locate_denylists(explicit)[1]


CI_VARIABLES = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "TF_BUILD", "JENKINS_URL", "TEAMCITY_VERSION",
                "CODEBUILD_BUILD_ID", "DRONE", "BITBUCKET_BUILD_NUMBER", "CIRCLECI", "TRAVIS")


def _in_ci() -> bool:
    return any(os.environ.get(v) for v in CI_VARIABLES)


def _inside(path: Path, roots: Sequence[Path]) -> bool:
    p = path.resolve()
    for root in roots:
        r = root.resolve()
        if p == r or r in p.parents:
            return True
    return False


def _apply_cli(settings: Settings, args: argparse.Namespace) -> None:
    """Command-line options win over the public config; they are trusted input."""
    if args.fail_on:
        settings.fail_on = args.fail_on
        settings.fail_on_cli = True
    settings.cli_exclude.extend(args.exclude)
    if args.no_default_excludes:
        settings.default_excludes = False
    if args.max_file_size:
        try:
            settings.max_file_size = parse_size(args.max_file_size)
        except ValueError as exc:
            raise ConfigError(f"--max-file-size: {exc}") from None
        settings.cli_keys.add("max_file_size")
    for flag, key in (("no_archives", "archives"), ("no_decode", "decode"), ("no_external_tools", "external_tools")):
        if getattr(args, flag):
            setattr(settings, key, False)
            settings.cli_keys.add(key)
    if args.loose_denylist:
        settings.loose_denylist = True
    if args.gitleaks:
        settings.gitleaks = args.gitleaks
    for rule in args.disable:
        if rule.strip().lower().startswith("denylist"):
            raise ConfigError("the denylist cannot be disabled")
        settings.cli_disable.append(rule)
    for rule, glob in parse_cli_allow(args.allow):
        settings.allow.append(AllowRule(rules=[rule], paths=GlobSet([glob]), reason="--allow", cli=True))


def cmd_scan(args: argparse.Namespace) -> int:
    roots = [Path(p) for p in (args.paths or ["."])]
    for root in roots:
        if not root.exists() and not root.is_symlink():
            return _err(f"path not found: {root}")
    if args.reveal and _in_ci() and not os.environ.get(ENV_ALLOW_REVEAL):
        return _err("--reveal is refused in CI because build logs are often public "
                    f"(set {ENV_ALLOW_REVEAL}=1 to override)")
    if args.reveal:
        for out in (args.output, args.json_output, args.sarif_output, args.summary_markdown):
            if out and _inside(Path(out), roots):
                return _err("--reveal output must not be written inside a scanned tree")
    try:
        settings = load_settings(Path(args.config) if args.config else None, discover_from=roots[0],
                                 use_config=not args.no_config)
        _apply_cli(settings, args)
    except ConfigError as exc:
        return _err(str(exc))

    paths = resolve_denylists(args.denylist, args.no_denylist)
    try:
        denylist = Denylist.load(paths, loose=settings.loose_denylist)
    except DenylistError as exc:
        return _err(str(exc))
    for message in denylist.warnings:
        _warn(message)
    if args.require_denylist and not denylist:
        return _err("no denylist entries were loaded (--require-denylist)")
    if args.denylist and not denylist:
        # Usually an empty pipe: --denylist <(helper) whose command failed. On
        # stderr, so that --quiet does not hide it.
        _warn("the denylist given with --denylist has no entries (an empty file, or a pipe whose command printed "
              "nothing), so only the built-in rules run; add --require-denylist to stop instead")
    # The public config may narrow the built-in rules, never what the denylist sees.
    ignored = settings.keep_denylist_coverage() if denylist else []

    scanner = Scanner(settings, denylist, reveal=args.reveal)
    notes = scanner.notes
    if not denylist and denylist.files:
        notes.append("The private denylist has no entries: only built-in rules ran. "
                     "Check it with 'prepublish-audit check-denylist FILE'.")
    elif not denylist:
        notes.append("No private denylist loaded: only built-in rules ran. "
                     "See 'prepublish-audit init' or --denylist.")
    if ignored:
        notes.append(f"Not applied while a denylist is loaded, because they would narrow what it checks: "
                     f"{', '.join(ignored)} from the public config. Use the command-line options instead.")
    repo = None
    try:
        if args.history:
            repo = gitscan.prepare(roots[0])
            scanner.object_format = repo.object_format()
        for root in roots:
            scanner.scan_root(root, git_files=args.git_files)
        if repo is not None:
            gitscan.scan_history(scanner, repo)
    except (ScanError, gitscan.GitError) as exc:
        return _err(str(exc))

    code = _run_gitleaks(scanner, settings, roots, repo)
    if code:
        return code
    tools = scanner.tools.available()
    findings = scanner.finish()
    # With a denylist loaded, content it could not check fails the run at
    # "warning" even when the public config says fail-on = "error".
    floor = "warning" if denylist and not settings.fail_on_cli else None
    exit_code = compute_exit_code(findings, settings.fail_on, coverage_floor=floor)
    if floor and exit_code and not compute_exit_code(findings, settings.fail_on):
        notes.append(f"Failed although fail-on is '{settings.fail_on}': while a denylist is loaded, content it could "
                     "not check (scan.incomplete, git.shallow-clone) fails the run at warning level unless "
                     "--fail-on is given on the command line.")
    report = Report(
        findings=findings, stats=scanner.stats, roots=scanner.roots, catalogue=scanner.engine.catalogue,
        fail_on=settings.fail_on, exit_code=exit_code, reveal=args.reveal, history=repo is not None,
        git_files=args.git_files, denylist_entries=len(denylist), denylist_files=len(denylist.files),
        suppressed=scanner.engine.suppressed, notes=notes, tools=tools,
        mask=(lambda s: denylist.mask(s)) if denylist else (lambda s: s),
        sarif_real_paths=args.sarif_real_paths, empty_git_roots=scanner.empty_git_roots,
    )
    renderers = {"human": None, "json": render_json, "sarif": render_sarif, "github": render_github}
    try:
        if args.output:
            if args.format == "human":
                with open_report(args.output, report) as fh:
                    render_human(report, fh, color=False, quiet=args.quiet)
            else:
                write_text(args.output, renderers[args.format], report)  # type: ignore[arg-type]
        else:
            out = sys.stdout
            if args.format == "human":
                render_human(report, out, color=use_color(out, args.color), quiet=args.quiet)
            else:
                renderers[args.format](report, out)  # type: ignore[misc]
        if args.json_output:
            write_text(args.json_output, render_json, report)
        if args.sarif_output:
            write_text(args.sarif_output, render_sarif, report)
        if args.summary_markdown:
            write_text(args.summary_markdown, render_markdown, report, append=True)
    except OSError as exc:
        return _err(f"could not write the report: {exc.strerror}")
    return exit_code


def _run_gitleaks(scanner: Scanner, settings: Settings, roots: Sequence[Path], repo) -> int:
    mode = settings.gitleaks
    if mode == "never":
        return 0
    exe = gl.find()
    if exe is None:
        if mode == "always":
            return _err("gitleaks was requested (--gitleaks always) but is not on PATH")
        scanner.notes.append("gitleaks is not installed; built-in secret rules only.")
        return 0
    ver = gl.version(exe)
    incoming = []
    try:
        for root in roots:
            root = root.resolve()
            if not root.is_dir():
                continue

            def locate(path: Path, root: Path = root):
                path = path.resolve()
                if scanner.denylist and path in scanner._skip:
                    return None
                mp = scanner.match_path_for(path, root)
                if mp not in scanner.scanned_paths or mp in scanner.denylist_only_paths:
                    return None  # excluded, ignored or outside this scan
                return scanner.display_for(path, root), mp

            items = gl.run(exe, root, history=False, max_bytes=settings.max_file_size)
            for f in gl.to_findings(items, root, locate, history=False):
                if not scanner.engine.allowed(f.rule_id, f.location, None, None):
                    f.location = None
                    incoming.append(f)
        if repo is not None:
            top = repo.top
            real_top = top.resolve()

            def locate_history(path: Path):
                try:
                    rel = path.relative_to(top).as_posix()
                except ValueError:
                    rel = path.name
                if scanner.exclusion(scanner.history_match_path(real_top, rel)):
                    return None  # excluded paths are skipped in history too
                return rel, rel

            items = gl.run(exe, top, history=True, max_bytes=settings.max_file_size)
            for f in gl.to_findings(items, top, locate_history, history=True):
                if not scanner.engine.allowed(f.rule_id, f.location, None, None):
                    f.location = None
                    incoming.append(f)
    except gl.GitleaksError as exc:
        if mode == "always":
            return _err(str(exc))
        fix = hint_for(str(exc))
        scanner.notes.append(f"gitleaks did not complete ({exc}); built-in rules still ran."
                             + (f" Fix: {fix}" if fix else ""))
        return 0
    merged = gl.merge(scanner.findings, incoming)
    scanner.add(merged)
    version_text = ".".join(map(str, ver)) if ver else "unknown version"
    scanner.notes.append(f"gitleaks {version_text} also ran; {len(merged)} additional finding(s).")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules = catalogue(Settings())
    items = sorted(rules.values(), key=lambda r: r.id)
    if args.format == "json":
        json.dump([{"id": r.id, "title": r.title, "severity": r.severity, "description": r.description,
                    "remediation": r.remediation} for r in items], sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.format == "markdown":
        sys.stdout.write(rules_markdown(items))
    else:
        width = max(len(r.id) for r in items)
        for r in items:
            sys.stdout.write(f"{r.id:<{width}}  {r.severity:<7}  {r.title}\n")
    return 0


_CATEGORY_TITLES = {
    "denylist": "Private denylist",
    "secret": "Secrets",
    "leak": "Leak heuristics",
    "metadata": "Metadata",
    "git": "Git history",
    "config": "Configuration",
    "scan": "Scan coverage",
}


def rules_markdown(items) -> str:
    """docs/rules.md, generated from the rule catalogue."""
    out = [
        "# Rules",
        "",
        "<!-- Generated by `prepublish-audit rules --format markdown`; do not edit by hand. -->",
        "",
        "Every finding carries one of these rule IDs. Severities are defaults: change them with the",
        "`severity` table in the config (the denylist always stays an error). Disable a rule with",
        "`disable = [\"rule.id\"]`, or allow it in known-good places with an `[[allow]]` entry.",
        "The coverage rules (`scan.*`, `config.*`, `git.shallow-clone`) can only be disabled or allowed",
        "on the command line (`--disable`, `--allow`). Findings from gitleaks appear as",
        "`gitleaks.<gitleaks-rule-id>`.",
        "",
        "| Rule | Severity | Title |",
        "|---|---|---|",
    ]
    for r in items:
        out.append(f"| [`{r.id}`](#{r.id.replace('.', '')}) | {r.severity} | {r.title} |")
    current = None
    for r in items:
        category = r.id.split(".", 1)[0]
        if category != current:
            current = category
            out += ["", f"## {_CATEGORY_TITLES.get(category, category.title())}"]
        out += ["", f"### `{r.id}`", "", f"**{r.title}** (default severity: {r.severity})", "",
                r.description, "", f"**Fix:** {r.remediation}"]
    return "\n".join(out) + "\n"


def cmd_check_denylist(args: argparse.Namespace) -> int:
    paths = [Path(p) for p in args.files] or resolve_denylists(None, False)
    if not paths:
        return _err("no denylist given and none found in the default location")
    try:
        dl = Denylist.load(paths)
    except DenylistError as exc:
        return _err(str(exc))
    kinds: dict = {}
    for e in dl.entries:
        kinds[e.kind] = kinds.get(e.kind, 0) + 1
    with_allow = sum(1 for e in dl.entries if e.allow)
    labelled = sum(1 for e in dl.entries if not e.label.startswith("entry "))
    if not dl.entries:
        sys.stdout.write(f"EMPTY: 0 entries in {len(dl.files)} file(s), so it protects nothing. Add one value per "
                         "line; for a pipe such as <(pa_denylist), check that its command prints the list.\n")
        for message in dl.warnings:
            sys.stdout.write(f"warning: {message}\n")
        return 1
    detail = ", ".join(f"{n} {k}" for k, n in sorted(kinds.items()))
    sys.stdout.write(f"OK: {len(dl.entries)} entries in {len(dl.files)} file(s) ({detail}); "
                     f"{labelled} labelled, {with_allow} with allow contexts.\n")
    for message in dl.warnings:
        sys.stdout.write(f"warning: {message}\n")
    return 0


def _toml_available() -> bool:
    try:
        tomlcompat.loads("")
    except tomlcompat.TomlUnavailable:
        return False
    return True


def _home_relative(path: Path) -> str:
    """*path* with the home directory shown as ``~`` (keeps the username out of terminal logs)."""
    try:
        home = Path.home()
    except (RuntimeError, KeyError):  # pragma: no cover - no home directory
        return str(path)
    if home in path.parents:
        return "~/" + path.relative_to(home).as_posix()
    return str(path)


def cmd_init(args: argparse.Namespace) -> int:
    if _toml_available():
        target, content = Path(".prepublish-audit.toml"), EXAMPLE_CONFIG
    else:
        # Python 3.10 without tomli: a TOML config would stop every later scan.
        target, content = Path(".prepublish-audit.json"), EXAMPLE_CONFIG_JSON
    if target.exists() and not args.force:
        sys.stdout.write(f"{target} already exists (use --force to overwrite)\n")
    else:
        target.write_text(content, encoding="utf-8")
        sys.stdout.write(f"wrote {target} (public settings; commit it)\n")
        if target.suffix == ".json":
            sys.stdout.write("no TOML parser on this Python, so the config is JSON "
                             "(install 'tomli' to use .prepublish-audit.toml)\n")
    if not args.no_denylist:
        folder = default_denylist_dir()
        if folder is None:
            return _err("cannot find a home directory for the private denylist")
        path = folder / "denylist.txt"
        if path.exists():
            sys.stdout.write("private denylist already exists; left untouched\n")
        else:
            folder.parent.mkdir(parents=True, exist_ok=True)
            folder.mkdir(mode=0o700, exist_ok=True)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(EXAMPLE_DENYLIST)
            sys.stdout.write(f"created a private denylist template at {_home_relative(path)} "
                             "(mode 600, outside the repository)\n")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    doctor = Doctor([Path(p) for p in args.paths], denylist=args.denylist, config=args.config,
                    use_config=not args.no_config)
    doctor.run()
    return render_doctor(doctor, sys.stdout, color=use_color(sys.stdout, args.color), strict=args.strict)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    if not args_list or (args_list[0] not in COMMANDS and args_list[0] not in ("-h", "--help", "--version")):
        args_list.insert(0, "scan")
    parser = build_parser()
    try:
        args = parser.parse_args(args_list)
    except SystemExit as exc:
        if exc.code in (0, None):  # --help, --version
            return 0
        # argparse printed the usage and the error; add the fix like every other error.
        command = f"{args_list[0]} " if args_list[0] in COMMANDS else ""
        sys.stderr.write(f"prepublish-audit: fix: run 'prepublish-audit {command}--help' to see the options "
                         "and their values.\n")
        return 2
    try:
        if args.command == "rules":
            return cmd_rules(args)
        if args.command == "check-denylist":
            return cmd_check_denylist(args)
        if args.command == "init":
            return cmd_init(args)
        if args.command == "doctor":
            return cmd_doctor(args)
        return cmd_scan(args)
    except KeyboardInterrupt:
        sys.stderr.write("prepublish-audit: interrupted\n")
        return 2
    except BrokenPipeError:  # pragma: no cover - e.g. piped into head
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
