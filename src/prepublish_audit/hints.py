"""One-line fixes for known errors.

When a run stops with an error (exit code 2), or an optional helper such as
gitleaks fails, the CLI looks the message up here and prints the fix on the
next line::

    prepublish-audit: error: denylist 1 could not be read (No such file or directory)
    prepublish-audit: fix: Check that the file named by --denylist or ...

Fixes are fixed text. They never repeat anything from the message, so they
cannot leak a denylist entry, a matched value or a path. docs/troubleshooting.md
lists the same messages in a table; keep the two in step.
"""

from __future__ import annotations

import re
from typing import List, Optional, Pattern, Tuple

# (pattern searched in the error message, fix). The first match wins, so more
# specific patterns come first.
_TABLE: Tuple[Tuple[str, str], ...] = (
    # --- the private denylist ------------------------------------------------
    (r"^denylist \d+ could not be read \(Permission denied\)",
     "As the file's owner, run chmod 600 FILE (ls -l FILE shows the owner), or copy it to your own "
     "~/.config/prepublish-audit/ and chmod 600 the copy."),
    (r"^denylist \d+ could not be read \(Is a directory\)",
     "Pass the denylist file, not its folder, for example --denylist ~/.config/prepublish-audit/denylist.txt."),
    (r"^denylist \d+ could not be read",
     "Check that the file named by --denylist or $PREPUBLISH_AUDIT_DENYLIST exists and that you can read it "
     "(ls -l FILE); 'prepublish-audit init' creates the default ~/.config/prepublish-audit/denylist.txt."),
    (r"^denylist \d+ is not valid UTF-8",
     "Save the denylist as UTF-8 (your editor's 'save with encoding', or iconv -f OLD-ENCODING -t UTF-8), "
     "then run 'prepublish-audit check-denylist'."),
    (r"reading TOML on Python 3\.10 needs",
     "Add a TOML parser to the same environment (pipx inject prepublish-audit tomli, or pip install tomli), "
     "or use a .txt or .json file instead."),
    (r"^denylist \d+: invalid JSON",
     "Fix the JSON at that line ('python3 -m json.tool FILE > /dev/null' shows the exact position), "
     "or switch to the text format (.txt)."),
    (r"^denylist \d+: invalid TOML",
     "Fix the TOML syntax (strings need quotes, each entry is an [[entries]] table), "
     "or switch to the text format (.txt)."),
    (r"^denylist \d+: (?:\d+ unknown top-level key|expected a table/object|'entries' must be a list)",
     "Put every entry in the 'entries' list: [[entries]] tables in TOML, {\"entries\": [...]} in JSON "
     "(README, 'The private denylist')."),
    (r"^denylist \d+ entry \d+: (?:must be a string or a table|give exactly one of|\d+ unknown (?:allow )?key"
     r"|'\w+' must be a (?:string|list)|every allow item needs|allow '\w+' must be a string)",
     "Each entry is a string, or a table with exactly one of literal, regex, word or loose, plus optional "
     "label and allow = [{ path = \"GLOB\" }] (README, 'The private denylist')."),
    (r"invalid allow (?:regular expression|path)",
     "Write allow lines as 'allow: PATH-GLOB [line=REGEX] [section=REGEX]' and escape regex characters "
     "such as ( [ . + with a backslash."),
    (r"(?:'allow:'|'label:') must follow an entry|'allow:' needs a path pattern|unknown 'allow:' option"
     r"|=' given twice|=' needs a regular expression",
     "Indented lines belong to the entry above them: '  label: TEXT' or "
     "'  allow: PATH-GLOB [line=REGEX] [section=REGEX]'."),
    (r"^'(?:internal-patterns #\d+|allow #\d+\.line)': invalid regular expression",
     "Fix the regular expression in the public config; python3 -c \"import re; re.compile(r'PATTERN')\" "
     "shows the problem."),
    (r"invalid regular expression",
     "Escape characters that are special in regular expressions ( ( ) [ ] { } . * + ? | ) with a backslash, "
     "or drop the re: prefix to match the text literally; then run 'prepublish-audit check-denylist'."),
    (r"pattern matches the empty string",
     "A pattern such as a* or (x)? matches everywhere; make it require at least one character (a+, x)."),
    (r"entry is shorter than \d+ characters",
     "Use a longer, more specific value, or a regular expression with word boundaries such as re:\\bAB\\b."),
    # --- the public config ------------------------------------------------------
    (r"the denylist cannot be disabled|the denylist severity cannot be changed"
     r"|denylist matches can only be allowed|--allow cannot allow denylist matches",
     "Allow a denylist entry in the private denylist itself: add an indented 'allow: PATH-GLOB' line "
     "under the entry (optionally with line= or section=)."),
    (r"coverage rules \(scan\.\*, config\.\*, git\.shallow-clone\) can only be changed",
     "Pass --disable RULE or --allow RULE:GLOB on the command line (for example in your CI step); "
     "the public config cannot hide what the scan could not check."),
    (r"accepted only on the command line \(--fail-on never\)",
     "Set fail-on to \"error\", \"warning\" or \"note\" in the config, or pass --fail-on never on the "
     "command line."),
    (r"^'severity': level for",
     "Use error, warning or note as the level, for example severity = { \"leak.email\" = \"note\" }."),
    (r"^'fail-on' must be one of",
     "Use one of error, warning or note (the command line also accepts --fail-on never)."),
    (r"empty path pattern",
     "Remove the empty or '/'-only pattern from the path list, or write a glob such as \"docs/**\"."),
    (r"^'gitleaks' must be one of",
     "Use gitleaks = \"auto\", \"always\" or \"never\"."),
    (r"^unknown config key",
     "Check the spelling against README, 'Configuration reference': keys use dashes (fail-on) and "
     "heuristic settings go under [heuristics]."),
    (r"^unknown heuristics key",
     "Check the spelling against the heuristics.* keys in README, 'Configuration reference'."),
    (r"^allow #\d+: give at least one of",
     "Give every [[allow]] entry at least one of rules, paths, line or values, plus a reason."),
    (r"^allow #\d+: unknown key",
     "An [[allow]] entry takes the keys rules, paths, line, values and reason."),
    (r"^--allow expects RULE:PATH-GLOB",
     "Write --allow RULE:GLOB, for example --allow 'leak.email:docs/**' (quote it so the shell does not "
     "expand the glob)."),
    (r"^--max-file-size:|^'max-(?:file|archive)-size':",
     "Write sizes as a number of bytes or with a unit, for example 64MiB, 500MB or 1GiB."),
    (r"must be a list of strings|must be true or false|must be an integer >=|must be a number between"
     r"|must be a table|must be a list|must be a string|items must be strings",
     "Fix the value type: lists as [\"a\", \"b\"], true/false and numbers without quotes "
     "(README, 'Configuration reference')."),
    (r": invalid JSON \(line",
     "Fix the JSON at that line ('python3 -m json.tool FILE > /dev/null' shows the exact position)."),
    (r": invalid TOML",
     "Fix the TOML syntax at the reported line and column: strings need quotes, tables are written [name]."),
    (r": expected a table/object",
     "The config must be a TOML table or a JSON object at the top level, for example fail-on = \"warning\"."),
    (r"^cannot read config",
     "Check that the config file exists and that you can read it, or pass --no-config to use the defaults."),
    # --- what to scan -----------------------------------------------------------
    (r"^path not found",
     "Check the path (cd into the repository first and quote paths that contain spaces); "
     "'prepublish-audit doctor PATH' checks the whole setup."),
    (r"refused in CI",
     "Re-run the same command with --reveal on your own machine; in CI keep the redacted report, "
     "because build logs are often readable by many people."),
    (r"--reveal output must not be written inside a scanned tree",
     "Write revealed reports outside every repository, for example -o ~/prepublish-audit-report.txt, "
     "and delete them when you are done."),
    (r"no denylist entries were loaded \(--require-denylist\)",
     "Pass --denylist FILE or set PREPUBLISH_AUDIT_DENYLIST. A pipe is empty if its command failed (Keychain "
     "helper not loaded, keychain locked); a GitHub secret is empty on pull requests from forks and in jobs "
     "without the right 'environment:'."),
    (r"no denylist given and none found",
     "Create one with 'prepublish-audit init' (it writes ~/.config/prepublish-audit/denylist.txt), "
     "or name the file: prepublish-audit check-denylist FILE."),
    (r"cannot find a home directory",
     "Set HOME (or XDG_CONFIG_HOME), or create the denylist yourself and pass it with --denylist."),
    (r"^--history needs a git repository",
     "Run it inside a git clone (git rev-parse --show-toplevel must work) and check 'git --version', "
     "or drop --history to scan the files only."),
    (r"^--git-files",
     "Run it inside a git clone with git installed (git ls-files must work), or drop --git-files to scan "
     "everything on disk."),
    (r"^git \S+ failed",
     "Check the repository with 'git status' and 'git fsck'; for a partial (--filter) or damaged clone, "
     "make a full clone and scan that."),
    # --- gitleaks -----------------------------------------------------------------
    (r"gitleaks was requested \(--gitleaks always\) but is not on PATH",
     "Install gitleaks (brew install gitleaks, or a release binary from github.com/gitleaks/gitleaks/releases), "
     "or use --gitleaks auto to run it only when it is installed."),
    (r"gitleaks timed out",
     "Exclude large generated folders with --exclude, or skip it with --gitleaks never; the built-in secret "
     "rules still run."),
    (r"gitleaks could not start",
     "Check that 'gitleaks version' runs on this machine (file permissions, CPU architecture), "
     "or use --gitleaks never."),
    (r"gitleaks exited with status|gitleaks wrote an unreadable report",
     "Run 'gitleaks version' and update it (8.x is expected; 8.19+ uses the dir and git commands), "
     "or use --gitleaks never."),
    # --- output -------------------------------------------------------------------
    (r"^could not write the report",
     "Check that the output folder exists and that you can write to it."),
)

_COMPILED: List[Tuple[Pattern[str], str]] = [(re.compile(rx), fix) for rx, fix in _TABLE]


def hint_for(message: str) -> Optional[str]:
    """The one-line fix for a known error *message*, or ``None``."""
    for rx, fix in _COMPILED:
        if rx.search(message):
            return fix
    return None


def all_hints() -> List[str]:
    """Every fix text, for tests and documentation checks."""
    return [fix for _, fix in _TABLE]
