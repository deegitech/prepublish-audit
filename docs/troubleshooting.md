# Troubleshooting

Start with `prepublish-audit doctor`: it checks the whole setup and prints the fix under every
problem. When a run stops with an error (exit code 2), the tool prints the message and, on the next
line, the fix:

```text
prepublish-audit: error: denylist 1 could not be read (No such file or directory)
prepublish-audit: fix: Check that the file named by --denylist or $PREPUBLISH_AUDIT_DENYLIST exists and that you can read it (ls -l FILE); 'prepublish-audit init' creates the default ~/.config/prepublish-audit/denylist.txt.
```

This page lists every such message, the warnings and notes in reports, the findings that surprise
newcomers, the `doctor` items, and the walls around the tool (install, macOS Keychain, AWS, GitHub).
In the messages, `N`, `L`, `FILE`, `PATH` and `...` stand for the parts that change. Messages from
other platforms are quoted as seen at the time of writing; their wording and console labels may
differ.

Error messages never quote a denylist entry: an invalid entry is reported by its line number, and a
regular-expression error without the pattern.

## Contents

1. [Errors about the denylist](#1-errors-about-the-denylist)
2. [Errors about the public config](#2-errors-about-the-public-config)
3. [Errors about the command line, git and gitleaks](#3-errors-about-the-command-line-git-and-gitleaks)
4. [Warnings and notes in a report](#4-warnings-and-notes-in-a-report)
5. [Findings that surprise newcomers](#5-findings-that-surprise-newcomers)
6. [doctor items](#6-doctor-items)
7. [Install, macOS Keychain and AWS](#7-install-macos-keychain-and-aws)
8. [GitHub Actions](#8-github-actions)
9. [GitHub, while publishing](#9-github-while-publishing)

## 1. Errors about the denylist

| Message | Meaning | Fix |
|---|---|---|
| `denylist N could not be read (No such file or directory)` | The file given with `--denylist` or in `$PREPUBLISH_AUDIT_DENYLIST` does not exist. `N` is its position in that list. | Check the path; `prepublish-audit doctor` shows which file is used and where it came from. `prepublish-audit init` creates the default `~/.config/prepublish-audit/denylist.txt`. |
| `denylist N could not be read (Permission denied)` | The file belongs to another user or is not readable by you. | As the file's owner, `chmod 600 FILE` (`ls -l FILE` shows the owner), or copy it to your own `~/.config/prepublish-audit/` and `chmod 600` the copy. |
| `denylist N could not be read (Is a directory)` | `--denylist` or `$PREPUBLISH_AUDIT_DENYLIST` names a folder. | Pass the file, not its folder: `--denylist ~/.config/prepublish-audit/denylist.txt`. |
| `denylist N is not valid UTF-8` | The file was saved in another encoding (Windows-1252, Latin-1...), or it is not a text file. | Save it as UTF-8 in your editor, or convert it: `iconv -f WINDOWS-1252 -t UTF-8 old.txt > denylist.txt`. |
| `denylist N line L: invalid regular expression (... at position P)` | A `re:` entry is not valid Python regular-expression syntax. | Escape the special characters `( ) [ ] { } . * + ?` and the vertical bar with a backslash, or drop the `re:` prefix to match the text literally. Check with `prepublish-audit check-denylist`. |
| `denylist N line L: pattern matches the empty string` | A pattern such as `re:a*` would match everywhere. | Make it require at least one character (`re:a+`). |
| `denylist N line L: entry is shorter than 3 characters and would match almost everything` | Plain, `word:` and `loose:` entries need at least 3 characters. | Use a longer, more specific value, or a regular expression with word boundaries such as `re:\bAB\b`. |
| `denylist N line L: 'allow:' must follow an entry` (or `'label:'`) | An indented line comes before the first entry. | Put `label:` and `allow:` lines, indented, under the entry they belong to. |
| `denylist N line L: 'allow:' needs a path pattern` | An `allow:` line without a path glob. | `allow: PATH-GLOB [line=REGEX] [section=REGEX]`, for example `allow: README.md section=^About`. |
| `denylist N line L: unknown 'allow:' option (use line=<regex> or section=<regex>)` | Something other than `line=` or `section=` after the glob (a path with spaces counts too). | Use only `line=` and `section=`; write a path with spaces as a glob, such as `docs/my?notes.md`. |
| `denylist N line L: 'line=' given twice` / `'section=' needs a regular expression` | A repeated or empty option. | Give each option once, with a value. |
| `denylist N line L: invalid allow regular expression (...)` / `invalid allow path (...)` | The `line=` or `section=` regex, or the path glob, is invalid. | Escape regex characters such as `( [ . +` with a backslash; a path glob cannot be empty or `/`. |
| `denylist N: invalid JSON (line L)` | JSON syntax error. | `python3 -m json.tool FILE > /dev/null` shows the exact position without printing the content. |
| `denylist N: invalid TOML` | TOML syntax error. | Strings need quotes and every entry is an `[[entries]]` table; or switch to the text format (`.txt`). |
| `denylist N: K unknown top-level key(s); only 'entries' and 'version' are allowed` | A TOML or JSON denylist that is not in the `entries` layout. The key names are not printed, because they could be entries. | Put every value in the `entries` list: `[[entries]]` tables in TOML, `{"entries": [...]}` in JSON. |
| `denylist N: expected a table/object with an 'entries' list` / `'entries' must be a list` | Same layout problem. | As above. |
| `denylist N entry E: give exactly one of literal, regex, word, loose` (or `must be a string or a table`, `K unknown key(s)`, `every allow item needs a 'path'`, `'label' must be a string`) | A structured entry has the wrong keys or types. | Each entry is a string, or a table with exactly one of `literal`, `regex`, `word`, `loose`, plus optional `label` and `allow = [{ path = "GLOB" }]`. |
| `denylist N: reading TOML on Python 3.10 needs the 'tomli' package: ...` | Python 3.10 has no TOML parser. | `pipx inject prepublish-audit tomli` (or `pip install tomli` in the same environment), or use a `.txt` or `.json` denylist. |
| `no denylist entries were loaded (--require-denylist)` | `--require-denylist` was given, but no file was found, the files are empty, or a pipe such as `<(pa_denylist)` was empty because its command failed. | Pass `--denylist FILE` or set `PREPUBLISH_AUDIT_DENYLIST`. With the macOS Keychain: the helper is not loaded in this terminal, the item name is wrong, or the keychain is locked (see [section 7](#7-install-macos-keychain-and-aws)). In GitHub Actions the secret is empty on pull requests from forks, in jobs without the right `environment:`, and in private repositories on GitHub Free (see [section 8](#8-github-actions)). |
| `no denylist given and none found in the default location` (`check-denylist`) | Nothing to check. | `prepublish-audit init`, or name the file: `prepublish-audit check-denylist FILE`. |
| `EMPTY: 0 entries in N file(s), so it protects nothing.` (`check-denylist`, exit code 1) | The file holds only comments (for example the template from `init`), or a pipe such as `<(pa_denylist)` was empty. | Add one value per line (setup.md, step 3). For a pipe, see [section 7](#7-install-macos-keychain-and-aws). |
| `cannot find a home directory for the private denylist` (`init`) | Neither `HOME` nor `XDG_CONFIG_HOME` is usable. | Set `HOME` (or `XDG_CONFIG_HOME`), or create the denylist yourself and pass it with `--denylist`. |

## 2. Errors about the public config

The public config is `.prepublish-audit.toml`, `prepublish-audit.toml`, `.prepublish-audit.json`
or `[tool.prepublish-audit]` in `pyproject.toml`. Unknown key names are shown with `_` instead
of `-`.

| Message | Meaning | Fix |
|---|---|---|
| `unknown config key(s): NAME` | A typo, or a key that does not exist. Unknown keys are errors so that a typo cannot switch a check off. | Compare with README, "Configuration reference": keys use dashes (`fail-on`), heuristic settings go under `[heuristics]`. |
| `unknown heuristics key(s): NAME` | A typo under `[heuristics]`. | Compare with the `heuristics.*` keys in the README. |
| `'KEY' must be a list of strings` / `must be true or false` / `must be an integer >= N` / `must be a number between 0 and 8` / `'heuristics' must be a table` / `'allow' must be a list of tables` | Wrong value type. | Lists as `["a", "b"]`; `true`/`false` and numbers without quotes. |
| `'fail-on = "never"' is accepted only on the command line (--fail-on never)` | The config is part of the repository, so it may not turn failing off. | Use `fail-on = "error"`, `"warning"` or `"note"`, or pass `--fail-on never` on the command line. |
| `'fail-on' must be one of error, warning, note` | Unknown level. | Use one of those three. |
| `'severity': level for 'RULE' must be error, warning or note` | Unknown level in the `severity` table. | For example `severity = { "leak.email" = "note" }`. |
| `'gitleaks' must be one of auto, always, never` | Unknown mode. | `gitleaks = "auto"`, `"always"` or `"never"`. |
| `the denylist cannot be disabled from the public config` / `the denylist severity cannot be changed from the public config` / `allow #N: denylist matches can only be allowed inside the private denylist` | By design: anyone who can open a pull request can edit the config. | Allow an entry in the private denylist itself, with an indented `allow: PATH-GLOB` line under it. |
| `'disable': coverage rules (scan.*, config.*, git.shallow-clone) can only be changed on the command line ...` (also for `severity` and `allow #N`) | By design: these rules say what could not be checked. | Use `--disable RULE` or `--allow RULE:GLOB` on the command line, for example in your CI step. |
| `allow #N: give at least one of rules, paths, line or values` | An empty `[[allow]]` entry would allow everything. | Add `rules`, `paths`, `line` or `values`, and a `reason`. |
| `allow #N: unknown key(s): NAME` | A typo in an `[[allow]]` entry. | The keys are `rules`, `paths`, `line`, `values` and `reason`. |
| `allow #N: empty path pattern` | A path glob that is `/` or only spaces. | Remove it, or write a glob such as `"docs/**"`. |
| `'internal-patterns #N': invalid regular expression (...)` / `'allow #N.line': invalid regular expression (...)` | A regex in the config does not compile. | `python3 -c "import re; re.compile(r'PATTERN')"` shows the problem. |
| `internal-patterns #N: pattern matches the empty string` | The pattern would match everywhere. | Make it require at least one character. |
| `'max-file-size': unrecognised size (...)` / `--max-file-size: ...` | A size the tool cannot read. | A number of bytes or a unit: `64MiB`, `500MB`, `1GiB`. |
| `FILE: invalid TOML (...)` / `FILE: invalid JSON (line L)` / `FILE: expected a table/object` | Syntax error, or a top level that is not a table. | Fix the reported line; strings need quotes, tables are `[name]`. |
| `FILE: reading TOML on Python 3.10 needs the 'tomli' package: ...` | As for the denylist. | `pipx inject prepublish-audit tomli`, or use `.prepublish-audit.json`. |
| `cannot read config FILE: ...` | The config exists but cannot be read. | Fix its permissions, or pass `--no-config` to use the defaults. |

## 3. Errors about the command line, git and gitleaks

| Message | Meaning | Fix |
|---|---|---|
| `path not found: PATH` | The file or folder to scan does not exist. | `cd` into the repository first; quote paths that contain spaces. |
| `--reveal is refused in CI because build logs are often public (set PREPUBLISH_AUDIT_ALLOW_REVEAL=1 to override)` | A CI variable such as `CI` or `GITHUB_ACTIONS` is set. | Re-run the same command with `--reveal` on your own machine. Overriding prints secrets into build logs. |
| `--reveal output must not be written inside a scanned tree` | A revealed report contains the secrets; inside the tree it could be committed. | Write it outside every repository (`-o ~/prepublish-audit-report.txt`) and delete it when done. |
| `--allow expects RULE:PATH-GLOB, for example leak.email:docs/**` | Missing colon or glob. | `--allow 'leak.email:docs/**'` (quoted, so the shell does not expand it). |
| `--allow cannot allow denylist matches` / `the denylist cannot be disabled` | By design. | Use an indented `allow:` line under the entry in the private denylist. |
| `--history needs a git repository (and git on PATH)` | Not inside a git working tree, or git is missing. | Run it inside a clone (`git rev-parse --show-toplevel` must work) and check `git --version`, or drop `--history`. |
| `--git-files needs git: ...` / `--git-files: not inside a git work tree (or git failed)` | Same, for `--git-files`. | Run it inside a clone with git installed, or drop `--git-files` to scan everything on disk. |
| `git COMMAND failed: ...` | git could not read part of the repository, for example a blob missing from a partial (`--filter`) clone; lazy fetching is off on purpose. | `git status` and `git fsck`; for a partial or damaged clone, make a full clone and scan that. |
| `gitleaks was requested (--gitleaks always) but is not on PATH` | `--gitleaks always` or `gitleaks = "always"` without gitleaks installed. | `brew install gitleaks`, or a release binary from github.com/gitleaks/gitleaks/releases; or `--gitleaks auto`. |
| `gitleaks timed out` | gitleaks ran for more than an hour. | Exclude large generated folders (`--exclude`), or `--gitleaks never`; the built-in secret rules still run. |
| `gitleaks could not start (...)` | The binary cannot run here (permissions, wrong CPU architecture). | Check that `gitleaks version` works, or `--gitleaks never`. |
| `gitleaks exited with status N` / `gitleaks wrote an unreadable report` | An unexpected gitleaks version or a crash. | Update gitleaks (8.x is expected; 8.19 and newer use the `dir` and `git` commands), or `--gitleaks never`. |
| `could not write the report: ...` | The `-o`, `--json-output`, `--sarif-output` or `--summary-markdown` path cannot be written. | Check that the folder exists and that you can write to it. |
| `error: argument --fail-on: invalid choice: ...`, `error: unrecognized arguments: ...` (or another usage error), followed by `prepublish-audit: fix: run 'prepublish-audit scan --help' ...` | A misspelled option or value. | `prepublish-audit scan --help` (or `doctor --help`, `check-denylist --help`...) lists the options and values. |

With `--gitleaks auto` (the default) the gitleaks errors above do not stop the run; they become the
note `gitleaks did not complete (...)`, with the same fix.

## 4. Warnings and notes in a report

The run completes; these explain what it did or did not cover.

| Message | Meaning | Fix |
|---|---|---|
| `prepublish-audit: warning: denylist N is readable by other users (mode 644); run chmod 600 on it` | Group or other users can read the file. | `chmod 600 FILE`. A denylist streamed through a pipe (`--denylist <(...)`) is not a file on disk and is not reported. |
| `denylist N line L: duplicate of entry M` | The same value twice (case-insensitive). | Remove one of the lines. |
| `denylist N line L: entry is only 3 characters long and may be noisy` | Short entries match inside longer words. | Use a longer value, or `word:` so it only matches whole words. |
| Note: `No private denylist loaded: only built-in rules ran.` | No `--denylist`, no `$PREPUBLISH_AUDIT_DENYLIST`, no default file. | `prepublish-audit init` and fill the file (setup.md, steps 2 to 4). |
| `prepublish-audit: warning: the denylist given with --denylist has no entries (an empty file, or a pipe whose command printed nothing), ...` and the note `The private denylist has no entries: only built-in rules ran.` | The file holds no entries, or `<(pa_denylist)` was empty (helper not loaded, wrong item name, keychain locked). Only the built-in rules ran, so a `PASSED` means little. | `prepublish-audit check-denylist <(pa_denylist)` shows the count ([section 7](#7-install-macos-keychain-and-aws)). Add `--require-denylist` so that this stops the scan. |
| `Note: no private denylist entries were loaded, so only the built-in rules ran.` (with `--quiet`) | As above, in the short report that hooks print. | As above. |
| Note: `gitleaks is not installed; built-in secret rules only.` | Optional helper missing. | `brew install gitleaks` (optional). |
| Note: `gitleaks did not complete (...); built-in rules still ran. Fix: ...` | See section 3. | The fix is printed in the note. |
| Note: `exiftool failed on N invocation(s); built-in parsers were used for those files.` (also `ffprobe`, `pdfinfo`) | The helper crashed on some files. | Update the helper; the files were still checked by the built-in parsers. |
| Note: `Not applied while a denylist is loaded, because they would narrow what it checks: ...` | The public config tried to shrink limits or turn off decoding, archives or helpers. | Nothing to do; use the command-line options if you really need that. |
| Note: `Failed although fail-on is 'error': ...` | Content the denylist could not check (`scan.incomplete`, `git.shallow-clone`) fails at `warning` while a denylist is loaded. | Fix the coverage problem, or pass `--fail-on` on the command line. |
| `Warning: no files were scanned (everything was excluded, ignored or empty).` | Excludes or `--git-files` left nothing. | Check `exclude` and `--exclude`; run without `--git-files` to see what is on disk. |
| `Warning: nothing under PATH was scanned, because git would not publish it (--git-files); ...` | PATH is ignored by git, typically a build folder such as `dist/`, so `--git-files` read nothing there. `--history` still read the history, so the rest of the run looks complete. | Scan the folder without `--git-files`: `prepublish-audit scan dist/`. |
| Note: `--git-files: git would publish nothing under PATH ...` | Everything under PATH is ignored by git or outside the work tree. | Run without `--git-files`, or check `.gitignore`. |
| `***` inside a path | The path contains a denylist entry and is masked so it cannot leak into logs. | `--reveal` on your own machine shows the real path. |
| `History: N finding(s) live only in git history.` | Old blobs, paths, messages or identities contain the finding. | Deleting the file is not enough: publish a fresh single-commit history or rewrite history ([release-checklist.md](release-checklist.md)). |

## 5. Findings that surprise newcomers

Every finding has a rule ID; the report ends with a "How to fix" line per rule, and
[rules.md](rules.md) describes all of them.

| Rule | Meaning | Fix |
|---|---|---|
| `config.denylist-in-tree` | The private denylist file sits inside the tree you are scanning. | Move it outside every repository, for example to `~/.config/prepublish-audit/`. If it was ever committed, publish a fresh history. |
| `scan.incomplete` | Something could not be checked: too large, encrypted, unreadable, or an unsupported container (rar, 7z, dmg, iso). | Check it by hand, raise the limit (`--max-file-size 64MiB`), or exclude it on the command line if it is safe. |
| `git.shallow-clone` | Older commits were not fetched, so they were not scanned. | `git fetch --unshallow`; in GitHub Actions use `actions/checkout` with `fetch-depth: 0`. |
| `git.author-identity` | A commit, tag or author email that is not a no-reply address. | Publish from a fresh history committed with `<id>+<login>@users.noreply.github.com` (GitHub > Settings > Emails) or `noreply@github.com`. |
| `leak.numeric-id` on a timestamp, a version or a constant | Long digit runs look like account IDs. | `heuristics.allowed-numbers = ["..."]`, or an `[[allow]]` entry for the path. |
| `secret.high-entropy-string` on a hash or a lockfile | Random-looking strings look like keys. | Check it is not a credential, then allow it with an `[[allow]]` entry (`values`, `paths` or `line`). |
| `denylist` on your own company name in `LICENSE` | The entry is in the denylist on purpose. | Add `allow: LICENSE` (and, for example, `allow: README.md section=^About`) under the entry. |
| `metadata.author`, `metadata.location` | Author, device or GPS data inside an image, PDF, Office file or video. | `exiftool -all= FILE` (images, PDF), "Inspect Document" in Office, or export the file again. |

## 6. doctor items

`prepublish-audit doctor` prints `✓` passed, `✗` failed (exit code 1), `!` worth fixing (exit 0,
or 1 with `--strict`) and `-` skipped. Every `✗` and `!` line is followed by `fix:`.

| Item | Meaning | Fix |
|---|---|---|
| `✗ No private denylist found, so a scan would run the built-in rules only` | Nothing at `--denylist`, `$PREPUBLISH_AUDIT_DENYLIST` or the default location. | `prepublish-audit init`, then fill `~/.config/prepublish-audit/denylist.txt`. |
| `✗ Denylist not found: FILE (from $PREPUBLISH_AUDIT_DENYLIST)` | The variable points at a file that does not exist. | `export PREPUBLISH_AUDIT_DENYLIST=~/.config/prepublish-audit/denylist.txt`, or unset it. |
| `✗ Denylist cannot be used: ...` | The denylist does not load; the message is one from section 1. | The fix from section 1 is printed under it. |
| `✗ Denylist has no entries yet, so it protects nothing` | Usually right after `init`: the template holds only comments. | Fill it (setup.md, step 3). |
| `✗ Denylist can be read by other users (mode 644)` | Group or others can read it. | `chmod 600 FILE`. |
| `✗ The denylist is inside the tree you are going to scan (PATH)` | A scan would report `config.denylist-in-tree`. | The doctor prints the commands: `mkdir -p -m 700 ~/.config/prepublish-audit && mv FILE ~/.config/prepublish-audit/denylist.txt && chmod 600 ~/.config/prepublish-audit/denylist.txt`, so that `scan` finds it without options. If that name is taken, move it elsewhere outside every repository and pass the new path with `--denylist`. |
| `! The denylist is inside ~, which contains your home folder` / `! ~ is your home folder or contains it, so a scan would read everything in it` | You ran the doctor in your home folder (or above it), for example from a new terminal. Instead of a scan command, the doctor ends with `Do not scan there`. | Run it inside the repository you will publish, or pass its path: `prepublish-audit doctor PATH`. |
| `✗ Denylist is tracked by git in the repository that contains it` | It is committed (or staged) somewhere. | `git rm --cached FILE`, add it to `.gitignore`, move it out; if that repository was ever pushed, treat the entries as exposed. |
| `! Denylist is inside a git working tree and not ignored, so 'git add -A' would commit it` | For example a dotfiles repository that contains `~/.config`. | Add it to that repository's `.gitignore`, or move it. |
| `✗ Public config is invalid: ...` | A message from section 2. | The fix is printed under it. |
| `✗ Path to scan not found: PATH` | The path given to the doctor does not exist. | Pass the folder or file you will publish. |
| `✗ gitleaks not found, but the config requires it (gitleaks = "always")` | Every scan would stop with exit code 2. | Install gitleaks, or set `gitleaks = "auto"`. |
| `! Shallow clone: a --history scan would miss older commits` | The clone has only part of the history. | `git fetch --unshallow`. |
| `! New commits here would carry a personal email address (not shown)` | git would use an address that is not a no-reply one; with no email configured, git makes one up from your user and computer names. | `git config user.email "<id>+<login>@users.noreply.github.com"` (GitHub > Settings > Emails shows yours). |
| `! pre-push hook not installed: ...` / `! pre-commit hook not installed: ...` | `.pre-commit-config.yaml` lists prepublish-audit, but git will not run it. | `pre-commit install --hook-type pre-push` / `pre-commit install`. |
| `! git not found` / `! gitleaks not found` / `! exiftool not found` / `! ffprobe not found` / `! pdfinfo not found` | Optional helpers (git is needed for `--git-files` and `--history`). | The install command is printed under the item. |
| `! ...: no TOML parser, so .toml configs and denylists cannot be read` | Python 3.10 without `tomli`. | `pipx inject prepublish-audit tomli`. |

When nothing failed, the doctor ends with `Ready. Next:` and the scan to run. It adds
`--git-files --history` only when the path is the top of a git repository (a gitignored build
folder such as `dist/` has nothing for `--git-files` to read), and it repeats your own `--denylist`,
`-c` and `--no-config` options, with `--require-denylist`. A denylist you streamed (`<(...)`) has to
be streamed again, because a pipe can be read only once.

## 7. Install, macOS Keychain and AWS

| Message or symptom | Meaning | Fix |
|---|---|---|
| `prepublish-audit: command not found` | pipx's folder for commands is not on `PATH`. | `pipx ensurepath`, then open a new terminal. |
| `ERROR: Package 'prepublish-audit' requires a different Python: 3.9.x not in '>=3.10'` | Python older than 3.10. | `pipx install --python python3.12 "git+https://github.com/deegitech/prepublish-audit@v0.1.0"` (any 3.10+). |
| `security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.` | No Keychain item with that service and account name. | Store it (setup.md, step 4B), and use the same `-s prepublish-audit-denylist -a "$USER"` in the helper. |
| `command not found: pa_denylist` (zsh), `pa_denylist: command not found` (bash), and `check-denylist <(pa_denylist)` prints `EMPTY: 0 entries` | The helper is not loaded in this terminal: it was added to `~/.zshrc` after the terminal opened, or to another shell's file. | Open a new terminal, or run `source ~/.zshrc`. |
| `security: ...: User interaction is not allowed.` (wording varies) | The keychain is locked and cannot ask for its password, for example in an SSH session. The pipe is then empty. | Unlock it in that session: `security unlock-keychain ~/Library/Keychains/login.keychain-db`; or use option A (a private file) on that machine. |
| `check-denylist <(pa_denylist)` shows far fewer entries than you wrote, or a strange `invalid` error | Observed (Oct 2026): the item was stored through the interactive prompt, which keeps only 128 characters; or it was stored without base64. | Store it again from the file: `-w "$(base64 < FILE)"` (setup.md, step 4B). |
| `check-denylist <(pa_denylist)` reports 1 entry, and scans match nothing | The command text was stored instead of the denylist: the clipboard variant's store command and `pbcopy </dev/null` were pasted together. | Store it again from the file, or paste one line at a time. |
| Entries with letters such as ş, ğ or ı stopped matching after storing from the clipboard | `pbpaste` used a locale that is not UTF-8 (see `man pbcopy`). | Store from the file (`base64 < FILE`), or use `LANG=en_US.UTF-8 pbpaste`. |
| Scans still find a value you removed from the Keychain item, or miss one you added | The plaintext file from step 3 is still at `~/.config/prepublish-audit/denylist.txt`, and plain scans and hooks read it. | Delete it after storing the item (setup.md, step 4B), and pass `--require-denylist --denylist <(pa_denylist)`. |
| `An error occurred (ParameterNotFound) when calling the GetParameter operation` | Wrong parameter name, or another region. | Check `--name`, and the region (`--region` or `AWS_REGION`). |
| `An error occurred (AccessDeniedException) when calling the GetParameter operation: ... is not authorized to perform: ssm:GetParameter ...` | The server's role may not read the parameter. | Allow `ssm:GetParameter` on that parameter for the role; add `kms:Decrypt` on the key if you use your own KMS key. |
| `An error occurred (ValidationException) when calling the PutParameter operation: ... maximum parameter value of 4096 characters ...` | The denylist is larger than a standard parameter holds. | `--tier Advanced` (8 KB), or split it into several parameters and files. |

## 8. GitHub Actions

| Message or symptom | Meaning | Fix |
|---|---|---|
| `::error title=prepublish-audit::No denylist was provided and require-denylist is true. ...` | The `denylist` input was empty. | Check that the job has `environment: prepublish-audit` (the environment that holds the secret), that the secret is named `PREPUBLISH_DENYLIST`, and that the run is not a pull request from a fork or a Dependabot pull request (they get no Actions secrets). A private repository on GitHub Free has no environment secrets at all: store the secret after the repository goes public, or use a paid plan. |
| `::warning title=prepublish-audit::No denylist was provided, so only the built-in rules ran. ...` | The built-in-rules job, as intended, or a missing secret. | Nothing for the pull-request job; otherwise as above. |
| `::warning title=prepublish-audit::Shallow clone: check out with fetch-depth: 0 to scan the whole history.` | `actions/checkout` fetched one commit. | Add `fetch-depth: 0` to the checkout step. |
| `::error title=prepublish-audit::Python 3.10 or newer is required on the runner ...` | The runner's default Python is too old. | Add `actions/setup-python` before the step. |
| The denylist job waits with "Waiting for review" | The environment has required reviewers. | A reviewer opens the run → **Review deployments** → ticks the environment → **Approve and deploy**. |
| `Resource not accessible by integration` when uploading SARIF | The job lacks permission to write code-scanning results. | Give that job `permissions: security-events: write`. |
| `Advanced Security must be enabled for this repository to use code scanning` (wording varies) | Code scanning is not available on this private repository. | Remove the SARIF upload step until the repository is public, or enable GitHub Code Security (Settings → Advanced Security). |
| `Unable to resolve action deegitech/prepublish-audit@...` | A wrong tag or commit SHA in `uses:`. | `git ls-remote https://github.com/deegitech/prepublish-audit refs/tags/v0.1.0` and use that SHA. |

## 9. GitHub, while publishing

| Message or symptom | Meaning | Fix |
|---|---|---|
| `remote: error: GH007: Your push would publish a private email address.` | Your commits use your private email and **Block command line pushes that expose my email** is on. | `git config user.email "<id>+<login>@users.noreply.github.com"`, then for a fresh single-commit repository `git commit --amend --reset-author --no-edit` and push again; for more commits, publish a fresh history. |
| `remote: error: GH009: Secrets detected! This push failed.` or `remote: error: GH013: Repository rule violations found ...` with `Push cannot contain secrets` | Push protection found a credential in a commit. | Rotate the credential, remove it from every commit (a fresh history is simplest) and push again. Use the unblock link in the message only for a test value or a false positive. |
| `remote: error: GH006: Protected branch update failed for refs/heads/main.` or `GH013: Repository rule violations found for refs/heads/main.` (`Changes must be made through a pull request`, `Cannot force-push to this branch`) | Branch protection or a ruleset blocks direct pushes. | Push a branch and open a pull request. For the very first push of a new repository, add the protection after it. |
| The pre-push hook never runs | Only the pre-commit hook type was installed. | `pre-commit install --hook-type pre-push` (`prepublish-audit doctor` reports it). |
| `This API operation needs the "admin:org" scope.` from `gh` | Organisation-wide settings need that scope. | `gh auth refresh -h github.com -s admin:org`, or use the web UI; drop it afterwards with `gh auth refresh -h github.com -r admin:org`. |
| Secret scanning, push protection or CodeQL are missing in a private repository's settings | They are paid products on private repositories (at the time of writing). | Rely on prepublish-audit and the local hooks while private; turn them on right after the repository goes public (setup.md, step 8.8). |
