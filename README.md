# prepublish-audit

[![CI](https://github.com/deegitech/prepublish-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/deegitech/prepublish-audit/actions/workflows/ci.yml)
[![CodeQL](https://github.com/deegitech/prepublish-audit/actions/workflows/codeql.yml/badge.svg)](https://github.com/deegitech/prepublish-audit/actions/workflows/codeql.yml)
[![Python 3.10-3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776ab)](pyproject.toml)
[![Runtime dependencies: none](https://img.shields.io/badge/runtime%20dependencies-none-brightgreen)](pyproject.toml)
[![SARIF 2.1.0](https://img.shields.io/badge/output-SARIF%202.1.0-6f42c1)](#output-and-exit-codes)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**The last gate before code, sites and bundles leave your company.** prepublish-audit checks a
repository, a site build or a zip you are about to share against a **private denylist** of strings
only you know, plus built-in secret patterns and leak heuristics. It looks inside file contents,
file names, binaries, archives, image/PDF/Office/video metadata and the **whole git history**, and it
never prints what it found unless you ask for it on your own machine.

[Türkçe özet](README.tr.md)

```text
$ prepublish-audit scan .
prepublish-audit 0.1.0
Scanned: 2 files (2 text, 0 binary)
Denylist: 1 entry from 1 file

docs/roadmap.md
  3:1       error    denylist                         Denylist match: codename  [redacted, 13 chars]

src/settings.py
  1:17      error    secret.github-token              GitHub token  [redacted, 40 chars]
  2:14      warning  leak.home-path                   Absolute home-directory path  [redacted, 32 chars]
  3:16      warning  leak.identifier-assignment       Hard-coded account identifier  [redacted, 10 chars]

FAILED: 2 error(s), 2 warning(s), 0 note(s) (fail-on: warning)
How to fix:
  denylist                    Remove or rename it. If it is allowed in this place, add an indented 'allow:' line under the entry.
  secret.github-token         Revoke it at github.com/settings/tokens (or the app settings) and create a new one.
  leak.home-path              Use relative paths, ~, or an environment variable.
  leak.identifier-assignment  Read the ID from configuration that is not published.
  A finding that is fine to publish: allow it (README, 'Allowing known-good findings'). Errors and fixes: https://github.com/deegitech/prepublish-audit/blob/v0.1.0/docs/troubleshooting.md
Matched text is redacted. Re-run locally with --reveal to see it (never in CI logs).
```

## First 15 minutes

1. **Install** with pipx: `pipx install "git+https://github.com/deegitech/prepublish-audit@v0.1.0"`.
2. **Create your private denylist** and the public config: `cd` into the repository you will
   publish, run `prepublish-audit init`, then add the strings that must never leave to
   `~/.config/prepublish-audit/denylist.txt`.
3. **Check the setup:** in the same folder, run `prepublish-audit doctor`. It prints `✓` or `✗` for
   every check (denylist found, valid, private and outside the repository; config; git; optional
   helpers) and the exact fix under every `✗`. It exits 0 when you are ready and prints the scan
   command to run next.
4. **Scan:** `prepublish-audit scan --git-files --history .` It only reads; nothing is changed.

[docs/setup.md](docs/setup.md) walks through every step from zero, including where to keep the
denylist (a private file, the macOS Keychain, a GitHub environment secret, AWS SSM on servers) and
the GitHub settings to switch on before a repository goes public.
[docs/troubleshooting.md](docs/troubleshooting.md) lists every error message with its meaning and
fix; the tool prints the same fix under each error.

## Contents

- [First 15 minutes](#first-15-minutes)
- [Why](#why)
- [What it checks](#what-it-checks)
- [Install](#install)
- [Quickstart](#quickstart)
- [Configuration reference](#configuration-reference)
- [Examples](#examples)
- [Security model](#security-model)
- [Limitations](#limitations)
- [FAQ](#faq)
- [About](#about)
- [License](#license)

## Why

Secret scanners are good at one job: finding credential-shaped strings. The leaks that hurt small
teams are often something else:

- an ad-account, customer or campaign ID in a script you open-source;
- `/Users/<name>/...` inside a source map that ships with your website;
- a colleague's email in a commit from two years ago;
- the author name and GPS position inside a screenshot or a PDF;
- a product codename in a branch name or a deleted file that is still in history;
- a link to an internal Google Doc, Slack thread or ads console.

None of these look like an API key, and most of them are specific to you. prepublish-audit combines
a private list of your own sensitive strings with heuristics for these shapes, and treats anything it
could not inspect as a finding instead of silently skipping it.

It is the gate we run before releasing our own repositories.

## What it checks

| Layer | What it looks at |
|---|---|
| **Private denylist** | Your own strings and patterns: case-insensitive literals, regular expressions, whole-word and separator-insensitive entries. Each entry can be allowed in specific places (path glob, line regex, Markdown section). Entries are never printed. |
| **Secrets** | Private keys; AWS, GitHub, GitLab, Google API/OAuth, Meta, Slack, Stripe, npm, PyPI, OpenAI and Anthropic credentials; JWTs; passwords in URLs; `Authorization` headers; hard-coded credentials; high-entropy strings. Optionally merges [gitleaks](https://github.com/gitleaks/gitleaks) results. |
| **Leak heuristics** | Home-directory and `/Volumes/...` paths, emails outside allowed domains, long numeric IDs, private and public IPs, internal hostnames, links to private workspaces and consoles, confidentiality markings, phone and card numbers, cloud account/resource IDs, ad and analytics account IDs, Apple team/key/issuer IDs, hard-coded `*_id` values, and your own internal-name patterns. |
| **Files and names** | Every file and directory name; sensitive file types (`.p8`, `.p12`, keystores, SSH keys, Terraform state, `.env`...); `.DS_Store`, resource forks and per-user IDE state; embedded `.git` directories; symlink targets. |
| **Encoded content** | Base64, percent-encoding, HTML entities and `\u` escapes are decoded and checked again. |
| **Binaries and archives** | Printable ASCII and UTF-16 strings in binaries; zip, jar, apk, ipa, docx/xlsx/pptx, tar, gzip, bzip2 and xz, nested, with size, depth and decompression-bomb limits. |
| **Metadata** | EXIF author/owner/host computer/serials and GPS, XMP, PNG text chunks, WebP, RIFF INFO, QuickTime/MP4 user data and ISO 6709 locations, PDF info and page text, every Office/ODF document property (custom ones included), alt text and other markup attributes, comment and revision authors. Uses exiftool, ffprobe and pdfinfo when installed. |
| **Git history** (`--history`) | Every reachable blob, including deleted files; every path that ever existed, old names of renamed files included; commit and tag messages; author, committer and tagger identities; branch, tag and stash names; shallow clones. |
| **Output** | Human, JSON, SARIF 2.1.0 (GitHub code scanning), GitHub annotations and a Markdown step summary. Exit codes 0/1/2. |

The full rule list with severities is in [docs/rules.md](docs/rules.md).

## Install

prepublish-audit needs Python 3.10 or newer and has no runtime dependencies.

```bash
pipx install "git+https://github.com/deegitech/prepublish-audit@v0.1.0"
# or, inside a virtual environment:
python -m pip install "git+https://github.com/deegitech/prepublish-audit@v0.1.0"
```

A PyPI release is planned; until then install from GitHub as above. Python 3.10 has no TOML parser
in the standard library, so to read TOML configs and denylists there, install the `toml` extra:

```bash
pipx install "prepublish-audit[toml] @ git+https://github.com/deegitech/prepublish-audit@v0.1.0"
```

JSON configs and text denylists work everywhere, and on Python 3.10 without the extra
`prepublish-audit init` writes a JSON config instead of a TOML one.

Optional helpers, used automatically when they are on `PATH`:
[exiftool](https://exiftool.org/), `ffprobe` (from [FFmpeg](https://ffmpeg.org/)), `pdfinfo`
(from [Poppler](https://poppler.freedesktop.org/)) and [gitleaks](https://github.com/gitleaks/gitleaks).
Without them the built-in parsers still read EXIF, XMP, PNG, MP4/QuickTime, PDF and Office metadata.

## Quickstart

```bash
# 1. In the repository you will publish: create a private denylist (outside every repository)
#    and a public config, then check the setup.
cd ~/src/myrepo
prepublish-audit init
$EDITOR ~/.config/prepublish-audit/denylist.txt
prepublish-audit check-denylist
prepublish-audit doctor

# 2. Scan before you publish.
prepublish-audit scan --git-files --history .    # a repository you are about to open-source
prepublish-audit scan site/dist                  # a static site build
prepublish-audit scan release.zip                # a bundle you are about to share

# 3. On your own machine, see exactly what matched.
prepublish-audit scan --git-files --history --reveal .
```

`scan` is the default command, so `prepublish-audit .` works too. Fix the findings, allow the
known-good ones (see [Allowing known-good findings](#allowing-known-good-findings)) and run again
until it passes. If findings remain in history, follow [docs/release-checklist.md](docs/release-checklist.md).

## Configuration reference

### The private denylist

The denylist lists what must never leave: customer and account IDs, internal host and product names,
people's names, card digits, internal URLs. **Keep it outside every repository** and readable only by
you (`chmod 600`). A denylist found inside the scanned tree is reported as an error and is not scanned.

Where it is read from, first match wins:

1. `--denylist FILE` (repeatable);
2. `$PREPUBLISH_AUDIT_DENYLIST` (one path, or several separated by `:`; `;` on Windows);
3. `$XDG_CONFIG_HOME/prepublish-audit/denylist.{txt,toml,json}`, by default
   `~/.config/prepublish-audit/`.

`--no-denylist` skips all of them; `--require-denylist` fails (exit 2) when none is loaded.

**Text format**, one entry per line:

```text
# Whole-line comments start with '#'. There are no inline comments:
# everything after the prefix belongs to the entry.
Acme Internal Tools
re:\bacme-(?:prod|staging)-[a-z0-9-]+\b
word:4821
loose:heron dashboard
lit:# an entry that starts with a hash
Acme Corp
  label: company name
  allow: LICENSE
  allow: README.md section=^About
  allow: **/*.py line=^# Copyright
```

| Syntax | Meaning |
|---|---|
| plain line | Literal, matched case-insensitively anywhere (Turkish `I`/`ı`/`İ` included). Whitespace inside it also matches line breaks and runs of spaces, so wrapped prose is caught. |
| `re:` | Python regular expression, case-insensitive. Errors are reported by line number only. |
| `word:` | Literal that must not touch other letters or digits (`word:4821` does not match `148210`). |
| `loose:` | Literal whose words may be joined by spaces, dots, dashes, underscores or nothing (`loose:heron dashboard` also matches `heron-dashboard` and `HeronDashboard`). `--loose-denylist` applies this to every plain entry. |
| `lit:` | Escape hatch for an entry that starts with `#`, `re:` and so on. |
| indented `label: text` | Shown in reports instead of "entry 6 (line 9)". Describe the entry, never repeat it. |
| indented `allow: GLOB [line=REGEX] [section=REGEX]` | The entry is allowed in matching places: a path glob, optionally limited to lines that match `line=` or to Markdown sections whose heading (or a parent heading) matches `section=`. |

Entries shorter than three characters are rejected. Matching also runs on Unicode-normalised text and
on decoded content: percent-encoded, HTML-entity and `\u`-escaped text, and base64 tokens of 16 or more
characters (values of 12 or more bytes; a shorter value encoded on its own is not decoded).

**TOML or JSON** (`.toml` / `.json` extension) hold the same information:

```toml
[[entries]]
literal = "Acme Corp"          # or regex = '...', word = "...", loose = "..."
label = "company name"
allow = [{ path = "LICENSE" }, { path = "README.md", section = "^About" }]
```

In the GitHub Action, pass the denylist content from an environment secret, never to pull-request
runs; see [Examples](#examples).

### The public config

Settings that are safe to publish live in `.prepublish-audit.toml` (or `prepublish-audit.toml`,
`.prepublish-audit.json`, or `[tool.prepublish-audit]` in `pyproject.toml`). The scanner looks for
it in the scanned directory and its parents, up to the repository root. Unknown keys are errors, so
typos cannot silently disable a check. **Never put private values here; they belong in the denylist.**

Globs in `exclude`, `[[allow]]`, `--exclude`, `--allow` and denylist `allow:` lines are relative to
the config file's directory, or, without a config, to the scanned folder (for files named on the
command line, as pre-commit does: to the current directory). History paths are matched the same way.

Anyone who can change the repository can change this file, so it only tunes the built-in rules and
cannot weaken the denylist:

- **Excluded paths are still checked against the denylist** (and only against it) when one is
  loaded. To skip a path completely, pass `--exclude` on the command line.
- With a denylist loaded, config values that would shrink what is read are **not applied**: a
  `max-file-size`, `max-archive-size` or `max-archive-depth` below the default, and `decode`,
  `archives` or `external-tools` turned off. A note says so; the command-line options still work.
- The coverage rules (`scan.*`, `config.*`, `git.shallow-clone`) cannot be disabled, allowed or
  re-graded here, and `fail-on = "never"` is refused; only the command line can do that.
- With a denylist loaded, content it could not check (`scan.incomplete`, `git.shallow-clone`) fails
  the run at `warning` level even if the config sets `fail-on = "error"`, unless `--fail-on` is
  given on the command line.

The config still decides which built-in findings fail the build, so protect it like code (for
example with CODEOWNERS and required reviews).

```toml
fail-on = "warning"
exclude = ["dist/**", "*.min.js"]
disable = ["leak.phone-number"]
severity = { "leak.numeric-id" = "note" }

[heuristics]
numeric-id-min-length = 10
allowed-email-domains = ["acme.example"]
internal-patterns = [{ pattern = '(?i)\bheron-[a-z]+-prod\b', label = "service names" }]

[[allow]]
rules = ["leak.*"]
paths = ["tests/fixtures/**"]
reason = "invented test data"
```

| Key | Default | Meaning |
|---|---|---|
| `fail-on` | `"warning"` | Lowest severity that makes the run fail: `error`, `warning` or `note` (`never` only with `--fail-on`). |
| `exclude` | `[]` | Path globs to skip for the built-in rules, in the tree and in history (gitignore-style: `*`, `**`, `?`, `[...]`; no slash = any depth). With a denylist loaded these paths are still checked against it. |
| `default-excludes` | `true` | Skip `.git`, `node_modules`, virtualenvs and tool caches (each skipped folder is listed in the report). |
| `max-file-size` | `"32MiB"` | Larger files: media get a metadata-only check, anything else is reported as `scan.incomplete`. A smaller value is not applied while a denylist is loaded. |
| `max-archive-size` | `"1GiB"` | Largest archive to open, and total bytes read from one archive (a smaller value: as above). |
| `max-archive-depth` | `3` | Nesting depth for archives inside archives (a smaller value: as above). |
| `disable` | `[]` | Rule IDs or globs to turn off (never the denylist; coverage rules only with `--disable`). |
| `severity` | `{}` | Per-rule severity overrides, e.g. `{ "leak.email" = "note" }` (not for the denylist or coverage rules). |
| `[[allow]]` | none | Known-good findings: `rules` (globs), `paths` (globs), `line` (regex), `values` (exact matches), `reason`. |
| `loose-denylist` | `false` | Same as `--loose-denylist`. |
| `decode` | `true` | Decode base64/percent/entity/`\u` content before matching (`false` is not applied while a denylist is loaded). |
| `archives` | `true` | Look inside archives (as above). |
| `external-tools` | `true` | Use exiftool, ffprobe and pdfinfo when installed (as above). |
| `gitleaks` | `"auto"` | `auto` (run when installed), `always` (required) or `never`. |
| `heuristics.numeric-id-min-length` | `10` | Shortest digit run reported as an ID. |
| `heuristics.allowed-email-domains` | example/test domains, `users.noreply.github.com` | Domains (and subdomains) that are fine to publish. |
| `heuristics.allowed-emails` | `git@github.com`, `noreply@github.com`... | Exact addresses that are fine to publish. |
| `heuristics.allowed-numbers` | `[]` | Numbers that are not IDs. |
| `heuristics.allowed-hosts` | Docker/Kubernetes/GCP metadata names | Internal-looking hostnames that are fine. |
| `heuristics.allowed-ips` | public resolvers, common gateways | IP addresses that are fine. |
| `heuristics.allowed-home-users` | `runner`, `ubuntu`, `user`... | Usernames in home paths that are placeholders. |
| `heuristics.git-identity-domains` | `users.noreply.github.com` | Commit email domains that are fine to publish. |
| `heuristics.git-identity-emails` | `noreply@github.com` | Commit emails that are fine to publish. |
| `heuristics.entropy-threshold` | `4.3` | Shannon entropy (bits/char) for `secret.high-entropy-string`. |
| `heuristics.entropy-min-length` | `24` | Shortest token checked for entropy. |
| `heuristics.internal-patterns` | `[]` | Regexes (or `{pattern, label}` tables) for `leak.internal-name`. |

Lists extend the built-in defaults; they never replace them.

### Allowing known-good findings

Three mechanisms, from most to least specific:

1. **Denylist allow contexts** (only place where a denylist match can be allowed): indented
   `allow:` lines under the entry, as above.
2. **Inline pragma** for built-in rules: put `prepublish-audit:allow` on the line, optionally
   followed by rule IDs or globs (`# prepublish-audit:allow leak.email`). Pragmas never suppress
   denylist matches.
3. **Config `[[allow]]`** entries and `--allow RULE:GLOB` on the command line. Coverage rules
   (`scan.*`, `git.shallow-clone`) can only be allowed with `--allow`.

When a strong finding is allowed, weaker findings on the same text (for example an entropy warning
on an allowed token) are allowed with it. Suppressed findings are counted in every report.

### Command line

```text
prepublish-audit [scan] [PATH ...] [options]
prepublish-audit doctor [PATH ...] [--denylist FILE] [--config FILE] [--no-config] [--strict] [--color WHEN]
prepublish-audit rules [--format text|json|markdown]
prepublish-audit check-denylist [FILE ...]
prepublish-audit init [--force] [--no-denylist]
```

| Option | Meaning |
|---|---|
| `-d, --denylist FILE` | Private denylist (repeatable). |
| `--no-denylist` / `--require-denylist` | Skip the default denylist / fail when none is loaded. |
| `--loose-denylist` | Match plain entries with or without separators. |
| `--git-files` | Scan only what git would publish (tracked plus untracked, not ignored). |
| `--history` | Also scan the whole git history, identities and ref names. |
| `--exclude GLOB` / `--no-default-excludes` | Skip paths completely, denylist included / also scan dependency and cache folders. |
| `--max-file-size SIZE` | Largest file whose content is scanned, e.g. `64MiB`. |
| `--no-archives` / `--no-decode` / `--no-external-tools` | Turn off archive opening, decoding, or exiftool/ffprobe/pdfinfo. |
| `--gitleaks auto\|always\|never` | Run gitleaks too. |
| `-c, --config FILE` / `--no-config` | Use a specific config / ignore config files. |
| `--disable RULE` / `--allow RULE:GLOB` | Turn a rule off / allow it under a path glob. |
| `--fail-on LEVEL` | `error`, `warning` (default), `note` or `never`. |
| `-f, --format FORMAT` | `human` (default), `json`, `sarif` or `github`. |
| `-o, --output FILE` | Write the main report to a file. |
| `--json-output FILE` / `--sarif-output FILE` | Write extra JSON / SARIF reports. |
| `--sarif-real-paths` | Keep unmasked paths in SARIF so code scanning can link every alert to its file (private repositories only). |
| `--summary-markdown FILE` | Append a Markdown summary, e.g. to `$GITHUB_STEP_SUMMARY`. |
| `--reveal` | Show matched text and lines (local use only; refused in CI). |
| `--color auto\|always\|never` / `-q, --quiet` | Colour and verbosity of the human report. |
| `--strict` (`doctor`) | Also fail (exit 1) on items marked `!`: optional helpers, shallow clone, commit email, hooks. |
| `--version` / `-h, --help` | Version and help. |

`check-denylist` validates denylist files and prints counts and warnings, never entries
(exit 0 = valid, 1 = valid but empty, 2 = invalid). `init` writes a starter
`.prepublish-audit.toml` here and a 0600 denylist template in the default location.

`doctor` checks the setup for a scan of `PATH` (default `.`) without scanning it, read-only and
offline, and prints one line per check: `✓` passed, `✗` failed, `!` worth fixing, `-` skipped, with a
`fix:` line under every `✗` and `!`. It looks up the denylist like `scan` (`--denylist`,
`$PREPUBLISH_AUDIT_DENYLIST`, the default location) and checks that it loads, has entries, has mode
600, is not tracked by or exposed to git and is outside `PATH`; that the public config is valid; that
git is installed, the clone is not shallow, new commits use a no-reply address and configured
pre-commit hooks are installed; and which of gitleaks, exiftool, ffprobe and pdfinfo are found. It
never prints denylist entries or your commit email. Exit 0 = nothing failed, 1 = at least one `✗`
(with `--strict`, also any `!`). When nothing failed, its last line is the scan command to run next:
`--git-files --history` only for the top of a repository, and your own `--denylist`, `-c` and
`--no-config` options repeated, with `--require-denylist`.

When a command stops with an error (exit 2), usage errors included, a second line,
`prepublish-audit: fix: ...`, says what to do; [docs/troubleshooting.md](docs/troubleshooting.md)
lists every message. A `--denylist` that loads no entries (for example an empty pipe) is reported on
stderr; add `--require-denylist` to make it stop the run.

### Output and exit codes

| Exit code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on`. |
| `1` | Findings at or above `--fail-on`. |
| `2` | Usage, configuration or runtime error (bad flag, unreadable denylist, invalid regex, `--history` outside a repository, `--gitleaks always` without gitleaks...). |

Every report says what was scanned, what was excluded and how many findings were suppressed; the
human report ends with a "How to fix" line for each rule that fired. JSON
reports follow the `prepublish-audit/report/v1` layout (`summary`, `scanned`, `findings`, `skipped`,
`notes`); `scanned` includes `excluded`, `denylist_only` and `default_excluded_dirs` counts. Each
finding has a `rule_id`, `severity`, `message`, `path`, `line`, `column`, `end_column`, `origin`
(`file`, `archive`, `metadata`, `binary`, `history`, `history-path`, `commit`, `ref`...), `detail`,
`location` (for findings without a path, such as `commit 1a2b3c4d5e6f`), `commit`, `blob`,
`match_length` and a stable `fingerprint` that is never derived from the matched text.

## Examples

**GitHub Actions** (full file with SARIF upload: [examples/github-workflow.yml](examples/github-workflow.yml)):

```yaml
jobs:
  denylist-audit:
    if: github.event_name != 'pull_request'   # pull requests can change the workflow and print secrets
    runs-on: ubuntu-latest
    environment: prepublish-audit             # required reviewers + the PREPUBLISH_DENYLIST secret
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      - uses: deegitech/prepublish-audit@v0.1.0   # pin to the release commit SHA, see below
        with:
          denylist: ${{ secrets.PREPUBLISH_DENYLIST }}
          history: "true"
```

Run the built-in rules on pull requests in a second job without the `denylist` input; the example
file shows both jobs. Anyone who can push a branch can make a pull-request workflow print its
secrets, so keep the denylist in an environment with required reviewers, give each repository a
list with only what it needs, and rely on the local pre-push hook as the gate before code leaves a
machine. Pin the action to the full commit SHA of the release
(`git ls-remote https://github.com/deegitech/prepublish-audit refs/tags/v0.1.0`) and keep the tag
as a comment: `uses: deegitech/prepublish-audit@<sha> # v0.1.0`.

Action inputs: `path`, `denylist`, `require-denylist`, `history`, `git-files`, `fail-on`,
`sarif-file`, `json-file`, `config`, `gitleaks`, `args`. Outputs: `exit-code`, `findings`,
`sarif-file`. Empty `fail-on` and `gitleaks` inputs leave those settings to the repository config.
The action runs from source with the runner's Python (3.10+), prints findings as annotations and
writes a step summary.

**pre-commit** ([examples/pre-commit-config.yaml](examples/pre-commit-config.yaml)):

```yaml
repos:
  - repo: https://github.com/deegitech/prepublish-audit
    rev: v0.1.0
    hooks:
      - id: prepublish-audit            # staged files on every commit
      - id: prepublish-audit-history    # whole repository and history before every push
        args: [--require-denylist]      # stop, instead of passing, when no denylist is found
```

Hooks find the denylist in the default file or through `$PREPUBLISH_AUDIT_DENYLIST`, not through
your shell functions; [docs/setup.md](docs/setup.md#step-7-run-it-automatically-once-per-repository)
has a hook for a denylist kept in the macOS Keychain.

**A site build or a bundle**, after the build step:

```bash
npm run build
prepublish-audit scan --fail-on warning dist/        # catches source maps with home paths, IDs in bundles
prepublish-audit scan --history --git-files .        # and the repository itself
prepublish-audit scan build/MyApp.ipa                # opens the archive and checks every member
```

**Machine-readable results**:

```bash
prepublish-audit scan -f json -o report.json . ; jq '.summary' report.json
prepublish-audit scan -f sarif -o report.sarif --history .
```

More: [examples/denylist.example.txt](examples/denylist.example.txt),
[examples/denylist.example.toml](examples/denylist.example.toml),
[examples/prepublish-audit.toml](examples/prepublish-audit.toml).

## Security model

prepublish-audit handles the most sensitive list your organisation has, so its own behaviour is
part of the product:

- **The denylist stays private.** Entries are never printed: not in reports, not in annotations,
  not in error messages (invalid entries are reported by line number, unknown keys of a TOML or JSON
  denylist by count, and regular-expression errors without the pattern). Findings show the entry's
  label. Every text in a report that can come from scanned content (paths, messages, metadata field
  names, details, locations and notes) is masked where it contains an entry (`docs/***-plan.md`),
  in human, JSON, SARIF, GitHub and Markdown output. The tool reports a denylist that sits inside
  the scanned tree as an error and warns when the file is readable by other users.
- **Redacted by default.** Matched text and source lines appear only with `--reveal`. `--reveal`
  is refused when a CI environment is detected (GitHub Actions, GitLab, Jenkins, TeamCity, AWS
  CodeBuild, Drone and anything that sets `CI`; override: `PREPUBLISH_AUDIT_ALLOW_REVEAL=1`). A
  revealed report may not be written inside a scanned tree, and report files written with
  `--reveal` get mode `0600`. Fingerprints hash the rule and the masked location, never the secret,
  so a short value such as four card digits cannot be recovered from them, not even when it is part
  of a file name.
- **SARIF paths are masked too.** A path that contains a denylist entry would otherwise end up in
  code scanning, where alerts outlive a later history rewrite. Such alerts cannot link to their
  file; `--sarif-real-paths` keeps the real paths for private repositories.
- **The public config cannot weaken the denylist.** It is part of the repository, so anyone who
  can open a pull request can edit it. It can tune and exclude the built-in rules, but excluded
  paths are still checked against a loaded denylist, values that would shrink what is read are not
  applied, coverage rules and `fail-on = "never"` are command-line only, and content the denylist
  could not check fails the run (see [The public config](#the-public-config)).
- **The GitHub Action keeps the secret off command lines.** It receives the denylist as an
  environment variable, writes it to a file in a fresh `0700` directory under `RUNNER_TEMP` with
  `umask 077`, passes the path, and deletes the directory when the step ends. Inputs are passed as
  environment variables, never interpolated into shell code. A secret given to a pull-request
  workflow is readable by whoever can push a branch, so the examples run the denylist job only
  outside pull requests and in an environment with required reviewers.
- **Read-only and offline.** The scanner never modifies files, never extracts archives to disk and
  never opens network connections. Git runs with read-only commands, lazy fetching for partial
  clones disabled (`GIT_NO_LAZY_FETCH`), fsmonitor hooks off and no pager. External tools get
  absolute paths (and ffprobe a `file:` URL), run without a shell and with timeouts; gitleaks runs
  with `--redact` and writes its report to a private temporary directory that is removed afterwards.
- **Hostile input is bounded.** Archives have size, member, depth and compression-ratio limits;
  oversized or encrypted content, unsupported containers and unreadable files become
  `scan.incomplete` findings instead of silent skips. The metadata parsers (XMP, PDF streams,
  Office XML, TIFF, QuickTime) move forward through their input with a cursor and copy only what
  they read, and the tests check that crafted 2 MB inputs finish in under two seconds. Built-in
  patterns are written to avoid catastrophic backtracking and were profiled on multi-megabyte
  minified and single-line files. Printable strings in binaries are checked in 4 MiB chunks, so a
  large binary is covered to its end.
- **Fails closed.** Shallow clones are findings, unknown config keys are errors, skipped default
  folders (`node_modules`, virtualenvs...) and excluded paths are counted in every report, a
  run that scanned no files says so, and so does a path that `--git-files` left unread.
- **Small supply chain.** No runtime dependencies; CI actions are pinned to commit SHAs, gitleaks is
  downloaded by version and verified against a pinned SHA-256, and Dependabot and CodeQL watch the
  repository.

## Limitations

prepublish-audit lowers the risk of an accidental leak; it does not make one impossible.

- **Heuristics are heuristics.** Expect some false positives (IDs, IPs, entropy) and missed values
  with unusual shapes. The private denylist is the reliable part: put every value you know about in it.
- **Not built to stop a determined insider.** Deliberate obfuscation (splitting strings, homoglyphs,
  custom encodings, encryption) is out of scope.
- **No OCR.** Text inside images, scanned PDFs or videos is not read. PDF page text is extracted on a
  best-effort basis; fonts with custom encodings may hide text.
- **Containers it cannot open** (rar, 7z, dmg, iso and similar) are reported as `scan.incomplete`.
  External metadata tools only run on files on disk, not on archive members or history blobs, which
  use the built-in parsers.
- **Git:** only objects reachable from refs are scanned (unreachable objects are not pushed). Git LFS
  files are seen as pointers; submodules are not followed. Clean/smudge filters can make one issue
  appear for both the working tree and history.
- **Binary strings** are taken from code, databases, fonts and similar files; in images, audio and
  video only the metadata regions are read, not the compressed pixel or sample data.
- **Encoded values:** base64 is decoded only for tokens of 16 or more characters, so a value of up
  to 11 bytes that is base64-encoded on its own is not found. Put such values in the denylist in
  their encoded form as well.
- **SARIF with `--sarif-real-paths`** contains real file paths, deleted history paths included. A
  path that contains a denylist entry then shows it in code scanning; use the option only for
  private repositories.
- **History reports** include git blob and commit IDs. They are public anyway once the repository
  is pushed, but a blob ID identifies the exact content of a file, so a tiny file whose whole
  content is guessable could be identified from it.
- **Platforms:** CI runs on Linux and macOS. Windows should work but is not tested in CI yet; the
  GitHub Action needs a bash shell and `python3`.

## FAQ

**Why not just use gitleaks or TruffleHog?**
Use them too; prepublish-audit even runs gitleaks for you when it is installed. Secret scanners know
credential formats. prepublish-audit adds what only you know (the denylist), the non-credential
leaks above, metadata in media and documents, and identities and ref names in git history.

**Where should the denylist live?**
On the machines that run the scan, outside every repository: `~/.config/prepublish-audit/` locally,
an environment secret with required reviewers in CI. Share it with the people who publish, the way
you share other secrets, and give CI only the entries that each repository needs.

**The report shows `***` in a path. Why?**
The path contains a denylist entry, and printing it would leak the entry into logs. Run with
`--reveal` on your own machine to see the real path.

**It found something in history. I deleted the file; why does it still fail?**
The old blob is still in the repository and would be pushed with it. Publish a fresh single-commit
history or rewrite the history; see [docs/release-checklist.md](docs/release-checklist.md).

**Why does a shallow clone fail the history scan?**
Commits that were not fetched were not checked. In GitHub Actions, check out with `fetch-depth: 0`.

**Something does not work. Where do I start?**
Run `prepublish-audit doctor`; it checks the setup and prints the fix for each problem. Every error
message is in [docs/troubleshooting.md](docs/troubleshooting.md).

**Does it send anything anywhere?**
No. It reads files and runs local tools (git and, if present, exiftool, ffprobe, pdfinfo, gitleaks).

**How fast is it?**
It reads every byte it scans, so time grows with the size of the tree and the history. Observed in
October 2026 on a laptop: the CPython 3.14 standard library (2,513 files, 54 MB, built-in rules, no
history) took about 17 seconds. A history scan reads each distinct old version of a file once, so it
costs about as much as scanning those versions as files.

## About

prepublish-audit is built and maintained by **DEEGITECH Teknoloji ve Yazılım Ltd. Şti.**, a small
software and game studio from Türkiye. We wrote it while shipping our iOS game
[Wide Molly Hooked](https://widemolly.com) ([App Store](https://apps.apple.com/app/id6813081261)), <!-- prepublish-audit:allow leak.numeric-id -->
and it is the gate every one of our open-source releases has to pass.

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md). Please report
vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 DEEGITECH Teknoloji ve Yazılım Ltd. Şti.
