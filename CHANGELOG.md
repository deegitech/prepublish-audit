# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-04

First public release.

### Added

- `scan` command for files, directories, archives and bundles, with `--git-files` to cover exactly what
  git would publish.
- Private denylist in text, TOML or JSON form: case-insensitive literals, regular expressions, `word:`
  and `loose:` entries, labels, and allow contexts by path glob, line regex or Markdown section.
  Entries are never printed; the scanner reports a denylist found inside the scanned tree as an error.
- Built-in secret rules: private keys, AWS, GitHub, GitLab, Google API/OAuth, Meta, Slack, Stripe, npm,
  PyPI, OpenAI and Anthropic keys, JWTs, passwords in URLs, Authorization headers, hard-coded
  credentials and high-entropy strings.
- Leak heuristics: home-directory and mounted-volume paths, emails, long numeric IDs, private and public
  IP addresses, internal hostnames, links to private workspaces and consoles, confidentiality markings,
  phone and payment-card numbers, cloud account and resource IDs, ad and analytics account IDs, Apple
  developer IDs, hard-coded account identifiers and configurable internal-name patterns.
- Sensitive file types (.p8, .p12, keystores, SSH keys, Terraform state, .env...) and OS/IDE metadata
  files (.DS_Store, resource forks, xcuserdata...).
- Decoding of base64 (tokens of 16+ characters), percent-encoded, HTML-entity and `\u`-escaped text
  before matching.
- Binary string extraction (ASCII and UTF-16, in 4 MiB chunks to the end of the file),
  zip/tar/gzip/bzip2/xz archives with nesting, size and decompression-bomb limits.
- Metadata: EXIF (author, owner, host computer, serials, GPS), XMP, PNG text chunks, WebP, RIFF INFO,
  QuickTime/MP4 user data and ISO 6709 locations, PDF info and best-effort page text, every
  Office/ODF document property, markup attributes such as alt text, and comment authors; metadata
  field names are checked too; optional exiftool, ffprobe and pdfinfo.
- `--history`: every reachable blob, every path that ever existed (old names of renamed files
  included), commit and tag messages, author, committer and tagger identities, and ref names;
  shallow clones are reported. Exclude globs apply to history as well.
- Optional gitleaks run, merged and de-duplicated.
- Reports: human, JSON, SARIF 2.1.0, GitHub annotations and a Markdown step summary; exit codes 0/1/2.
  Excluded paths and skipped default folders are counted.
- `rules`, `check-denylist` and `init` commands (`init` writes a JSON config on Python 3.10 without
  a TOML parser).
- `doctor` command: checks the setup for a scan without scanning (Python and TOML support; the
  denylist is found, valid, not empty, mode 600, not tracked by or exposed to git and outside the
  scanned path; a path that contains the home folder; the public config; git, shallow clones, the
  commit email and configured pre-commit hooks; gitleaks, exiftool, ffprobe and pdfinfo). It prints
  one line per check with the fix under every problem, exits 1 when something failed (`--strict`:
  also on items to review), never prints denylist entries or the commit email, and ends with the
  scan command to run next (`--git-files --history` only for the top of a work tree; its own
  `--denylist`, `-c` and `--no-config` repeated, with `--require-denylist`).
- Every error that stops a run, usage errors included, is followed by a one-line fix
  (`prepublish-audit: fix: ...`); a gitleaks failure note carries its fix too. Messages link to the
  documentation of the installed version.
- The human report ends with a "How to fix" line for each rule that fired.
- Composite GitHub Action, pre-commit hooks, release checklist and examples.
- `docs/setup.md` (setup from zero, including the macOS Keychain, GitHub environment secrets, AWS SSM
  and the GitHub settings before going public) and `docs/troubleshooting.md` (every message, its
  meaning and its fix).

### Security

- The public config is treated as untrusted: with a denylist loaded, paths it excludes are still
  checked against the denylist, values that would shrink what is read are not applied, the coverage
  rules (`scan.*`, `config.*`, `git.shallow-clone`) and `fail-on = "never"` are command-line only,
  and content the denylist could not check fails the run even with `fail-on = "error"`.
- Reports mask denylist entries in paths, messages, metadata field names, details, locations and
  notes in every format, SARIF included (`--sarif-real-paths` opts out); fingerprints hash masked
  paths; reports written with `--reveal` get mode 0600; control characters in file names are
  escaped in human, GitHub and Markdown output.
- Errors about TOML/JSON denylists and invalid regular expressions never quote denylist content.
- Case-insensitive literals also match Turkish dotted and dotless I.
- Metadata parsers do linear, bounded work on crafted input.
- `--reveal` is also refused on Jenkins, TeamCity, AWS CodeBuild, Drone, Bitbucket, CircleCI and
  Travis CI.
- A `--denylist` that loads no entries (an empty file, or a pipe whose command failed) is reported on
  stderr, also with `--quiet`, and `check-denylist` reports it as `EMPTY` (exit 1). With
  `require-denylist: true`, the GitHub Action also fails on a secret that holds no entries.
- A path that `--git-files` left unread (a gitignored build folder) is reported as a warning instead
  of "No secrets or internal information found".
