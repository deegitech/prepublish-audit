# Contributing

Thanks for helping make prepublish-audit better. Bug reports, new rules, false-positive fixes and
documentation improvements are all welcome.

## Ground rules

- **No real data, ever.** Issues, pull requests, tests, fixtures and commit messages must not contain
  real secrets, IDs, emails, names, hostnames or local paths. Use invented values with the same shape.
- **Credential-shaped test values are assembled at runtime** from fragments (see `tests/helpers.py`),
  so that no secret scanner, including this one and gitleaks, sees a complete credential in the source.
- **Reports never print matched text** without `--reveal`. Any change that could print a denylist entry,
  a secret or a source line by default is a security bug.
- **Standard library only** at runtime. An optional extra is acceptable only when there is no reasonable
  stdlib alternative (today the only one is `tomli`, for TOML on Python 3.10).
- Code, comments and docs are in English. Python 3.10 is the oldest supported version.

## Development setup

```bash
git clone https://github.com/deegitech/prepublish-audit.git
cd prepublish-audit
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Running the tests

```bash
python -m pytest -q                          # the usual way
python -m unittest discover -s tests -t .    # standard library only, no pytest needed
```

The tests are fully offline. Git history fixtures are created in temporary directories, and
exiftool, ffprobe, pdfinfo and gitleaks are replaced by small fake executables. Tests that need a
POSIX shell or git skip themselves when those are missing.

Before you open a pull request, also run the tool on itself:

```bash
python -m prepublish_audit scan --history .
```

## Adding or changing a rule

1. Add or edit the rule in `src/prepublish_audit/rules.py`. Every rule needs a stable ID
   (`secret.*`, `leak.*`, `metadata.*`...), a title, a description, a remediation and, for content
   rules, a validator that throws away placeholders.
2. Add tests that show both sides: values that must be found and look-alikes that must not be.
3. Regenerate the rule reference: `prepublish-audit rules --format markdown > docs/rules.md`
   (a test fails when it is out of date).
4. Add a line to `CHANGELOG.md` under "Unreleased".

Keep rules fast: they run over every file, every history blob and every metadata value. Prefer a
cheap regular expression plus a validator over a clever regular expression, give the rule keywords
when it has a fixed prefix, and avoid nested quantifiers that can backtrack.

## Adding or changing an error message

Every error that stops a run is followed by a one-line fix. When you add or reword an error, add its
pattern and fix to `src/prepublish_audit/hints.py` (fixed text only: never echo the message, a path
or a denylist entry) and a row to `docs/troubleshooting.md`; `tests/test_hints.py` checks both. New
setup checks belong in `src/prepublish_audit/doctor.py`, with a `fix:` for every failure.

## Commit messages and pull requests

- One topic per pull request; explain the "why" in the description.
- Use the pull request template checklist.
- Commit with your GitHub no-reply address (`<id>+<login>@users.noreply.github.com`, shown under
  Settings > Emails), not a personal one: public history keeps it forever. The self-audit reports
  other addresses as `git.author-identity` notes.
- By contributing you agree that your contribution is licensed under the MIT License of this project.

## Reporting security problems

Please do not open public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
