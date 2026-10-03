## What and why

<!-- What does this change, and which problem does it solve? Link the issue if there is one. -->

## Checklist

- [ ] Tests cover the change (`python -m pytest -q` passes locally).
- [ ] New or changed rules are documented (`prepublish-audit rules --format markdown > docs/rules.md`).
- [ ] `CHANGELOG.md` has an entry under "Unreleased".
- [ ] No real secrets, IDs, emails, names or internal paths anywhere in the diff, tests or commit messages
      (test values that look like credentials are assembled at runtime; see `tests/helpers.py`).
- [ ] Reports still never print matched text or denylist entries without `--reveal`.
