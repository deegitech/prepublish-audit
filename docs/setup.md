# Setup from zero (about 15 minutes)

This guide takes you from nothing to a first scan you can trust: install the tool, build the private
denylist, store it safely, check everything with `prepublish-audit doctor`, and run the first scan.
Steps 1 to 6 take about 15 minutes. Steps 7 and 8 (CI, hooks and the GitHub settings before a
repository goes public) are done once per repository.

Console menus are renamed often. Click paths below give the likely labels and older variants; the
names on your screen may differ.

When something fails, the tool prints the fix under the error (`prepublish-audit: fix: ...`), and
[troubleshooting.md](troubleshooting.md) lists every message with its meaning and fix.

## Contents

1. [What you need](#what-you-need)
2. [Step 1. Install](#step-1-install-2-minutes)
3. [Step 2. Create the denylist and the public config](#step-2-create-the-denylist-and-the-public-config-1-minute)
4. [Step 3. Fill the denylist](#step-3-fill-the-denylist-5-to-10-minutes)
5. [Step 4. Store it safely](#step-4-store-it-safely-2-minutes)
6. [Step 5. Check the setup with doctor](#step-5-check-the-setup-with-doctor-1-minute)
7. [Step 6. Run the first scan](#step-6-run-the-first-scan-2-minutes)
8. [Step 7. Run it automatically](#step-7-run-it-automatically-once-per-repository)
9. [Step 8. Before the repository goes public](#step-8-before-the-repository-goes-public-once-per-repository)
10. [Expiry and renewal](#expiry-and-renewal)
11. [Common mistakes](#common-mistakes)

## What you need

| What | Needed for | How to check or get it |
|---|---|---|
| Python 3.10 or newer (3.11+ reads TOML without extras) | everything | `python3 --version`; macOS: `brew install python` |
| pipx (recommended) | installing the tool in its own environment | macOS: `brew install pipx && pipx ensurepath`; Debian/Ubuntu: `sudo apt-get install pipx` |
| git | installing from GitHub (step 1), `--git-files`, `--history`, the hooks | `git --version`; macOS: `xcode-select --install` |
| gitleaks, exiftool, ffprobe, pdfinfo (all optional) | a second secret scanner, richer image/PDF/video metadata | step 1 |
| GitHub CLI `gh` (optional) | storing the CI secret from a file (step 4D), organisation settings (step 8) | `gh --version`; macOS: `brew install gh`, then `gh auth login` |
| AWS CLI (optional) | servers that read the denylist from Parameter Store (step 4E) | `aws --version`; macOS: `brew install awscli` |
| A GitHub account with admin rights on the repository (you can see its **Settings** tab) | steps 7 and 8 only | organisation-wide settings need an organisation owner |

prepublish-audit itself needs no account, no API key and no network access: it runs offline and only
reads files.

**GitHub plan notes** (at the time of writing; plans change, so check GitHub's documentation):

- Secret scanning, push protection and CodeQL code scanning are free on **public** repositories. On
  private repositories they need the paid GitHub Secret Protection and GitHub Code Security products
  (formerly part of GitHub Advanced Security).
- Environment secrets in a **private** repository need GitHub Pro, Team or Enterprise. Required
  reviewers on an environment of a private repository need GitHub Enterprise; on public repositories
  every plan has them.
- Branch protection and rulesets on a private repository need GitHub Pro, Team or Enterprise.
- Dependabot alerts and security updates, and private vulnerability reporting on public
  repositories, are available on every plan.

This is one more reason to run prepublish-audit locally: it protects a private repository before
GitHub's own scanners are switched on.

## Step 1. Install (2 minutes)

```bash
pipx install "git+https://github.com/deegitech/prepublish-audit@v0.1.0"
prepublish-audit --version          # prepublish-audit 0.1.0
```

On Python 3.10, add TOML support (Python 3.11 and newer have it built in):

```bash
pipx inject prepublish-audit tomli
```

Optional helpers, used automatically when they are on `PATH`:

```bash
# macOS (Homebrew)
brew install gitleaks exiftool ffmpeg poppler

# Debian/Ubuntu (gitleaks: download a release binary from github.com/gitleaks/gitleaks/releases)
sudo apt-get install libimage-exiftool-perl ffmpeg poppler-utils
```

If the shell says `prepublish-audit: command not found`, run `pipx ensurepath` and open a new
terminal.

## Step 2. Create the denylist and the public config (1 minute)

Run `init` inside the repository you are going to publish:

```bash
cd ~/src/myrepo
prepublish-audit init
```

```text
wrote .prepublish-audit.toml (public settings; commit it)
created a private denylist template at ~/.config/prepublish-audit/denylist.txt (mode 600, outside the repository)
```

You now have two files with opposite rules:

| File | Holds | Rule |
|---|---|---|
| `.prepublish-audit.toml` in the repository | which built-in findings fail the build, excludes, known-good findings | public: commit it, never put a private value in it |
| `~/.config/prepublish-audit/denylist.txt` (folder mode 700, file mode 600) | the strings that must never leave | private: never inside a repository, never committed |

On Python 3.10 without `tomli`, `init` writes `.prepublish-audit.json` instead.

## Step 3. Fill the denylist (5 to 10 minutes)

The denylist is the reliable part of the tool: the heuristics guess, the denylist knows. Build it
from your real configuration files, consoles and logs. Typical entries:

- account, customer, campaign, app, page and ad-account IDs (`1234567890`, `act_123456789012345`);
- bundle IDs and package names that reveal internal names (`com.example.mygame`);
- people's names, user names (also the one in your home folder path), personal and internal email
  addresses (`you@example.com`);
- hostnames, internal domains, bucket and database names, IP addresses;
- product codenames, unreleased feature names, partner and customer names;
- the last digits of company cards (`word:4821`), phone numbers.

Open the file in your editor (`$EDITOR ~/.config/prepublish-audit/denylist.txt`) and add one entry per
line. Everything below is invented; use your own values:

```text
# ~/.config/prepublish-audit/denylist.txt  (mode 600, never inside a repository)
Example Studio Internal
  label: company internal name
1234567890
  label: ad account
act_123456789012345
  label: Meta ad account
com.example.mygame
  label: bundle ID
you@example.com
  label: personal email
word:4821
  label: card digits
re:\bheron-(?:prod|staging)-[a-z0-9-]+\b
  label: service names
loose:project heron
  label: codename
```

- A plain line is matched case-insensitively anywhere. `word:` must not touch other letters or
  digits, `re:` is a Python regular expression, `loose:` also matches `project-heron`,
  `project_heron` and `ProjectHeron`.
- An indented `label:` is what reports show instead of the entry. Describe the entry; never repeat it.
- A value that may appear in a few places (your company name in `LICENSE`, for example) gets
  indented `allow:` lines: `allow: LICENSE`, `allow: README.md section=^About`.

**Find candidates you forgot.** Run the built-in heuristics over private material you keep outside
the repository (exported configs, a notes folder) and read the matches on your own screen:

```bash
prepublish-audit scan --no-denylist --gitleaks never --reveal ~/work/private-notes | less
```

The leak heuristics list IDs, email addresses, hosts and paths they recognise; copy the ones that
must never be published into the denylist. Do not save this output inside a repository.

Validate the file. It prints counts, never entries:

```bash
prepublish-audit check-denylist
```

```text
OK: 8 entries in 1 file(s) (5 literal, 1 loose, 1 regex, 1 word); 8 labelled, 0 with allow contexts.
```

## Step 4. Store it safely (2 minutes)

Pick one place per machine. prepublish-audit reads the denylist from, first match wins:
`--denylist FILE` (repeatable), then `$PREPUBLISH_AUDIT_DENYLIST`, then
`~/.config/prepublish-audit/denylist.{txt,toml,json}`.

### A. A private file (default for laptops and workstations)

```bash
chmod 700 ~/.config/prepublish-audit
chmod 600 ~/.config/prepublish-audit/denylist.txt
ls -l ~/.config/prepublish-audit/denylist.txt      # -rw-------
```

Keep it out of every git working tree. If your `~/.config` is a dotfiles repository, add
`prepublish-audit/` to its `.gitignore`; `doctor` checks this for you.

### B. macOS Keychain (no plaintext file on disk)

The Keychain holds the denylist base64-encoded, because `security` is made for one-line passwords
and base64 keeps line breaks and non-ASCII letters (ş, ğ, ı...) intact.

1. Store the file you filled in step 3. It is one command; the `\` continues the line:

   ```bash
   security add-generic-password -U -a "$USER" -s prepublish-audit-denylist \
     -w "$(base64 < ~/.config/prepublish-audit/denylist.txt)"
   ```

2. Add a helper to `~/.zshrc` (bash: `~/.bashrc`), then **open a new terminal** or run
   `source ~/.zshrc`, so that the helper exists:

   ```bash
   pa_denylist() { security find-generic-password -a "$USER" -s prepublish-audit-denylist -w | base64 --decode; }
   ```

3. Read it back. The count must match the one `check-denylist` printed in step 3:

   ```bash
   prepublish-audit check-denylist <(pa_denylist)
   ```

4. Delete the plaintext file and any editor backups of it (`denylist.txt~`, `.denylist.txt.swp`).
   Otherwise every plain `scan` and every hook keeps reading the old file, which goes stale as soon as
   you update the Keychain item:

   ```bash
   rm ~/.config/prepublish-audit/denylist.txt
   ```

5. From now on, pass it with `--require-denylist`, so that an empty pipe stops the scan instead of
   passing it:

   ```bash
   prepublish-audit doctor --denylist <(pa_denylist)
   prepublish-audit scan --require-denylist --denylist <(pa_denylist) --git-files --history .
   ```

Gotchas:

- **Never leave `-w` without a value.** `security` then prompts for the password, and, observed
  (Oct 2026), the prompt silently keeps only the first 128 characters. A denylist is longer, so always
  use the `-w "$(...)"` form.
- **An empty pipe looks like a clean scan.** When the helper is not loaded in this terminal, the item
  name is wrong, or the keychain is locked (for example in an SSH session:
  `User interaction is not allowed.`), `<(pa_denylist)` is empty. Without `--require-denylist` the scan
  then runs the built-in rules only and can print `PASSED`; it warns on stderr, and `check-denylist`
  prints `EMPTY`.
- The value is on the `security` command line for a moment, where other users of the same Mac could
  see it with `ps`. On a shared Mac, use option A.
- **Hooks and CI cannot call your shell function.** Step 7 shows a hook that reads the Keychain
  itself; CI uses options D and E.
- **To update the list**, restore it to a private file, edit it, then repeat steps 1, 3 and 4
  (`-U` replaces the item):

  ```bash
  (umask 077; pa_denylist > ~/.config/prepublish-audit/denylist.txt)
  $EDITOR ~/.config/prepublish-audit/denylist.txt
  ```

  To remove the item: `security delete-generic-password -a "$USER" -s prepublish-audit-denylist`.
- **From the clipboard instead of a file** (for example when the list lives in a password manager):
  paste `security add-generic-password -U -a "$USER" -s prepublish-audit-denylist -w "$(pbpaste | base64)"`
  into Terminal without pressing Enter, copy the list, then press Enter: `$(pbpaste)` reads the
  clipboard only then. Clipboard managers keep a history and Universal Clipboard sends the clipboard
  to your other Apple devices; `pbcopy </dev/null` clears neither. `pbpaste` also needs a UTF-8 locale
  for letters such as ş or ı (`LANG=en_US.UTF-8`, see `man pbcopy`). Paste one line at a time:
  pasted together with `pbcopy </dev/null`, the store command runs while the clipboard still holds
  the command text, and that text is stored as your denylist.

### C. An environment variable (a path, never the content)

```bash
export PREPUBLISH_AUDIT_DENYLIST="$HOME/secure/denylists/team.txt"                          # one file
export PREPUBLISH_AUDIT_DENYLIST="$HOME/secure/denylists/team.txt:$HOME/secure/denylists/repo.txt"  # several
```

Separate several files with `:` (`;` on Windows). Each file still needs mode 600.

### D. CI: a GitHub environment secret

Give CI a small denylist made for the repository, never your organisation-wide list, and only to
jobs that do not run on pull requests (anyone who can push a branch can change a pull request's
workflow and print its secrets).

1. Repository → **Settings** → **Environments** → **New environment**. Name it `prepublish-audit`
   and click **Configure environment**.
2. Under **Deployment protection rules**, tick **Required reviewers**, add yourself or a team, and
   click **Save protection rules** (private repositories: see the plan notes above).
3. Under **Environment secrets**, click **Add environment secret** (names may differ). Name:
   `PREPUBLISH_DENYLIST`. Value: the content of the repository's denylist. Click **Add secret**.

   Without the clipboard, from a terminal with the GitHub CLI inside the repository. First create
   `~/.config/prepublish-audit/ci/myrepo.txt` (mode 600) with only the entries this repository needs:

   ```bash
   mkdir -p -m 700 ~/.config/prepublish-audit/ci
   touch ~/.config/prepublish-audit/ci/myrepo.txt && chmod 600 ~/.config/prepublish-audit/ci/myrepo.txt
   $EDITOR ~/.config/prepublish-audit/ci/myrepo.txt
   prepublish-audit check-denylist ~/.config/prepublish-audit/ci/myrepo.txt
   gh secret set PREPUBLISH_DENYLIST --env prepublish-audit < ~/.config/prepublish-audit/ci/myrepo.txt
   ```

4. Add the workflow from step 7. Its denylist job names `environment: prepublish-audit`; the action
   writes the secret to a 0600 file in a fresh 0700 folder under `RUNNER_TEMP`, passes the path and
   deletes the folder when the step ends.

A secret holds up to 48 KB. Secrets never reach pull requests from forks, and environment secrets
reach only jobs that name the environment.

### E. Servers and self-hosted runners: AWS Systems Manager Parameter Store

Store the denylist once as a SecureString from an admin machine (AWS console path: **Systems
Manager** → **Parameter Store** → **Create parameter** → Type **SecureString**; names may differ):

```bash
aws ssm put-parameter --name /prepublish-audit/denylist --type SecureString \
  --value "file://$HOME/.config/prepublish-audit/denylist.txt" --overwrite
```

Standard parameters hold up to 4 KB. A larger list needs `--tier Advanced` (8 KB, billed per
parameter), or several parameters loaded as several files.

In the job script on the server, fetch it at the start into memory-backed storage that only the job
user can read, and remove it at the end:

```bash
umask 077
dir="$(mktemp -d /dev/shm/prepublish-audit.XXXXXX)"   # /dev/shm is tmpfs on most Linux systems
trap 'rm -rf "$dir"' EXIT
aws ssm get-parameter --name /prepublish-audit/denylist --with-decryption \
  --query Parameter.Value --output text > "$dir/denylist.txt"
export PREPUBLISH_AUDIT_DENYLIST="$dir/denylist.txt"
prepublish-audit doctor && prepublish-audit scan --require-denylist --git-files --history .
```

The instance or job role needs `ssm:GetParameter` on that parameter, and `kms:Decrypt` if you
encrypt it with your own KMS key instead of the default `aws/ssm` key. A long-running service can
fetch it at boot into a systemd `RuntimeDirectory=` (tmpfs under `/run`) with
`RuntimeDirectoryMode=0700`.

## Step 5. Check the setup with doctor (1 minute)

```bash
prepublish-audit doctor              # or: prepublish-audit doctor PATH-YOU-WILL-SCAN
```

Sample output for a finished setup, after steps 7 and 8 (your versions will differ). Right after
step 4 you see `- No prepublish-audit hook in .pre-commit-config.yaml` instead of the two hook lines,
and perhaps `! New commits here would carry a personal email address`; steps 7 and 8 fix both. With
the Keychain (step 4B), run `prepublish-audit doctor --denylist <(pa_denylist)`.

```text
prepublish-audit doctor 0.1.0 (read-only, offline)

✓ Python 3.14.7, prepublish-audit 0.1.0 (TOML support)
✓ Denylist found: ~/.config/prepublish-audit/denylist.txt (default location)
✓ Denylist is valid: 8 entries (5 literal, 1 loose, 1 regex, 1 word), 8 labelled
✓ Denylist is private (mode 600)
✓ Denylist is not inside a git working tree
✓ Denylist is outside the path(s) to scan: .
✓ Public config: .prepublish-audit.toml
✓ git 2.50.1
✓ Full git history available (not a shallow clone)
✓ New commits here use a no-reply email address
✓ pre-commit hook installed (pre-commit)
✓ pre-push hook installed (pre-commit)
✓ gitleaks 8.30.1
! exiftool not found (optional: more image, PDF and video metadata)
    fix: brew install exiftool; Debian/Ubuntu: sudo apt-get install libimage-exiftool-perl
✓ ffprobe 8.1.2
! pdfinfo not found (optional: PDF metadata when exiftool is missing)
    fix: brew install poppler; Debian/Ubuntu: sudo apt-get install poppler-utils

14 passed, 0 failed, 2 to review, 0 skipped
Ready. Next: prepublish-audit scan --git-files --history .
```

| Mark | Meaning | Exit code |
|---|---|---|
| `✓` | passed | |
| `✗` | failed: a scan would not protect you, or would stop with an error. A `fix:` line follows. | 1 |
| `!` | worth fixing, but a scan still works (optional helpers, shallow clone, personal commit email, a hook that is configured but not installed, a path that contains your home folder). A `fix:` line follows. | 0, or 1 with `--strict` |
| `-` | skipped or not applicable | |

The checks, in order: Python and TOML support; the denylist is found, valid, not empty, private
(mode 600), not tracked by or exposed to git, and outside the path you will scan; the public config
is valid; git is installed, the history is complete, new commits use a no-reply address, configured
hooks are installed; gitleaks, exiftool, ffprobe and pdfinfo are found. It is read-only and offline,
and it never prints denylist entries or your commit email address: paths are shown relative to your
home folder and masked with the denylist. When a terminal cannot show `✓` and `✗`, it prints `[ok]`
and `[FAIL]` instead.

When nothing failed, the last line is the scan to run next. It has `--git-files --history` only when
the path is the top of a git repository (a gitignored build folder such as `dist/` has nothing for
`--git-files` to read), and it repeats your own `--denylist`, `-c` and `--no-config` options with
`--require-denylist`. Run in your home folder, the doctor ends with `Do not scan there` instead.

## Step 6. Run the first scan (2 minutes)

There is no write mode: `scan` never changes a file, so every run is a dry run. Start with what git
would publish plus the whole history:

```bash
prepublish-audit scan --git-files --history .
```

```text
prepublish-audit 0.1.0
Scanned: 4 files (4 text, 0 binary); 0 history blobs, 1 commit, 1 ref
Denylist: 8 entries from 1 file  |  helpers: ffprobe

docs/roadmap.md
  3:5       error    denylist                         Denylist match: codename  [redacted, 13 chars]

src/settings.py
  1:12      warning  leak.home-path                   Absolute home-directory path  [redacted, 21 chars]
  2:15      warning  leak.identifier-assignment       Hard-coded account identifier  [redacted, 10 chars]

FAILED: 1 error(s), 2 warning(s), 0 note(s) (fail-on: warning)
How to fix:
  denylist                    Remove or rename it. If it is allowed in this place, add an indented 'allow:' line under the entry.
  leak.home-path              Use relative paths, ~, or an environment variable.
  leak.identifier-assignment  Read the ID from configuration that is not published.
  A finding that is fine to publish: allow it (README, 'Allowing known-good findings'). Errors and fixes: https://github.com/deegitech/prepublish-audit/blob/v0.1.0/docs/troubleshooting.md
Matched text is redacted. Re-run locally with --reveal to see it (never in CI logs).
Notes:
  - gitleaks 8.30.1 also ran; 0 additional finding(s).
```

On your own machine, add `--reveal` to see each match and its line (it is refused in CI):

```bash
prepublish-audit scan --git-files --history --reveal .
```

Then, for each finding: remove or replace the value, or allow it where it is fine (an indented
`allow:` line in the denylist for denylist matches, an `[[allow]]` entry in `.prepublish-audit.toml`
for built-in rules). Findings that live only in history do not go away when you delete the file:
publish a fresh single-commit history ([release-checklist.md](release-checklist.md)). Exit codes: `0`
passed, `1` findings, `2` an error (with a `fix:` line).

Other things you can scan the same way: `prepublish-audit scan dist/` for a site build,
`prepublish-audit scan release.zip` for a bundle. Leave out `--git-files` there: a build folder is
usually gitignored, so `--git-files` would read nothing in it (the report says so).

## Step 7. Run it automatically (once per repository)

**Hooks on your machine** ([pre-commit](https://pre-commit.com)), the gate before anything leaves it.
Add [examples/pre-commit-config.yaml](../examples/pre-commit-config.yaml) to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/deegitech/prepublish-audit
    rev: v0.1.0
    hooks:
      - id: prepublish-audit            # staged files, on every commit
      - id: prepublish-audit-history    # whole repository and history, before every push
        args: [--require-denylist]      # stop, instead of passing, when no denylist is found
```

then:

```bash
pipx install pre-commit
pre-commit install                        # staged files on every commit
pre-commit install --hook-type pre-push   # whole repository and history before every push
```

The second command is the one people forget: without it the history hook never runs.
`prepublish-audit doctor` reports a hook that is configured but not installed.

Hooks run without your shell, so they find the denylist only through option A (the default file) or
option C (`PREPUBLISH_AUDIT_DENYLIST`, which a GUI git client may not pass on). A hook prints nothing
while it passes, so without `--require-denylist` a missing denylist would go unnoticed. Someone who
pushes without a denylist (an outside contributor, after the repository goes public) can skip that
hook with `SKIP=prepublish-audit-history git push`.

With the Keychain only (option B), replace the `prepublish-audit-history` hook with a local hook,
under `repos:`, that reads the Keychain itself:

```yaml
  - repo: local
    hooks:
      - id: prepublish-audit-keychain
        name: prepublish-audit (history, denylist from the Keychain)
        language: system
        entry: bash -c 'prepublish-audit scan --require-denylist --quiet --git-files --history --denylist <(security find-generic-password -a "$USER" -s prepublish-audit-denylist -w | base64 --decode) .'
        pass_filenames: false
        always_run: true
        stages: [pre-push]
```

**GitHub Actions**, the backstop. Copy [examples/github-workflow.yml](../examples/github-workflow.yml)
to `.github/workflows/prepublish-audit.yml`, create the environment and secret from step 4D, and pin
the action to the release commit:

```bash
git ls-remote https://github.com/deegitech/prepublish-audit refs/tags/v0.1.0
# uses: deegitech/prepublish-audit@<that SHA> # v0.1.0
```

Start the first run from **Actions** → **prepublish-audit** → **Run workflow**. With required
reviewers, the denylist job waits until a reviewer opens the run, clicks **Review deployments**,
ticks the environment and clicks **Approve and deploy**.

## Step 8. Before the repository goes public (once per repository)

The full checklist is [release-checklist.md](release-checklist.md); these are the console steps.

1. **Your commit email.** Profile picture → **Settings** → **Emails**: tick **Keep my email
   addresses private** and **Block command line pushes that expose my email**. The page shows your
   `<id>+<login>@users.noreply.github.com` address; use it in the repository:

   ```bash
   git config user.email "1234567890+your-login@users.noreply.github.com"
   ```

2. **Create the repository private.** **+** → **New repository** → **Private**. Publish a fresh
   single-commit history (release-checklist.md, step 3), push, and run the final scan on exactly
   that commit.
3. **Turn on the protections.** Repository → **Settings** → **Advanced Security**, in the
   **Security and quality** section of the sidebar (older labels: **Code security**, **Code security
   and analysis**; names may differ):
   - **Secret Protection** → **Enable**, then **Push protection** → **Enable** (older label for the
     first: **Secret scanning**);
   - **Private vulnerability reporting** → **Enable** (public repositories only);
   - **Dependabot alerts** and **Dependabot security updates** → **Enable**;
   - **Code scanning** → **CodeQL analysis** → **Set up** → **Default**.
4. **Protect `main`, after the first push.** **Settings** → **Rules** → **Rulesets** → **New
   ruleset** → **New branch ruleset** (or **Settings** → **Branches** → **Add classic branch
   protection rule**). Target the default branch and enable **Restrict deletions**, **Block force
   pushes**, **Require a pull request before merging** and **Require status checks to pass**. Pushing
   to a protected branch directly is refused with `GH006` or `GH013`.
5. **Actions defaults.** **Settings** → **Actions** → **General**: under **Workflow permissions**
   choose **Read repository contents and packages permissions** and click **Save**; under **Approval
   for running fork pull request workflows from contributors** (older label: **Fork pull request
   workflows from outside collaborators**) choose **Require approval for first-time contributors** or
   **Require approval for all external contributors**. Names may differ.
6. **Organisation-wide defaults** (organisation owners). Organisation → **Settings** →
   **Advanced Security** or **Code security** → **Configurations** (apply the GitHub recommended
   configuration to all repositories), and **Authentication security** (in the **Security** section)
   → **Require two-factor authentication for everyone in your organization** → **Save** →
   **Confirm**. Before you confirm, GitHub lists who is affected: members without 2FA lose access to
   the organisation's resources until they turn it on, and outside collaborators without it are
   removed and lose their forks of the organisation's private repositories (they can be reinstated
   within three months). Check that list first. These settings need the web UI or a token with the
   `admin:org` scope: `gh auth refresh -h github.com -s admin:org`, and afterwards
   `gh auth refresh -h github.com -r admin:org` to drop the scope again.
7. **Go public.** **Settings** → **General** → **Danger Zone** → **Change repository visibility** →
   **Change to public**. Scan the release artefacts too: `prepublish-audit scan dist/`.
8. **Right after going public (GitHub Free).** A private repository on a free plan has no Secret
   Protection, push protection, CodeQL, private vulnerability reporting, rulesets or branch
   protection, so steps 3 and 4 could only be done in part. Do them now, and check step 5.

## Expiry and renewal

Nothing in prepublish-audit expires: there is no token, no licence and no server. What goes stale is
the denylist, and a stale denylist fails quietly by passing.

- Add a new identifier the day it appears: a new ad account, campaign, app, bucket, host, domain or
  team member.
- Set a calendar reminder (monthly or quarterly) to repeat the candidate search from step 3, then run
  `prepublish-audit check-denylist` and `prepublish-audit doctor`.
- After every change, update every copy: the CI secret (**Settings** → **Environments** →
  `prepublish-audit` → `PREPUBLISH_DENYLIST` → edit → **Update secret**, or `gh secret set` again),
  the SSM parameter (`put-parameter ... --overwrite`) and the Keychain item (step 4B, "To update
  the list").
- Tokens around the tool: a GitHub CLI login has no fixed expiry, but drop the `admin:org` scope
  after use; a personal access token expires on the date you chose, so renew it under **Settings** →
  **Developer settings** → **Personal access tokens** before then.
- After upgrading prepublish-audit or a helper, run `prepublish-audit doctor` again.

## Common mistakes

> [!WARNING]
> **Common mistakes**
>
> - Keeping the denylist inside the repository, or in a dotfiles repository that gets pushed.
>   `doctor` reports both.
> - Storing it in the Keychain through the interactive prompt (`-w` with no value): observed
>   (Oct 2026), the prompt keeps only 128 characters. Use `-w "$(base64 < FILE)"`.
> - Keeping the plaintext file after moving the list to the Keychain: plain scans and hooks keep
>   reading the old copy.
> - Scanning with `--denylist <(pa_denylist)` but without `--require-denylist`: an empty pipe (helper
>   not loaded, keychain locked) gives a `PASSED` that checked nothing private.
> - Pasting the Keychain clipboard command and `pbcopy </dev/null` at once: the command text is
>   stored instead of the denylist.
> - Putting private values into `.prepublish-audit.toml`. It is public; private values belong in
>   the denylist.
> - Giving the denylist to pull-request workflows, or giving every repository your full
>   organisation-wide list.
> - Running `--reveal` in CI, or writing a revealed report inside a repository.
> - Deleting a file in a new commit and expecting the history to be clean.
> - Committing with a personal or work email before switching to the no-reply address.
> - Installing the hooks without `pre-commit install --hook-type pre-push`, or without
>   `args: [--require-denylist]` on the history hook.
> - Scanning a gitignored build folder with `--git-files`: nothing in it is read.
> - Checking out with the default `fetch-depth: 1` in CI, so the history scan sees one commit.
> - Making the repository public before the final scan.
