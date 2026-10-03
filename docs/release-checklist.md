# Release checklist: open-sourcing a repository

This is the checklist we follow before a repository goes public. It assumes you have
prepublish-audit installed and a private denylist at `~/.config/prepublish-audit/denylist.txt`
(or in `$PREPUBLISH_AUDIT_DENYLIST`); [setup.md](setup.md) gets you there from zero, and
`prepublish-audit doctor` confirms it.

Anything that reached a public repository should be treated as compromised, even if it was
public only for a minute: forks, clones, mirrors and caches keep it. So the order matters:
**clean first, publish last.**

## 1. Prepare the code

- [ ] Remove internal-only material: planning notes, logs, reports, exports, screenshots, test
      recordings, `.env` files, local configs.
- [ ] Replace hard-coded IDs, account numbers, hostnames and paths with configuration that is read at
      runtime, and use obvious placeholders in examples (`1234567890`, `you@example.com`,
      `com.example.app`, `db.example.internal`).
- [ ] Make sure the package metadata (author, email, URLs) is what you want to publish.
- [ ] Check binary assets: images, PDFs, office files and videos carry author, device and location
      metadata. Strip it (`exiftool -all= file`) or regenerate the files.

## 2. Audit the working tree and the history

```bash
prepublish-audit check-denylist
prepublish-audit scan --git-files --history .          # redacted, as CI would print it
prepublish-audit scan --git-files --history --reveal . # on your own machine, to see each match
```

- [ ] Fix every finding, or allow it deliberately: in the private denylist for denylist entries
      (an indented `allow:` line), in `.prepublish-audit.toml` for built-in rules.
- [ ] Re-run until the result is `PASSED`.
- [ ] If findings remain **in history**, do not try to delete files in a new commit: the old blobs are
      still in the repository. Publish a fresh history (step 3) or rewrite it with a tool such as
      git-filter-repo, then audit again.

## 3. Publish a fresh, single-commit history

Unless the history itself is valuable and clean, start the public repository from a single commit:

```bash
mkdir ../release
git archive --format=tar HEAD | tar -x -C ../release
cd ../release
git init -b main
git add -A
# Set the identity on the command itself: a global git config may hold a personal name and email.
git -c user.name="Your Org" -c user.email="noreply@github.com" commit -m "Initial public release"
git log --all --format='%an <%ae> | %cn <%ce>'           # check every identity that will be published
prepublish-audit scan --git-files --history --require-denylist .
```

- [ ] The commit author and committer use a no-reply address: `noreply@github.com` for an
      organisation identity, or your `<id>+<login>@users.noreply.github.com` (GitHub shows it under
      Settings > Emails). The `<login>` part is your GitHub username, so put it in your denylist if it
      must not appear. prepublish-audit reports any other address as `git.author-identity`.
- [ ] Your name, username and personal email are in the denylist, so the history scan fails if any
      of them is in a commit, tag or file.
- [ ] Release tags do not record a personal tagger: create them as lightweight tags
      (`git tag v1.0.0`) or from the GitHub release page, not with `git tag -a` under your global
      identity. Check with `git for-each-ref --format='%(refname) %(taggername) %(taggeremail)' refs/tags`.
- [ ] In your GitHub email settings, turn on **Keep my email addresses private** and
      **Block command line pushes that expose my email**.
- [ ] No other branches, tags or stashes exist in the new repository (`git for-each-ref`).

## 4. Create the repository as private first

- [ ] Create the repository **private**, push, and look at it in the browser: file list, README
      rendering, Actions logs of the first CI run, release assets.
- [ ] If you run the prepublish-audit action with a denylist in CI, store it as an **environment**
      secret (for example `PREPUBLISH_DENYLIST` in an environment with required reviewers), keep it
      to the entries this repository needs, and run that job only outside pull requests (see
      `examples/github-workflow.yml`). Anyone who can push a branch can change a pull-request
      workflow and print the secrets it receives; forks receive none.

## 5. Turn on the platform protections

Under **Settings > Advanced Security**, in the **Security and quality** section of the sidebar
(older labels: **Code security**, **Code security and analysis**; names can differ between plans).
On GitHub Free, a private repository has most of these only once it is public, so come back to this
step right after step 6:

- [ ] **Secret Protection** and its **Push protection** (older label: **Secret scanning**).
- [ ] **Private vulnerability reporting**, so that people can report issues without opening a
      public issue (pair it with a `SECURITY.md`).
- [ ] **Dependabot alerts** and **Dependabot security updates**; add a `.github/dependabot.yml`
      for version updates of dependencies and GitHub Actions.
- [ ] **Code scanning** with **CodeQL analysis** (**Set up** → **Default**, or a workflow such as
      this repository's `.github/workflows/codeql.yml`).

Under **Settings > Rules** (rulesets) or **Branches** (branch protection) for `main`:

- [ ] Require a pull request before merging, and require the status checks that matter (tests,
      gitleaks, prepublish-audit).
- [ ] Block force pushes and deletions.
- [ ] Protect release tags (`v*`) from being moved or deleted.

Under **Settings > Actions > General**:

- [ ] **Workflow permissions**: **Read repository contents and packages permissions** by default;
      grant more per job.
- [ ] **Approval for running fork pull request workflows from contributors** (older label: **Fork
      pull request workflows from outside collaborators**): **Require approval for first-time
      contributors** or **Require approval for all external contributors**.
- [ ] Pin third-party actions to full commit SHAs (Dependabot keeps them updated).

## 6. Go public

- [ ] Run the final audit on the exact commit you will publish.
- [ ] Switch the repository to **public**.
- [ ] Create the release from a tag and scan the release artifacts too:
      `prepublish-audit scan dist/` (wheels, zips and tarballs are opened and checked).
- [ ] Watch secret scanning alerts and code scanning results for the first days.

## 7. After an accident

If something private was published anyway:

1. Revoke or rotate it immediately; deleting it is not enough.
2. Rewrite or replace the history, then ask GitHub Support to remove cached views and
   pull-request references if the data was sensitive.
3. Add the value to your denylist so that it can never come back.
