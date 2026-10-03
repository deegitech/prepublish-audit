# Security policy

prepublish-audit is a security tool, so we treat bugs that weaken its guarantees
as vulnerabilities, not just as defects.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub:

1. Open the [Security tab](https://github.com/deegitech/prepublish-audit/security) of this repository.
2. Choose **Report a vulnerability** (private vulnerability reporting).
3. Describe the problem, the affected version and how to reproduce it.

Do not open a public issue, pull request or discussion for a vulnerability.
Never include real secrets, denylist entries, IDs or personal data in a report:
build a reproduction from invented values that have the same shape.

We aim to acknowledge reports within five working days and to agree on a fix
and disclosure timeline with you. Fixes are released as patch versions and
published as GitHub Security Advisories. We are happy to credit reporters who
want to be named.

## What we consider a vulnerability

- A way to make any report, log line, error message, annotation or summary
  contain a denylist entry, a matched secret or a source line without `--reveal`
  (this includes SARIF unless `--sarif-real-paths` is given, and fingerprints
  from which a masked value can be recovered).
- The GitHub Action exposing the denylist secret (for example in logs, on a
  command line, in a file left behind, or in an artifact).
- Code execution, file writes outside the requested report paths, or network
  access caused by scanning crafted files, archives, metadata or repositories.
- Resource exhaustion that the documented limits should prevent (archive
  bombs, deeply nested archives, parser or regular-expression blow-ups on
  crafted input).
- A crafted public config that disables, weakens or bypasses denylist matches,
  for example by excluding paths from the denylist check, shrinking what is
  read, or making a run pass although content could not be checked. The config
  is part of the repository, so we treat it as untrusted input; the command
  line and the denylist itself are trusted.

Workflows that hand a denylist secret to pull-request runs are a configuration
problem rather than a vulnerability in the tool: anyone who can push a branch
can change such a workflow. The README and the example workflow show a safer
setup.

Missed detections and false positives of the heuristics are not vulnerabilities
on their own; please open a "False positive or missed leak" issue for them
(with invented data).

## Hardening already in place

See the "Security model" section of the [README](README.md#security-model).
