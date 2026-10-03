#!/usr/bin/env bash
# Entry point of the composite GitHub Action (action.yml).
#
# Inputs arrive as PA_* environment variables and are never interpolated into
# shell code. The denylist secret is written to a private temporary file and
# passed by path; the file is removed when this script exits.
set -euo pipefail
umask 077

if ! command -v python3 >/dev/null 2>&1 ||
   ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "::error title=prepublish-audit::Python 3.10 or newer is required on the runner (add actions/setup-python before this step)."
  exit 2
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/prepublish-audit.XXXXXX")"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

args=(scan --format github --json-output "$work/report.json")
# Empty inputs leave the setting to the repository config (or the default).
if [[ -n "${PA_FAIL_ON:-}" ]]; then args+=(--fail-on "$PA_FAIL_ON"); fi
if [[ -n "${PA_GITLEAKS:-}" ]]; then args+=(--gitleaks "$PA_GITLEAKS"); fi

if [[ -n "${PA_DENYLIST:-}" ]]; then
  printf '%s\n' "$PA_DENYLIST" > "$work/denylist.txt"
  args+=(--denylist "$work/denylist.txt")
  # A secret that holds no entries (only comments) must fail too.
  if [[ "${PA_REQUIRE_DENYLIST:-false}" == "true" ]]; then args+=(--require-denylist); fi
elif [[ "${PA_REQUIRE_DENYLIST:-false}" == "true" ]]; then
  echo "::error title=prepublish-audit::No denylist was provided and require-denylist is true. Check that the job sets 'environment:' to the environment that holds the secret and that the secret name matches; pull requests from forks and Dependabot do not receive secrets."
  exit 2
else
  echo "::warning title=prepublish-audit::No denylist was provided, so only the built-in rules ran. Pass one from a secret with the 'denylist' input."
  args+=(--no-denylist)
fi
unset PA_DENYLIST

target="${PA_PATH:-.}"
if [[ "${PA_HISTORY:-true}" == "true" ]]; then
  args+=(--history)
  if [[ "$(git -C "$target" rev-parse --is-shallow-repository 2>/dev/null || echo false)" == "true" ]]; then
    echo "::warning title=prepublish-audit::Shallow clone: check out with fetch-depth: 0 to scan the whole history."
  fi
fi
if [[ "${PA_GIT_FILES:-false}" == "true" ]]; then args+=(--git-files); fi
if [[ -n "${PA_SARIF:-}" ]]; then args+=(--sarif-output "$PA_SARIF"); fi
if [[ -n "${PA_CONFIG:-}" ]]; then args+=(--config "$PA_CONFIG"); fi
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then args+=(--summary-markdown "$GITHUB_STEP_SUMMARY"); fi
if [[ -n "${PA_ARGS:-}" ]]; then
  read -r -a extra <<< "$PA_ARGS"
  if [[ ${#extra[@]} -gt 0 ]]; then args+=("${extra[@]}"); fi
fi

set +e
PYTHONPATH="$PA_ACTION_PATH/src${PYTHONPATH:+:$PYTHONPATH}" python3 -m prepublish_audit "${args[@]}" -- "$target"
code=$?
set -e

if [[ -n "${PA_JSON:-}" && -f "$work/report.json" ]]; then cp "$work/report.json" "$PA_JSON"; fi
findings="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["summary"]["total"])' "$work/report.json" 2>/dev/null || echo 0)"
{
  echo "exit-code=$code"
  echo "findings=$findings"
  echo "sarif-file=${PA_SARIF:-}"
} >> "${GITHUB_OUTPUT:-/dev/null}"
exit "$code"
