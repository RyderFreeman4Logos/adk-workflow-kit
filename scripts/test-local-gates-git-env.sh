#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
test_root="$(mktemp -d "${TMPDIR:?}/adk-git-env.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
cp "$(git rev-parse --git-path index)" "$test_root/index"
before="$(sha256sum < "$test_root/index")"

# A real commit hook exports its alternate index to every child process.
set +e
GIT_INDEX_FILE="$test_root/index" bash "$repo_root/scripts/test-local-gates.sh"
rc=$?
set -e
after="$(sha256sum < "$test_root/index")"
if [[ "$before" != "$after" ]]; then
    printf 'FAIL local-gates fixtures modified the inherited Git index\n' >&2
    exit 1
fi
if [[ $rc -ne 0 ]]; then
    exit "$rc"
fi
printf 'PASS local-gates inherited Git index remains unchanged\n'
