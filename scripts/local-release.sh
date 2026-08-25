#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_BRANCH="${RELEASE_EXPECTED_BRANCH:-feat/release-003-signed-release}"
readonly EXPECTED_BASE="${RELEASE_EXPECTED_BASE:-ecbfbcc433c4902b1df5af4376ce8cb5ac0b2cfe}"
readonly REPO_ROOT="$(git rev-parse --show-toplevel)"
readonly OUTPUT_DIR="${RELEASE_OUTPUT_DIR:-$REPO_ROOT/.local-release}"
readonly KEY_PATH="${RELEASE_SIGNING_KEY:-}"

fail() {
    printf 'RELEASE_ERROR[%s]: %s\n' "$1" "$2" >&2
    exit 1
}

cd "$REPO_ROOT"
branch="$(git symbolic-ref --quiet --short HEAD)" || fail IDENTITY_DRIFT 'detached HEAD'
[[ "$branch" == "$EXPECTED_BRANCH" ]] || fail IDENTITY_DRIFT 'unexpected branch'
[[ -n "$KEY_PATH" && -f "$KEY_PATH" && ! -L "$KEY_PATH" ]] || fail KEY_MISSING 'signing key is missing'
base="$(git rev-parse --verify --quiet refs/remotes/origin/main^{commit})" || fail IDENTITY_DRIFT 'origin/main is missing'
[[ "$base" == "$EXPECTED_BASE" ]] || fail IDENTITY_DRIFT 'origin/main does not match the release base'
git merge-base --is-ancestor "$base" HEAD || fail IDENTITY_DRIFT 'HEAD is not based on origin/main'
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] || fail TREE_DIRTY 'working tree is not clean'

mkdir -p "$OUTPUT_DIR"
archive="$OUTPUT_DIR/adk-workflow-kit.tar.gz"
signature="$OUTPUT_DIR/adk-workflow-kit.tar.gz.sig"
tmp_archive="$(mktemp "$OUTPUT_DIR/.release.XXXXXX.tar.gz")"
trap 'rm -f "$tmp_archive"' EXIT

git archive --format=tar --prefix=adk-workflow-kit/ HEAD \
  | gzip -n > "$tmp_archive"
openssl pkeyutl -sign -rawin -inkey "$KEY_PATH" -in "$tmp_archive" -out "$signature" >/dev/null 2>&1 && \
mv -f "$tmp_archive" "$archive"
trap - EXIT
printf 'PASS local signed release: %s\n' "$archive"
