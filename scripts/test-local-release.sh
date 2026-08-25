#!/usr/bin/env bash
set -euo pipefail

repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
mkdir -p "$repo/scripts"
cp "$(git rev-parse --show-toplevel)/scripts/local-release.sh" "$repo/scripts/local-release.sh"
chmod +x "$repo/scripts/local-release.sh"
git -C "$repo" init -q
git -C "$repo" config user.name test
git -C "$repo" config user.email test@example.invalid
printf 'release fixture\n' > "$repo/README.md"
printf 'test-key.pem\nout/\n' > "$repo/.gitignore"
git -C "$repo" add README.md .gitignore scripts/local-release.sh
git -C "$repo" commit -qm base
git -C "$repo" branch -M feat/release-003-signed-release
git -C "$repo" update-ref refs/remotes/origin/main HEAD
base="$(git -C "$repo" rev-parse HEAD)"
openssl genpkey -algorithm Ed25519 -out "$repo/test-key.pem" 2>/dev/null
mkdir "$repo/out"

(cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$repo/out" \
  "$repo/scripts/local-release.sh" >/dev/null)
[[ -s "$repo/out/adk-workflow-kit.tar.gz" ]]
[[ -s "$repo/out/adk-workflow-kit.tar.gz.sig" ]]
first_archive_sha="$(sha256sum "$repo/out/adk-workflow-kit.tar.gz")"
openssl pkeyutl -verify -rawin -pubin \
  -inkey <(openssl pkey -in "$repo/test-key.pem" -pubout 2>/dev/null) \
  -in "$repo/out/adk-workflow-kit.tar.gz" \
  -sigfile "$repo/out/adk-workflow-kit.tar.gz.sig" >/dev/null
(cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$repo/out" \
  "$repo/scripts/local-release.sh" >/dev/null)
[[ "$first_archive_sha" == "$(sha256sum "$repo/out/adk-workflow-kit.tar.gz")" ]]

if (cd "$repo" && RELEASE_OUTPUT_DIR="$repo/out" "$repo/scripts/local-release.sh" 2>"$repo/missing.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[KEY_MISSING]' "$repo/missing.err"

printf 'dirty\n' > "$repo/dirty.txt"
if (cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$repo/out" \
  "$repo/scripts/local-release.sh" 2>"$repo/dirty.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[TREE_DIRTY]' "$repo/dirty.err"
rm "$repo/dirty.txt"

git -C "$repo" switch -q -c drift
if (cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$repo/out" \
  "$repo/scripts/local-release.sh" 2>"$repo/drift.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[IDENTITY_DRIFT]' "$repo/drift.err"

printf 'PASS local release tests\n'
