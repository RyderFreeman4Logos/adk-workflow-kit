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
sed -i "s/ecbfbcc433c4902b1df5af4376ce8cb5ac0b2cfe/$base/" "$repo/scripts/local-release.sh"
git -C "$repo" add scripts/local-release.sh
git -C "$repo" commit -qm fixture
openssl genpkey -algorithm Ed25519 -out "$repo/test-key.pem" 2>/dev/null
output_dir="$(mktemp -d)"

(cd "$repo" && RELEASE_EXPECTED_BRANCH=wrong RELEASE_EXPECTED_BASE=wrong RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$output_dir" \
  "$repo/scripts/local-release.sh" >/dev/null)
[[ -s "$output_dir/adk-workflow-kit.tar.gz" ]]
[[ -s "$output_dir/adk-workflow-kit.tar.gz.sig" ]]
first_archive_sha="$(sha256sum "$output_dir/adk-workflow-kit.tar.gz")"
openssl pkeyutl -verify -rawin -pubin \
  -inkey <(openssl pkey -in "$repo/test-key.pem" -pubout 2>/dev/null) \
  -in "$output_dir/adk-workflow-kit.tar.gz" \
  -sigfile "$output_dir/adk-workflow-kit.tar.gz.sig" >/dev/null
(cd "$repo" && RELEASE_EXPECTED_BRANCH=wrong RELEASE_EXPECTED_BASE=wrong RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$output_dir" \
  "$repo/scripts/local-release.sh" >/dev/null)
[[ "$first_archive_sha" == "$(sha256sum "$output_dir/adk-workflow-kit.tar.gz")" ]]

default_parent="$(mktemp -d)"
trap 'rm -rf "$repo" "$default_parent"' EXIT
(cd "$repo" && TMPDIR="$default_parent" RELEASE_EXPECTED_BASE=wrong RELEASE_SIGNING_KEY="$repo/test-key.pem" \
  "$repo/scripts/local-release.sh" >/dev/null)
[[ -s "$default_parent/adk-workflow-kit-release/adk-workflow-kit.tar.gz" ]]
[[ ! -e "$repo/.local-release" ]]

if (cd "$repo" && RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$repo/out" \
  "$repo/scripts/local-release.sh" 2>"$output_dir/repo-output.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[OUTPUT_PATH]' "$output_dir/repo-output.err"
[[ ! -e "$repo/out/adk-workflow-kit.tar.gz" ]]

printf 'not a private key\n' > "$repo/invalid-key.pem"
invalid_output="$(mktemp -d)"
if (cd "$repo" && RELEASE_SIGNING_KEY="$repo/invalid-key.pem" RELEASE_OUTPUT_DIR="$invalid_output" \
  "$repo/scripts/local-release.sh" 2>"$repo/invalid-key.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[KEY_INVALID]' "$repo/invalid-key.err"
[[ ! -e "$invalid_output/adk-workflow-kit.tar.gz" ]]
rm -rf "$invalid_output"

if (cd "$repo" && RELEASE_OUTPUT_DIR="$output_dir" "$repo/scripts/local-release.sh" 2>"$repo/missing.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[KEY_MISSING]' "$repo/missing.err"

printf 'dirty\n' > "$repo/dirty.txt"
if (cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$output_dir" \
  "$repo/scripts/local-release.sh" 2>"$output_dir/dirty.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[TREE_DIRTY]' "$output_dir/dirty.err"
rm "$repo/dirty.txt"

git -C "$repo" switch -q -c drift
if (cd "$repo" && RELEASE_EXPECTED_BASE="$base" RELEASE_SIGNING_KEY="$repo/test-key.pem" RELEASE_OUTPUT_DIR="$output_dir" \
  "$repo/scripts/local-release.sh" 2>"$output_dir/drift.err"); then
  exit 1
fi
grep -Fq 'RELEASE_ERROR[IDENTITY_DRIFT]' "$output_dir/drift.err"

printf 'PASS local release tests\n'
