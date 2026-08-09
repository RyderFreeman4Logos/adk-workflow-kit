#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
source_runner="$repo_root/scripts/local-gates.sh"
if [[ ! -x "$source_runner" ]]; then
    printf 'FAIL local-gates helper is missing or not executable: %s\n' "$source_runner" >&2
    exit 1
fi

test_root="$(mktemp -d "${TMPDIR:-/tmp}/adk-local-gates.XXXXXX")"
trap 'rm -rf -- "$test_root"' EXIT
fixture="$test_root/repo"
mkdir -p "$fixture/scripts" "$fixture/bin"
git -C "$fixture" init -q -b main
cp "$source_runner" "$fixture/scripts/local-gates.sh"
printf '%s\n' '.local-gates/' > "$fixture/.gitignore"
printf '%s\n' seed > "$fixture/tracked.txt"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    '[[ "$*" == "_quality-gates" ]] || { printf "unexpected just args: %s\\n" "$*" >&2; exit 64; }' \
    'printf "run\\n" >> "${FAKE_GATE_LOG:?}"' \
    '[[ "${FAKE_GATE_DIRTY:-0}" != 1 ]] || printf "dirty\\n" >> tracked.txt' \
    '[[ "${FAKE_GATE_FAIL:-0}" != 1 ]] || exit 42' \
    > "$fixture/bin/just"
printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'printf "%s\\n" "$*" > "${FAKE_CSA_LOG:?}"' \
    '[[ "$*" == "review --check-verdict --range main...HEAD" ]]' \
    > "$fixture/bin/csa"
chmod +x "$fixture/scripts/local-gates.sh" "$fixture/bin/just" "$fixture/bin/csa"
git -C "$fixture" add .
git -C "$fixture" -c user.name='Gate Test' -c user.email='gate-test@example.invalid' \
    commit -qm 'test: initialize fixture'
mkdir -p "$fixture/.local-gates"
runner="$fixture/scripts/local-gates.sh"
gate_log="$fixture/.local-gates/gate.log"
csa_log="$fixture/.local-gates/csa.log"
assertions=0

invoke() {
    (cd "$fixture" && env \
        PATH="$fixture/bin:$PATH" \
        FAKE_GATE_LOG="$gate_log" \
        FAKE_CSA_LOG="$csa_log" \
        FAKE_GATE_FAIL="${FAKE_GATE_FAIL:-0}" \
        FAKE_GATE_DIRTY="${FAKE_GATE_DIRTY:-0}" \
        "$@")
}

assert_fails() {
    local name="$1" expected="$2" output rc
    shift 2
    set +e
    output="$(invoke "$@" 2>&1)"
    rc=$?
    set -e
    if [[ $rc -eq 0 || "$output" != *"$expected"* ]]; then
        printf 'FAIL %s: exit=%s output=%s\n' "$name" "$rc" "$output" >&2
        exit 1
    fi
    ((assertions += 1))
}

assert_fails protected-branch 'main' "$runner" check-branch
git -C "$fixture" switch -qc feature/test
invoke "$runner" check-branch
((assertions += 1))
assert_fails missing-receipt 'missing' "$runner" verify
invoke "$runner" produce
invoke "$runner" verify
invoke "$runner" pre-push
[[ "$(<"$csa_log")" == 'review --check-verdict --range main...HEAD' ]]
((assertions += 4))

printf '%s\n' malformed > "$fixture/.local-gates/quality-gate.receipt"
assert_fails malformed-receipt 'malformed or stale' "$runner" verify
invoke "$runner" produce
printf '%s\n' dirty >> "$fixture/tracked.txt"
assert_fails dirty-tree 'clean' "$runner" verify
git -C "$fixture" restore tracked.txt
printf '%s\n' next >> "$fixture/tracked.txt"
git -C "$fixture" add tracked.txt
git -C "$fixture" -c user.name='Gate Test' -c user.email='gate-test@example.invalid' \
    commit -qm 'test: advance head'
assert_fails stale-receipt 'malformed or stale' "$runner" verify

set +e
FAKE_GATE_FAIL=1 invoke "$runner" produce >/dev/null 2>&1
failure_rc=$?
set -e
[[ $failure_rc -eq 42 && ! -e "$fixture/.local-gates/quality-gate.receipt" ]]
((assertions += 1))

invoke "$runner" produce
set +e
FAKE_GATE_DIRTY=1 invoke "$runner" produce >/dev/null 2>&1
drift_rc=$?
set -e
[[ $drift_rc -ne 0 && ! -e "$fixture/.local-gates/quality-gate.receipt" ]]
((assertions += 1))

printf 'PASS local-gates contract (%d assertions)\n' "$assertions"
