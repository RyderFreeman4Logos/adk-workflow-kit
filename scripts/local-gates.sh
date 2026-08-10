#!/usr/bin/env bash
set -euo pipefail

readonly RECEIPT_SCHEMA='adk-workflow-kit-local-gate-v1'
readonly RECEIPT_DIR='.local-gates'
readonly RECEIPT_FILE="$RECEIPT_DIR/quality-gate.receipt"
readonly RECEIPT_COMMAND='just _quality-gates'

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

push_blocked() {
    printf 'ERROR: local gate receipt is not valid for this exact tree: %s\n' "$*" >&2
    printf 'Run `just quality-gates` on the unchanged clean commit, then obtain a PASS review for `main...HEAD`.\n' >&2
    exit 1
}

readonly REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

check_branch() {
    CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD)" \
        || fail 'detached HEAD cannot pass repository governance gates'
    [[ "$CURRENT_BRANCH" != main ]] \
        || fail "branch 'main' is protected; create a feature branch"
}

ensure_clean_tree() {
    local status
    status="$(git status --porcelain=v1 --untracked-files=all)" \
        || fail 'cannot inspect repository status'
    [[ -z "$status" ]]
}

snapshot() {
    SNAPSHOT_HEAD="$(git rev-parse --verify 'HEAD^{commit}')" \
        || fail 'cannot resolve HEAD commit'
    SNAPSHOT_TREE="$(git rev-parse --verify 'HEAD^{tree}')" \
        || fail 'cannot resolve HEAD tree'
}

expected_receipt() {
    printf 'schema=%s\nstatus=PASS\nhead=%s\ntree=%s\ncommand=%s\n' \
        "$RECEIPT_SCHEMA" "$1" "$2" "$RECEIPT_COMMAND"
}

ensure_receipt_location() {
    git check-ignore -q -- "$RECEIPT_FILE" \
        || fail "$RECEIPT_DIR must remain ignored"
    [[ ! -L "$RECEIPT_DIR" ]] \
        || fail "$RECEIPT_DIR must be a repository-local directory, not a symlink"
    [[ ! -e "$RECEIPT_DIR" || -d "$RECEIPT_DIR" ]] \
        || fail "$RECEIPT_DIR is not a directory"
}

prepare_receipt_directory() {
    ensure_receipt_location
    mkdir -p -- "$RECEIPT_DIR"
    [[ -O "$RECEIPT_DIR" ]] || fail "$RECEIPT_DIR must be owned by the current user"
    chmod 700 -- "$RECEIPT_DIR"
    if [[ -e "$RECEIPT_FILE" || -L "$RECEIPT_FILE" ]]; then
        [[ ! -d "$RECEIPT_FILE" ]] || fail "$RECEIPT_FILE must not be a directory"
        rm -f -- "$RECEIPT_FILE"
    fi
}

publish_receipt() {
    local temporary_receipt
    temporary_receipt="$(mktemp "$RECEIPT_DIR/.quality-gate.XXXXXX")" \
        || fail 'cannot create temporary receipt'
    chmod 600 -- "$temporary_receipt"
    expected_receipt "$SNAPSHOT_HEAD" "$SNAPSHOT_TREE" > "$temporary_receipt"
    mv -f -- "$temporary_receipt" "$RECEIPT_FILE"
    printf 'PASS local quality gate receipt: %s\n' "$RECEIPT_FILE"
}

produce_receipt() {
    local before_head before_tree gate_rc
    check_branch
    ensure_clean_tree \
        || fail 'quality-gates requires a clean index and worktree before it begins'
    snapshot
    before_head="$SNAPSHOT_HEAD"
    before_tree="$SNAPSHOT_TREE"
    prepare_receipt_directory

    set +e
    (set -euo pipefail; just _quality-gates)
    gate_rc=$?
    set -e
    if [[ $gate_rc -ne 0 ]]; then
        printf 'ERROR: quality gate failed with exit code %s; no PASS receipt was written.\n' \
            "$gate_rc" >&2
        exit "$gate_rc"
    fi

    ensure_clean_tree \
        || fail 'quality gate changed the index or worktree; no PASS receipt was written'
    snapshot
    [[ "$SNAPSHOT_HEAD" == "$before_head" && "$SNAPSHOT_TREE" == "$before_tree" ]] \
        || fail 'HEAD or tree changed during the quality gate; no PASS receipt was written'
    publish_receipt
}

verify_receipt() {
    ensure_clean_tree || push_blocked 'the index or worktree is not clean'
    ensure_receipt_location
    snapshot
    [[ -f "$RECEIPT_FILE" && ! -L "$RECEIPT_FILE" && -O "$RECEIPT_FILE" ]] \
        || push_blocked 'the receipt is missing or unsafe'
    cmp -s -- "$RECEIPT_FILE" <(expected_receipt "$SNAPSHOT_HEAD" "$SNAPSHOT_TREE") \
        || push_blocked 'the receipt is malformed or stale'
    printf 'PASS local quality gate receipt verified for %s.\n' "$SNAPSHOT_HEAD"
}

native_review_receipt_valid() {
    local -a lines
    local report_path report_sha256 actual_sha256
    local native_receipt='.csa/native-review.receipt'

    git check-ignore -q -- "$native_receipt" || return 1
    [[ ! -L .csa && -f "$native_receipt" && ! -L "$native_receipt" && -O "$native_receipt" ]] \
        || return 1
    mapfile -t lines < "$native_receipt" || return 1
    [[ ${#lines[@]} -eq 6 || ${#lines[@]} -eq 7 ]] || return 1
    [[ "${lines[0]}" == 'schema=adk-workflow-kit-native-review-v1' ]] || return 1
    [[ "${lines[1]}" == 'status=PASS' ]] || return 1
    [[ "${lines[2]}" == "head=$SNAPSHOT_HEAD" ]] || return 1
    [[ "${lines[3]}" == "tree=$SNAPSHOT_TREE" ]] || return 1
    [[ "${lines[4]}" == 'range=main...HEAD' ]] || return 1
    report_sha256="${lines[5]#report_sha256=}"
    [[ "${lines[5]}" == report_sha256=* && "$report_sha256" =~ ^[0-9a-f]{64}$ ]] \
        || return 1
    if [[ ${#lines[@]} -eq 7 ]]; then
        report_path="${lines[6]#report_path=}"
        [[ "${lines[6]}" == report_path=* && "$report_path" == /* && -f "$report_path" && ! -L "$report_path" ]] \
            || return 1
        actual_sha256="$(sha256sum < "$report_path")" || return 1
        [[ "${actual_sha256%% *}" == "$report_sha256" ]] || return 1
    fi
}

pre_push() {
    local before_branch before_head before_tree expected_ref
    local update local_ref local_oid remote_ref remote_oid
    check_branch
    before_branch="$CURRENT_BRANCH"
    if ! IFS= read -r update; then
        push_blocked 'missing outgoing ref update'
    fi
    if [[ ! "$update" =~ ^([^[:space:]]+)\ ([0-9a-f]+)\ ([^[:space:]]+)\ ([0-9a-f]+)$ ]]; then
        push_blocked 'malformed outgoing ref update'
    fi
    local_ref="${BASH_REMATCH[1]}"
    local_oid="${BASH_REMATCH[2]}"
    remote_ref="${BASH_REMATCH[3]}"
    remote_oid="${BASH_REMATCH[4]}"
    if IFS= read -r update; then
        push_blocked 'multiple outgoing ref updates are unsupported'
    fi
    [[ ! "$local_oid" =~ ^0+$ ]] || push_blocked 'ref deletions are unsupported'
    [[ "$remote_ref" != refs/heads/main ]] \
        || push_blocked "remote ref 'refs/heads/main' is protected"
    expected_ref="refs/heads/$before_branch"
    [[ "$local_ref" == "$expected_ref" ]] \
        || push_blocked 'outgoing local ref must match checked-out branch'
    [[ "$remote_ref" == "$expected_ref" ]] \
        || push_blocked 'outgoing remote ref must match checked-out branch'
    git rev-parse --verify --quiet 'refs/heads/main^{commit}' >/dev/null \
        || fail 'local main branch is required for the review range'
    verify_receipt
    [[ "$local_oid" == "$SNAPSHOT_HEAD" ]] \
        || push_blocked 'outgoing object ID does not match reviewed HEAD'
    [[ "${#remote_oid}" -eq "${#SNAPSHOT_HEAD}" ]] \
        || push_blocked 'remote object ID is malformed'
    before_head="$SNAPSHOT_HEAD"
    before_tree="$SNAPSHOT_TREE"
    if command -v csa >/dev/null 2>&1 \
        && csa review --check-verdict --range main...HEAD; then
        printf 'PASS CSA review for main...%s.\n' "$SNAPSHOT_HEAD"
    elif native_review_receipt_valid; then
        printf 'PASS native review receipt for main...%s.\n' "$SNAPSHOT_HEAD"
    else
        fail 'pre-push requires a passing CSA review for main...HEAD or a valid native review receipt at .csa/native-review.receipt'
    fi
    ensure_clean_tree || fail 'repository changed while review receipt was checked'
    check_branch
    snapshot
    [[ "$CURRENT_BRANCH" == "$before_branch" \
        && "$SNAPSHOT_HEAD" == "$before_head" \
        && "$SNAPSHOT_TREE" == "$before_tree" ]] \
        || fail 'branch, HEAD, or tree changed while review receipt was checked'
    printf 'PASS pre-push receipts verified for main...%s.\n' "$SNAPSHOT_HEAD"
}

case "${1:-}" in
    check-branch) check_branch ;;
    produce) produce_receipt ;;
    verify) verify_receipt ;;
    pre-push) pre_push ;;
    *)
        printf 'Usage: %s {check-branch|produce|verify|pre-push}\n' "$0" >&2
        exit 64
        ;;
esac
