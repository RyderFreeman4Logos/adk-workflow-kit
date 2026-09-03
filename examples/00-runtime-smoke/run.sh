#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'usage: %s --scripted|--live|--replay\n' "$0" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
mode="$1"
package_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
workflowctl="${WORKFLOWCTL:-workflowctl}"

case "$mode" in
    --replay)
        cd "$package_dir"
        exec "$workflowctl" --json replay replay.json
        ;;
    --scripted|--live)
        ;;
    *)
        usage
        ;;
esac

if ! command -v "$workflowctl" >/dev/null 2>&1 && [ ! -x "$workflowctl" ]; then
    printf 'configuration error: workflowctl executable is unavailable\n' >&2
    exit 2
fi

if [ "$mode" = "--live" ]; then
    missing=''
    [ -n "${WORKFLOW_KIT_LIVE_BASE_URL:-}" ] || missing="${missing} WORKFLOW_KIT_LIVE_BASE_URL"
    [ -n "${WORKFLOW_KIT_LIVE_API_KEY:-}" ] || missing="${missing} WORKFLOW_KIT_LIVE_API_KEY"
    if [ -n "$missing" ]; then
        printf 'configuration error: set the required live variables:%s\n' "$missing" >&2
        exit 2
    fi
    case "$WORKFLOW_KIT_LIVE_BASE_URL" in
        http://*|https://*) ;;
        *)
            printf 'configuration error: WORKFLOW_KIT_LIVE_BASE_URL must use http:// or https://\n' >&2
            exit 2
            ;;
    esac
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf 'prerequisite missing: python3\n' >&2
    exit 2
fi

workdir="${WORKDIR:-}"
cleanup=0
if [ -z "$workdir" ]; then
    workdir="$(mktemp -d)"
    cleanup=1
else
    mkdir -p "$workdir"
fi
cleanup_workdir() {
    if [ "$cleanup" -eq 1 ]; then
        rm -rf "$workdir"
    fi
}
trap cleanup_workdir EXIT

cd "$package_dir"
input="$(<input.example.json)"
profile="profiles/fake.json"
if [ "$mode" = "--live" ]; then
    profile="$workdir/live-profile.json"
    python3 - "$profile" <<'PY'
import json
import os
import sys

with open("profiles/openai-compatible.template.json", encoding="utf-8") as source:
    profile = json.load(source)
model = os.environ.get("WORKFLOW_KIT_LIVE_MODEL", "local-model")
for key in ("model", "reviewer_model"):
    if key in profile:
        profile[key]["model"] = model
        profile[key]["base_url"] = os.environ["WORKFLOW_KIT_LIVE_BASE_URL"]
with open(sys.argv[1], "w", encoding="utf-8") as destination:
    json.dump(profile, destination, separators=(",", ":"))
    destination.write("\n")
PY
fi

"$workflowctl" validate workflow.toml >/dev/null
"$workflowctl" lock workflow.toml >/dev/null
run_json="$("$workflowctl" --json run workflow.toml --profile "$profile" --input "$input" --workdir "$workdir")"
printf '%s\n' "$run_json"
run_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["run_id"])' <<<"$run_json")"
"$workflowctl" --json inspect --run-id "$run_id" --workdir "$workdir" >/dev/null
"$workflowctl" --json resume --run-id "$run_id" --workdir "$workdir" >/dev/null
run_root="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["run_root"])' <<<"$run_json")"
artifact_id="$(python3 - "$run_root/run-manifest.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as source:
    print(json.load(source)["artifact_id"])
PY
)"
cp "$run_root/artifacts/$artifact_id" "$workdir/terminal-artifact.json"
printf 'terminal_artifact=%s\n' "$workdir/terminal-artifact.json"
