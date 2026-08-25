#!/usr/bin/env bash
set -euo pipefail

doc="$(git rev-parse --show-toplevel)/RELEASING.md"

! grep -Fq 'Every serialized contract carries an explicit schema version' "$doc"
grep -Fq 'Versioned top-level persisted artifacts' "$doc"
[[ "$(grep -Fc '`origin/main...HEAD`' "$doc")" -eq 2 ]]
! grep -Fq '`main...HEAD`' "$doc"

printf '%s\n' 'PASS releasing contract (4 assertions)'
