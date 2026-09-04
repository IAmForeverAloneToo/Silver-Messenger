#!/usr/bin/env bash
# Run the terminal smoke tests: build the workspace, then every
# tests/tui/test_*.py under each terminal type in $TERMS.
#
#   tests/tui/run.sh                        # xterm-256color
#   TERMS="xterm-256color linux" tests/tui/run.sh
#   tests/tui/run.sh test_help.py           # one test
#
# Needs python3 with pyte (pip install pyte); the tmux test skips itself
# when tmux is not installed.
set -euo pipefail
cd "$(dirname "$0")/../.."

python3 -c 'import pyte' 2>/dev/null || { echo "pyte is missing: pip install pyte" >&2; exit 1; }
cargo build --workspace --quiet

export SILVER_BIN_DIR="${SILVER_BIN_DIR:-$PWD/target/debug}"
export SILVER_TEST_DIR="${SILVER_TEST_DIR:-$(mktemp -d)}"
tests=("$@")
if [ ${#tests[@]} -eq 0 ]; then
    tests=(tests/tui/test_*.py)
else
    tests=("${tests[@]/#/tests/tui/}")
fi

failed=0
for term in ${TERMS:-xterm-256color}; do
    for t in "${tests[@]}"; do
        echo "== $(basename "$t") under TERM=$term"
        if ! TERM="$term" timeout 400 python3 "$t"; then
            failed=$((failed + 1))
        fi
        pkill -x silver-relay 2>/dev/null || true
    done
done
if [ "$failed" -gt 0 ]; then
    echo "$failed test(s) failed" >&2
    exit 1
fi
echo "all terminal tests passed"
