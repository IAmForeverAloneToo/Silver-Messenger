#!/bin/sh
# Run every model under Verifpal and compare each query's outcome with
# expected.txt. Verifpal exits 0 whether or not a query is broken, so its
# result code (one letter and one digit per query, in the order the model
# asks them: 'c0' a confidentiality query that holds, 'a1' an
# authentication query with an attack) is compared instead. The code is
# the one line of its output made of such pairs alone; it is not always
# the last line, since Verifpal says so when a newer version exists. A
# model that does not run, a query the expectations do not list, or an
# outcome that differs from the one expected fails the check.
#
#   VERIFPAL=/path/to/verifpal formal/check.sh
#
# Needs Verifpal 1.4 (cargo install --locked verifpal --version 1.4.2).
set -eu
cd "$(dirname "$0")"
verifpal="${VERIFPAL:-verifpal}"
tab=$(printf '\t')
status=0

# The queries a model asks, in order, one per line.
queries_of() {
    awk '/^queries\[/ { f = 1; next } f && /^\]/ { f = 0 } f { sub(/^[ \t]+/, ""); sub(/[ \t]+$/, ""); if ($0 != "") print }' "$1"
}

# Every model in the directory must have expectations.
for model in *.vp; do
    if ! grep -qF "$model$tab" expected.txt; then
        printf 'MISSING  %-24s not in expected.txt\n' "$model"
        status=1
    fi
done

for model in $(grep -v '^#' expected.txt | awk -F"$tab" '$1 != "options" { print $1 }' | sort -u); do
    options=$(awk -F"$tab" -v m="$model" '$1 == "options" && $2 == m { print $3 }' expected.txt)

    # The code expected.txt implies, built from the model's own query list
    # so that a query without an expectation is caught.
    expected=""
    missing=""
    while IFS= read -r query; do
        verdict=$(awk -F"$tab" -v m="$model" -v q="$query" '$1 == m && $2 == q { print $3 }' expected.txt)
        case "$verdict" in
            holds) digit=0 ;;
            fails) digit=1 ;;
            *) missing="$missing$query; "; continue ;;
        esac
        expected="$expected$(printf '%s' "$query" | cut -c1)$digit"
    done <<EOF
$(queries_of "$model")
EOF
    if [ -n "$missing" ]; then
        printf 'MISSING  %-24s no expectation for: %s\n' "$model" "$missing"
        status=1
        continue
    fi

    # shellcheck disable=SC2086 # the options are meant to split
    if ! output=$("$verifpal" verify "$model" $options --result-code 2>&1); then
        printf 'ERROR    %-24s Verifpal failed\n' "$model"
        printf '%s\n' "$output" | tail -20
        status=1
        continue
    fi
    got=$(printf '%s\n' "$output" | grep -E '^([ca][01])+$' | tail -1)
    if [ "$got" = "$expected" ]; then
        printf 'ok       %-24s %s\n' "$model" "$got"
    else
        printf 'MISMATCH %-24s expected %s, Verifpal says %s\n' "$model" "$expected" "$got"
        printf '%s\n' "$output" | sed -n '/Verification completed/,$p'
        status=1
    fi
done

if [ "$status" -eq 0 ]; then
    echo "every model agrees with expected.txt"
fi
exit "$status"
