#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

format="human"
tracker_file="docs/IMPLEMENTATION_TRACKER.md"

usage() {
    cat <<USAGE
Usage: tools/agent/progress-report.sh [--format human|json]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            format="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ "$format" != "human" && "$format" != "json" ]]; then
    echo "Invalid --format: $format" >&2
    exit 2
fi

if [[ ! -f "$tracker_file" ]]; then
    echo "Tracker file not found: $tracker_file" >&2
    exit 2
fi

summary="$(
awk '
function trim(s) {
    gsub(/^[ \t]+|[ \t]+$/, "", s)
    return s
}

/^\|/ {
    split($0, cols, "|")
    if (length(cols) < 10) {
        next
    }

    id = trim(cols[2])
    phase = trim(cols[3])
    status = trim(cols[5])

    if (id == "ID" || id == "" || id ~ /^-+$/) {
        next
    }

    total++
    phaseTotal[phase]++

    if (status == "DONE") {
        done++
        phaseDone[phase]++
    } else if (status == "IN_PROGRESS") {
        inProgress++
    } else if (status == "TODO") {
        todo++
        if (firstTodo == "") {
            firstTodo = id
        }
    } else if (status == "BLOCKED") {
        blocked++
    }
}

END {
    if (total == 0) {
        total = 0
    }
    if (done == "") done = 0
    if (inProgress == "") inProgress = 0
    if (todo == "") todo = 0
    if (blocked == "") blocked = 0
    if (firstTodo == "") firstTodo = "-"

    completion = 0
    if (total > 0) {
        completion = int((done * 100) / total)
    }

    printf "TOTAL\t%d\n", total
    printf "DONE\t%d\n", done
    printf "IN_PROGRESS\t%d\n", inProgress
    printf "TODO\t%d\n", todo
    printf "BLOCKED\t%d\n", blocked
    printf "COMPLETION\t%d\n", completion
    printf "NEXT_TODO\t%s\n", firstTodo

    for (phase in phaseTotal) {
        phaseCompletion = 0
        if (phaseTotal[phase] > 0) {
            phaseCompletion = int((phaseDone[phase] * 100) / phaseTotal[phase])
        }
        printf "PHASE\t%s\t%d\t%d\t%d\n", phase, phaseDone[phase], phaseTotal[phase], phaseCompletion
    }
}
' "$tracker_file"
)"

declare -A stats
phases=()
phase_done=()
phase_total=()
phase_completion=()

while IFS=$'\t' read -r kind c1 c2 c3 c4; do
    case "$kind" in
        TOTAL|DONE|IN_PROGRESS|TODO|BLOCKED|COMPLETION|NEXT_TODO)
            stats["$kind"]="$c1"
            ;;
        PHASE)
            phases+=("$c1")
            phase_done+=("${c2:-0}")
            phase_total+=("${c3:-0}")
            phase_completion+=("${c4:-0}")
            ;;
    esac
done <<< "$summary"

if [[ "$format" == "human" ]]; then
    echo "Tracker totals: total=${stats[TOTAL]} done=${stats[DONE]} in_progress=${stats[IN_PROGRESS]} todo=${stats[TODO]} blocked=${stats[BLOCKED]}"
    echo "Completion: ${stats[COMPLETION]}%"
    echo "Next TODO: ${stats[NEXT_TODO]}"
    if [[ "${#phases[@]}" -gt 0 ]]; then
        echo "Phase progress:"
        for i in "${!phases[@]}"; do
            echo "- ${phases[$i]}: ${phase_done[$i]}/${phase_total[$i]} DONE (${phase_completion[$i]}%)"
        done
    fi
    exit 0
fi

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "$value"
}

printf '{"total":%s,"done":%s,"in_progress":%s,"todo":%s,"blocked":%s,"completion_percent":%s,"next_todo":"%s","phases":[' \
    "${stats[TOTAL]}" \
    "${stats[DONE]}" \
    "${stats[IN_PROGRESS]}" \
    "${stats[TODO]}" \
    "${stats[BLOCKED]}" \
    "${stats[COMPLETION]}" \
    "$(json_escape "${stats[NEXT_TODO]}")"

for i in "${!phases[@]}"; do
    if [[ "$i" -gt 0 ]]; then
        printf ','
    fi
    printf '{"phase":"%s","done":%s,"total":%s,"completion_percent":%s}' \
        "$(json_escape "${phases[$i]}")" \
        "${phase_done[$i]}" \
        "${phase_total[$i]}" \
        "${phase_completion[$i]}"
done

echo ']}'
