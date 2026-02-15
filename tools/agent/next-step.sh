#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

format="human"
tracker_file="docs/IMPLEMENTATION_TRACKER.md"

usage() {
    cat <<USAGE
Usage: tools/agent/next-step.sh [--format human|json|prompt]
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

if [[ "$format" != "human" && "$format" != "json" && "$format" != "prompt" ]]; then
    echo "Invalid --format: $format" >&2
    exit 2
fi

if [[ ! -f "$tracker_file" ]]; then
    echo "Tracker file not found: $tracker_file" >&2
    exit 2
fi

row="$(
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
    priority = trim(cols[4])
    status = trim(cols[5])
    modules = trim(cols[6])
    goal = trim(cols[7])
    acceptance = trim(cols[8])
    agentPrompt = trim(cols[9])

    if (id == "ID" || id == "") {
        next
    }
    if (id ~ /^-+$/) {
        next
    }

    if (status == "TODO") {
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, phase, priority, status, modules, goal, acceptance, agentPrompt
        exit
    }
}
' "$tracker_file"
)"

if [[ -z "$row" ]]; then
    case "$format" in
        json)
            echo '{"status":"empty","message":"No TODO items in implementation tracker."}'
            ;;
        human|prompt)
            echo "No TODO items in implementation tracker."
            ;;
    esac
    exit 3
fi

IFS=$'\t' read -r id phase priority status modules goal acceptance agent_prompt <<< "$row"

json_escape() {
    local value="$1"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    printf '%s' "$value"
}

case "$format" in
    human)
        echo "Next TODO: $id"
        echo "Phase: $phase"
        echo "Priority: $priority"
        echo "Modules: $modules"
        echo "Goal: $goal"
        echo "Acceptance: $acceptance"
        echo "Agent Prompt:"
        echo "$agent_prompt"
        ;;
    json)
        printf '{"id":"%s","phase":"%s","priority":"%s","status":"%s","modules":"%s","goal":"%s","acceptance":"%s","prompt":"%s"}\n' \
            "$(json_escape "$id")" \
            "$(json_escape "$phase")" \
            "$(json_escape "$priority")" \
            "$(json_escape "$status")" \
            "$(json_escape "$modules")" \
            "$(json_escape "$goal")" \
            "$(json_escape "$acceptance")" \
            "$(json_escape "$agent_prompt")"
        ;;
    prompt)
        echo "$agent_prompt"
        ;;
esac
