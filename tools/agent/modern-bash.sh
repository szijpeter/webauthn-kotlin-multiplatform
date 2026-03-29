#!/usr/bin/env bash
set -euo pipefail

ensure_modern_bash() {
    local script_path="$1"
    shift || true

    if [[ "$script_path" != /* ]]; then
        script_path="$(cd "$(dirname "$script_path")" && pwd)/$(basename "$script_path")"
    fi

    if [[ "${BASH_VERSINFO[0]:-0}" -ge 4 ]]; then
        export AGENT_BASH_BIN="${AGENT_BASH_BIN:-$BASH}"
        if [[ "$AGENT_BASH_BIN" != */* ]]; then
            AGENT_BASH_BIN="$(command -v "$AGENT_BASH_BIN" || echo "$AGENT_BASH_BIN")"
            export AGENT_BASH_BIN
        fi
        if [[ "$AGENT_BASH_BIN" == */* ]]; then
            export PATH="$(dirname "$AGENT_BASH_BIN"):$PATH"
        fi
        return 0
    fi

    local candidates=(
        "/opt/homebrew/bin/bash"
        "/usr/local/bin/bash"
    )

    local candidate
    for candidate in "${candidates[@]}"; do
        [[ -x "$candidate" ]] || continue
        if "$candidate" -c '[[ "${BASH_VERSINFO[0]:-0}" -ge 4 ]]'; then
            export AGENT_BASH_BIN="$candidate"
            export PATH="$(dirname "$candidate"):$PATH"
            exec "$candidate" "$script_path" "$@"
        fi
    done

    cat >&2 <<'EOF'
ERROR: Bash 4+ is required for tools/agent scripts.
Install a modern Bash (for example via Homebrew) and rerun:
  brew install bash
EOF
    exit 1
}
