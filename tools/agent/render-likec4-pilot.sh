#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PILOT_DIR="$ROOT_DIR/docs/likec4-pilot"
LIKEC4_VERSION="1.58.0"

if ! command -v npx >/dev/null 2>&1; then
    echo "npx is required to run LikeC4." >&2
    exit 1
fi

if ! command -v dot >/dev/null 2>&1; then
    echo "Graphviz dot is required for the tested LikeC4 layout." >&2
    exit 1
fi

if ! command -v mmdc >/dev/null 2>&1; then
    echo "mmdc is required to render the Mermaid comparison asset." >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
likec4=(npx --yes "likec4@${LIKEC4_VERSION}")

"${likec4[@]}" validate "$PILOT_DIR/src"
"${likec4[@]}" export png --light --use-dot --flat -o "$PILOT_DIR/assets" "$PILOT_DIR/src"
rm -f "$PILOT_DIR/assets/index.png"
"${likec4[@]}" build --base ./ --output "$tmp_dir/site" "$PILOT_DIR/src"

mmdc -q \
    -i "$ROOT_DIR/README.md" \
    -o "$tmp_dir/README.rendered.md" \
    -a "$tmp_dir/assets"

cp "$tmp_dir/assets/README.rendered-2.svg" "$PILOT_DIR/assets/repository-architecture-mermaid.svg"

echo "Rendered LikeC4 pilot with: $(${likec4[@]} --version)"
