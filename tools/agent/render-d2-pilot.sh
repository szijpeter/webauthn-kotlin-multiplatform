#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PILOT_DIR="$ROOT_DIR/docs/d2-pilot"
D2_BIN="${D2_BIN:-d2}"

if ! command -v "$D2_BIN" >/dev/null 2>&1; then
    echo "D2 executable not found: $D2_BIN" >&2
    exit 1
fi

if ! command -v mmdc >/dev/null 2>&1; then
    echo "mmdc is required to render the Mermaid comparison assets." >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for source in "$PILOT_DIR"/src/*.d2; do
    name="$(basename "$source" .d2)"
    "$D2_BIN" "$source" "$PILOT_DIR/assets/${name}-d2.svg"
done

"$D2_BIN" --layout dagre "$PILOT_DIR/src/repository-overview.d2" "$tmp_dir/repository-overview-dagre.svg"

mmdc -q \
    -i "$ROOT_DIR/README.md" \
    -o "$tmp_dir/README.rendered.md" \
    -a "$tmp_dir/assets"

cp "$tmp_dir/assets/README.rendered-2.svg" "$PILOT_DIR/assets/repository-architecture-mermaid.svg"
cp "$tmp_dir/repository-overview-dagre.svg" "$PILOT_DIR/assets/repository-overview-d2-dagre.svg"

echo "Rendered D2 pilot with: $($D2_BIN --version)"
