#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PILOT_DIR="$ROOT_DIR/docs/kuml-pilot"
KUML_BIN="${KUML_BIN:-kuml}"

if ! command -v "$KUML_BIN" >/dev/null 2>&1; then
    echo "kUML executable not found: $KUML_BIN" >&2
    echo "Set KUML_BIN to a kUML v0.31.0 executable or install it before rerunning." >&2
    exit 1
fi

if ! command -v mmdc >/dev/null 2>&1; then
    echo "mmdc is required to render the Mermaid comparison assets." >&2
    exit 1
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

for source in "$PILOT_DIR"/src/*.kuml.kts; do
    name="$(basename "$source" .kuml.kts)"
    "$KUML_BIN" validate "$source"
    "$KUML_BIN" render "$source" \
        --config "$PILOT_DIR/kuml.config.kts" \
        --output "$PILOT_DIR/assets/${name}-kuml.svg"
done

mmdc -q \
    -i "$ROOT_DIR/README.md" \
    -o "$tmp_dir/README.rendered.md" \
    -a "$tmp_dir/assets"

cp "$tmp_dir/assets/README.rendered-1.svg" "$PILOT_DIR/assets/passkey-ceremony-mermaid.svg"
cp "$tmp_dir/assets/README.rendered-2.svg" "$PILOT_DIR/assets/repository-architecture-mermaid.svg"

echo "Rendered kUML pilot assets with: $($KUML_BIN --version)"
