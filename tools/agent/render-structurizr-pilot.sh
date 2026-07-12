#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
PILOT_DIR="$ROOT/docs/structurizr-pilot"
SRC="$PILOT_DIR/src/workspace.dsl"
ASSETS="$PILOT_DIR/assets"
CLI="${STRUCTURIZR_CLI:-structurizr.sh}"

command -v "$CLI" >/dev/null 2>&1 || {
  echo "Structurizr CLI not found. Set STRUCTURIZR_CLI to structurizr.sh." >&2
  exit 1
}
command -v plantuml >/dev/null 2>&1 || { echo "PlantUML is required." >&2; exit 1; }
command -v mmdc >/dev/null 2>&1 || { echo "Mermaid CLI is required." >&2; exit 1; }

mkdir -p "$ASSETS" "$ASSETS/plantuml"
rm -f "$ASSETS"/*.svg
"$CLI" validate -workspace "$SRC"
rm -f "$ASSETS/plantuml"/*
"$CLI" export -workspace "$SRC" -format plantuml/c4plantuml -output "$ASSETS/plantuml"
plantuml -tsvg "$ASSETS/plantuml"/*.puml
mmdc -i "$ROOT/docs/architecture.md" -o "$ASSETS/repository-architecture-mermaid.svg" -e svg -q
mv "$ASSETS/repository-architecture-mermaid-1.svg" "$ASSETS/repository-architecture-mermaid.svg"
cp "$ASSETS/plantuml/structurizr-system_context.svg" "$ASSETS/system-context.svg"
cp "$ASSETS/plantuml/structurizr-repository_overview.svg" "$ASSETS/repository-overview.svg"
cp "$ASSETS/plantuml/structurizr-core_dependencies.svg" "$ASSETS/core-dependencies.svg"
rm -rf "$ASSETS/plantuml"
echo "Rendered Structurizr DSL pilot with $($CLI version | head -1)"
