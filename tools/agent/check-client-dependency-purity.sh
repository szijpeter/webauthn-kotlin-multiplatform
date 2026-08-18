#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

check_module() {
  local module="$1"
  local forbidden="$2"
  local publications_dir="$repo_root/$module/build/publications"
  local files=()

  if [[ ! -d "$publications_dir" ]]; then
    echo "Missing publication metadata for $module: run publishToMavenLocal first." >&2
    return 1
  fi

  while IFS= read -r file; do
    files+=("$file")
  done < <(find "$publications_dir" -type f \( -name '*.pom' -o -name 'pom-default.xml' -o -name '*.module' -o -name 'module.json' \) -print)

  if (( ${#files[@]} == 0 )); then
    echo "No POM or Gradle module metadata found for $module." >&2
    return 1
  fi

  local failed=0
  for file in "${files[@]}"; do
    if rg -n -i "$forbidden" "$file"; then
      echo "Forbidden dependency in $module publication: $file" >&2
      failed=1
    fi
  done
  return "$failed"
}

# These artifacts are the replaceable seams: consumers must be able to supply
# their own codec without resolving the repository's Kotlinx implementation.
check_module "client/webauthn-client-platform" 'webauthn-json-kotlinx|kotlinx-serialization'
check_module "client/webauthn-client-json-core" 'webauthn-json-kotlinx|kotlinx-serialization'
check_module "client/webauthn-client-ktor" 'webauthn-json-kotlinx|kotlinx-serialization|ktor-client-(cio|okhttp|java|darwin|curl|winhttp)'

server_module_dir="$repo_root/server/webauthn-server-core-jvm/build/publications/maven"
server_module_json="$server_module_dir/module.json"
server_pom="$server_module_dir/pom-default.xml"
if [[ ! -f "$server_module_json" || ! -f "$server_pom" ]]; then
  echo "Missing publication metadata for server/webauthn-server-core-jvm: run publishToMavenLocal first." >&2
  exit 1
fi

# The server publication also carries a test-fixtures variant. Only the main
# API/runtime variants are part of the consumer dependency graph; fixture-only
# Kotlinx helpers are intentionally excluded from this assertion.
if jq -e --arg pattern 'webauthn-json-kotlinx|kotlinx-serialization|io\.ktor' \
  '.variants[] | select(.name | test("testFixtures") | not) | .dependencies[]? | select((.group + ":" + .module) | test($pattern; "i"))' \
  "$server_module_json" >/dev/null; then
  echo "Forbidden dependency in server/webauthn-server-core-jvm main publication metadata." >&2
  exit 1
fi

if awk -v pattern='webauthn-json-kotlinx|kotlinx-serialization|io\.ktor' \
  'BEGIN { RS = "</dependency>"; IGNORECASE = 1 }
   $0 ~ pattern && $0 !~ /<optional>true/ { failed = 1 }
   END { exit failed }' "$server_pom"; then
  :
else
  echo "Forbidden non-optional dependency in server/webauthn-server-core-jvm POM." >&2
  exit 1
fi

echo "Dependency-purity checks passed for replaceable client/server publications."
