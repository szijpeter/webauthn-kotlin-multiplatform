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

check_module "client/webauthn-client-platform" 'webauthn-json-kotlinx|kotlinx-serialization'
check_module "client/webauthn-client-json-core" 'webauthn-json-kotlinx|kotlinx-serialization'
check_module "client/webauthn-client-ktor" 'webauthn-json-kotlinx|kotlinx-serialization|ktor-client-(cio|okhttp|java|darwin|curl|winhttp)'

echo "Dependency-purity checks passed for replaceable client publications."
