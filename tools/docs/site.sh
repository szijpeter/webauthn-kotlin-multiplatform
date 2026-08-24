#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILD_ROOT="$REPOSITORY_ROOT/build/docs-site"
VIRTUAL_ENVIRONMENT="$BUILD_ROOT/venv"
LOCK_FILE="$REPOSITORY_ROOT/docs/site/requirements.lock"
LOCK_STAMP="$VIRTUAL_ENVIRONMENT/.requirements-lock.sha256"

lock_hash() {
  python3 - "$LOCK_FILE" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

bootstrap() {
  if [[ ! -f "$LOCK_FILE" ]]; then
    echo "Missing $LOCK_FILE; run tools/docs/site.sh lock" >&2
    exit 1
  fi

  if [[ ! -x "$VIRTUAL_ENVIRONMENT/bin/python" ]]; then
    python3 -m venv "$VIRTUAL_ENVIRONMENT"
  fi

  local expected_hash
  expected_hash="$(lock_hash)"
  local installed_hash=""
  if [[ -f "$LOCK_STAMP" ]]; then
    installed_hash="$(<"$LOCK_STAMP")"
  fi

  if [[ "$installed_hash" != "$expected_hash" ]]; then
    "$VIRTUAL_ENVIRONMENT/bin/python" -m pip install --disable-pip-version-check --require-hashes -r "$LOCK_FILE"
    printf '%s\n' "$expected_hash" > "$LOCK_STAMP"
  fi
}

build_site() {
  bootstrap
  cd "$REPOSITORY_ROOT"
  "$VIRTUAL_ENVIRONMENT/bin/python" -m mkdocs build --strict --config-file mkdocs.yml
  python3 tools/docs/public_site.py install-api
  python3 tools/docs/public_site.py check-html
}

serve_site() {
  cd "$REPOSITORY_ROOT"
  ./gradlew docsSiteStage dokkaGenerate --stacktrace
  build_site
  echo "Serving documentation at http://127.0.0.1:8000/"
  "$VIRTUAL_ENVIRONMENT/bin/python" -m http.server 8000 --directory "$BUILD_ROOT/site"
}

update_lock() {
  local lock_environment="$BUILD_ROOT/lock-venv"
  python3 -m venv "$lock_environment"
  "$lock_environment/bin/python" -m pip install --disable-pip-version-check 'uv==0.12.5'
  cd "$REPOSITORY_ROOT"
  "$lock_environment/bin/uv" pip compile \
    --generate-hashes \
    --output-file docs/site/requirements.lock \
    docs/site/requirements.in
}

case "${1:-}" in
  build|check)
    build_site
    ;;
  serve)
    serve_site
    ;;
  lock)
    update_lock
    ;;
  *)
    echo "Usage: tools/docs/site.sh <build|check|serve|lock>" >&2
    exit 2
    ;;
esac
