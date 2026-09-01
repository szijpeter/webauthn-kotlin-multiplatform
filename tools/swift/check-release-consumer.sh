#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <released-version>" >&2
  exit 2
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
exec "$repo_root/tools/swift/check-package-consumer.sh" --release "$1"
