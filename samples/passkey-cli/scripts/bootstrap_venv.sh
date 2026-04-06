#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${MODULE_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_PYTHON="${VENV_DIR}/bin/python"
REQUIREMENTS_FILE="${MODULE_DIR}/requirements.txt"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Python bootstrap failed: '${PYTHON_BIN}' is not on PATH." >&2
  exit 1
fi

"${PYTHON_BIN}" -m venv "${VENV_DIR}"
"${VENV_PYTHON}" -m pip install --upgrade pip
"${VENV_PYTHON}" -m pip install -r "${REQUIREMENTS_FILE}"

echo "Virtual environment ready at ${VENV_DIR}"
echo "Doctor command:"
echo "  ./gradlew :samples:passkey-cli:run --args=\"doctor\""
