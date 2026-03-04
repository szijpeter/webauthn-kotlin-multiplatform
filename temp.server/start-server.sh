#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$ROOT_DIR/temp.server"
LOCAL_PROPERTIES_FILE="$ROOT_DIR/local.properties"

PORT="${PORT:-8787}"
DEFAULT_ANDROID_PACKAGE_NAME="dev.webauthn.samples.composepasskey.android"

read_prop() {
    local file="$1"
    local key="$2"
    if [[ ! -f "$file" ]]; then
        return 1
    fi

    awk -F= -v key="$key" '
        /^[[:space:]]*#/ { next }
        NF >= 1 {
            k=$1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
            if (k == key) {
                v=substr($0, index($0, "=") + 1)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", v)
                print v
            }
        }
    ' "$file" | tail -n 1
}

upsert_prop() {
    local file="$1"
    local key="$2"
    local value="$3"
    local escaped_key
    escaped_key="$(printf '%s\n' "$key" | sed 's/[][\/.^$*+?|(){}]/\\&/g')"

    mkdir -p "$(dirname "$file")"
    touch "$file"

    if grep -qE "^[[:space:]]*${escaped_key}=" "$file"; then
        sed -i.bak -E "s|^[[:space:]]*${escaped_key}=.*$|${key}=${value}|" "$file"
        rm -f "${file}.bak"
    else
        printf "%s=%s\n" "$key" "$value" >> "$file"
    fi
}

require_cmd() {
    local cmd="$1"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
}

detect_debug_sha256() {
    local debug_keystore="$HOME/.android/debug.keystore"
    if [[ ! -f "$debug_keystore" ]]; then
        return 1
    fi

    keytool -list -v \
        -keystore "$debug_keystore" \
        -storepass android \
        -alias androiddebugkey \
        -keypass android 2>/dev/null | awk -F': ' '/SHA256:/{print $2; exit}'
}

cleanup() {
    if [[ -n "${SERVER_PID:-}" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
    fi
    if [[ -n "${NGROK_PID:-}" ]]; then
        kill "$NGROK_PID" >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT INT TERM

require_cmd node
require_cmd ngrok
require_cmd curl
require_cmd awk
require_cmd sed
require_cmd keytool

NGROK_DOMAIN="${NGROK_DOMAIN:-$(read_prop "$LOCAL_PROPERTIES_FILE" "ngrok.domain" || true)}"
ANDROID_PACKAGE_NAME="${ANDROID_PACKAGE_NAME:-$(read_prop "$LOCAL_PROPERTIES_FILE" "ANDROID_PACKAGE_NAME" || true)}"
ANDROID_SHA256="${ANDROID_SHA256:-$(read_prop "$LOCAL_PROPERTIES_FILE" "ANDROID_SHA256" || true)}"
if [[ -z "${ANDROID_SHA256}" ]]; then
    ANDROID_SHA256="$(read_prop "$LOCAL_PROPERTIES_FILE" "android.sha256" || true)"
fi
IOS_APP_ID="${IOS_APP_ID:-$(read_prop "$LOCAL_PROPERTIES_FILE" "IOS_APP_ID" || true)}"

if [[ -z "$ANDROID_PACKAGE_NAME" ]]; then
    ANDROID_PACKAGE_NAME="$DEFAULT_ANDROID_PACKAGE_NAME"
fi

if [[ -z "$ANDROID_SHA256" ]]; then
    ANDROID_SHA256="$(detect_debug_sha256 || true)"
fi

if [[ -z "$ANDROID_SHA256" ]]; then
    echo "ANDROID_SHA256 is not set and debug keystore fingerprint could not be detected." >&2
    echo "Set ANDROID_SHA256 in environment or local.properties." >&2
    exit 1
fi

echo "Starting ngrok tunnel on port $PORT..."
if [[ -n "$NGROK_DOMAIN" ]]; then
    ngrok http "$PORT" --domain="$NGROK_DOMAIN" >/dev/null 2>&1 &
else
    ngrok http "$PORT" >/dev/null 2>&1 &
fi
NGROK_PID=$!

NGROK_URL=""
for _ in {1..20}; do
    NGROK_URL="$(curl -fsS http://127.0.0.1:4040/api/tunnels \
        | grep -o '"public_url":"https://[^"]*' \
        | head -n 1 \
        | cut -d'"' -f4 || true)"
    if [[ -n "$NGROK_URL" ]]; then
        break
    fi
    sleep 1
done

if [[ -z "$NGROK_URL" ]]; then
    echo "Failed to resolve ngrok tunnel URL from ngrok API." >&2
    exit 1
fi

RP_ID="${NGROK_URL#https://}"
ORIGIN="$NGROK_URL"

echo "Using tunnel URL: $NGROK_URL"
echo "Using RP_ID: $RP_ID"
echo "Using ANDROID_PACKAGE_NAME: $ANDROID_PACKAGE_NAME"
echo "Using ANDROID_SHA256: $ANDROID_SHA256"

upsert_prop "$LOCAL_PROPERTIES_FILE" "WEBAUTHN_DEMO_ENDPOINT" "$ORIGIN"
upsert_prop "$LOCAL_PROPERTIES_FILE" "WEBAUTHN_DEMO_RP_ID" "$RP_ID"
upsert_prop "$LOCAL_PROPERTIES_FILE" "WEBAUTHN_DEMO_ORIGIN" "$ORIGIN"
upsert_prop "$LOCAL_PROPERTIES_FILE" "ANDROID_PACKAGE_NAME" "$ANDROID_PACKAGE_NAME"
upsert_prop "$LOCAL_PROPERTIES_FILE" "ANDROID_SHA256" "$ANDROID_SHA256"
if [[ -n "$IOS_APP_ID" ]]; then
    upsert_prop "$LOCAL_PROPERTIES_FILE" "IOS_APP_ID" "$IOS_APP_ID"
fi

echo "Updated local.properties with WEBAUTHN_DEMO_* and Android association values."
echo "Rebuild app after this script starts to bake updated values."

(
    cd "$SERVER_DIR"
    PORT="$PORT" \
    RP_ID="$RP_ID" \
    ORIGIN="$ORIGIN" \
    ANDROID_PACKAGE_NAME="$ANDROID_PACKAGE_NAME" \
    ANDROID_SHA256="$ANDROID_SHA256" \
    IOS_APP_ID="$IOS_APP_ID" \
    node server.mjs
) &
SERVER_PID=$!

wait "$SERVER_PID"
