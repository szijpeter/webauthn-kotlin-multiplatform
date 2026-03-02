#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "$0")/../.." && pwd)"
out_dir="$root_dir/spec-cache/webauthn"
mkdir -p "$out_dir"

ts="$(date -u +%Y%m%dT%H%M%SZ)"

tr_url="https://www.w3.org/TR/webauthn-3/"
ed_url="https://w3c.github.io/webauthn/"

tr_file="$out_dir/webauthn-tr-$ts.html"
ed_file="$out_dir/webauthn-ed-$ts.html"

curl -fsSL "$tr_url" -o "$tr_file"
curl -fsSL "$ed_url" -o "$ed_file"

cp "$tr_file" "$out_dir/webauthn-tr-latest.html"
cp "$ed_file" "$out_dir/webauthn-ed-latest.html"

cat > "$out_dir/LAST_UPDATED.txt" <<META
updated_utc=$ts
tr_url=$tr_url
ed_url=$ed_url
META

echo "Updated WebAuthn spec cache at $out_dir"
