#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"

normalize_project() {
  sed -E \
    -e 's@/\* webauthn-kotlin-multiplatform[^*]* \*/@/* ROOT_PACKAGE */@g' \
    -e 's@name = "webauthn-kotlin-multiplatform[^"]*";@name = "ROOT_PACKAGE";@g' \
    -e 's@[A-F0-9]{24} /\* ROOT_PACKAGE \*/@ROOT_PACKAGE_OBJECT_ID /* ROOT_PACKAGE */@g' \
    "$1" |
    awk '
      /\/\* Begin PBXFileReference section \*\// {
        print
        in_file_references = 1
        next
      }
      in_file_references && /\/\* End PBXFileReference section \*\// {
        if (root_package_line != "") {
          print root_package_line
        }
        for (line_number = 1; line_number <= file_reference_count; line_number++) {
          print file_reference_lines[line_number]
        }
        delete file_reference_lines
        file_reference_count = 0
        root_package_line = ""
        in_file_references = 0
        print
        next
      }
      in_file_references {
        if ($0 ~ /ROOT_PACKAGE_OBJECT_ID \/\* ROOT_PACKAGE \*\/ = \{/) {
          root_package_line = $0
        } else {
          file_reference_lines[++file_reference_count] = $0
        }
        next
      }
      { print }
    '
}

if [[ $# -gt 0 ]]; then
  if [[ "$1" == "--normalize-project" && $# -eq 2 ]]; then
    normalize_project "$2"
    exit 0
  fi
  echo "Usage: $0 [--normalize-project <project.pbxproj>]" >&2
  exit 2
fi

sample_root="$repo_root/sample/swift-passkey"
expected_version="$(tr -d '[:space:]' < "$sample_root/.xcodegen-version")"
actual_version="$(xcodegen --version | awk '{ print $2 }')"
if [[ "$actual_version" != "$expected_version" ]]; then
  echo "Expected XcodeGen $expected_version, found $actual_version." >&2
  exit 1
fi

python3 "$repo_root/tools/swift/test_check_xcodegen.py"

temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-xcodegen.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
generated_repo="$temporary/$(basename "$repo_root")"
generated_root="$generated_repo/sample/swift-passkey"
mkdir -p "$generated_root"
mkdir -p "$generated_repo/swift/Tests"
cp "$repo_root/Package.swift" "$generated_repo/Package.swift"
cp "$sample_root/project.yml" "$generated_root/project.yml"
cp -R "$sample_root/WebAuthnSwiftDemo" "$generated_root/WebAuthnSwiftDemo"
cp -R "$sample_root/WebAuthnSwiftDemoTests" "$generated_root/WebAuthnSwiftDemoTests"
cp -R "$sample_root/WebAuthnSwiftDemoUITests" "$generated_root/WebAuthnSwiftDemoUITests"
cp -R "$repo_root/swift/Tests/WebAuthnTests" "$generated_repo/swift/Tests/WebAuthnTests"
xcodegen generate --spec "$generated_root/project.yml" --project "$generated_root" --quiet

expected_project="$sample_root/WebAuthnSwiftDemo.xcodeproj"
generated_project="$generated_root/WebAuthnSwiftDemo.xcodeproj"
if ! diff -u \
  <(normalize_project "$expected_project/project.pbxproj") \
  <(normalize_project "$generated_project/project.pbxproj")
then
  echo "Committed Xcode project drifted from project.yml: project.pbxproj" >&2
  exit 1
fi
for relative_path in \
  project.xcworkspace/contents.xcworkspacedata \
  xcshareddata/xcschemes/WebAuthnSwiftDemo.xcscheme
do
  if ! diff -u "$expected_project/$relative_path" "$generated_project/$relative_path"; then
    echo "Committed Xcode project drifted from project.yml: $relative_path" >&2
    exit 1
  fi
done

echo "Committed Xcode project matches project.yml with XcodeGen $expected_version."
