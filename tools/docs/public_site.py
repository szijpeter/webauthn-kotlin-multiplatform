#!/usr/bin/env python3
"""Stage, assemble, and validate the public documentation site."""

from __future__ import annotations

import argparse
import functools
import html.parser
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
BUILD_ROOT = ROOT / "build" / "docs-site"
STAGED_ROOT = BUILD_ROOT / "staged"
SITE_ROOT = BUILD_ROOT / "site"
API_ROOT = BUILD_ROOT / "api"
REPORT_ROOT = BUILD_ROOT / "reports"
AUTHOR_ROOT = ROOT / "docs" / "site" / "content"
ASSET_ROOT = ROOT / "docs" / "site" / "assets"
REPOSITORY_URL = "https://github.com/szijpeter/webauthn-kotlin-multiplatform"
REPOSITORY_API_URL = "https://api.github.com/repos/szijpeter/webauthn-kotlin-multiplatform"
SWIFT_ARCHIVE_NAME = "WebAuthnBridge.xcframework.zip"
SWIFT_CHECKSUM_NAME = f"{SWIFT_ARCHIVE_NAME}.sha256"
PAGES_PREFIX = "/webauthn-kotlin-multiplatform/"
PUBLISHED_AREAS = ("client", "core", "server", "platform")
FORBIDDEN_SOURCE_PREFIXES = (
    "docs/ai/",
    "spec-cache/",
    "spec-notes/",
    ".gradle/",
    "build/",
)
REPOSITORY_PAGES = {
    "swift/README.md": "mobile/swift.md",
    "sample/compose-passkey/README.md": "guides/samples/compose-passkey.md",
    "sample/compose-passkey-ios/README.md": "guides/samples/compose-passkey-ios.md",
    "sample/swift-passkey/README.md": "guides/samples/swift-passkey.md",
    "sample/backend-ktor/README.md": "guides/samples/backend-ktor.md",
}
LINK_PATTERN = re.compile(
    r"(?P<prefix>!?\[[^\]]*\]\()(?P<target>[^)\s]+)(?P<suffix>(?:\s+[^)]*)?\))",
)
EXTERNAL_SCHEMES = {"http", "https", "mailto", "tel", "data", "javascript"}
UNRESOLVED_TOKEN_PATTERN = re.compile(r"@@[A-Z][A-Z0-9_]*@@")
SWIFT_RELEASE_SECTION_PATTERN = re.compile(
    r"<!-- public-site:swift-release:start -->.*?<!-- public-site:swift-release:end -->",
    re.DOTALL,
)
EXPECTED_ANDROID_SUPPORT = {
    "androidMinSdk": "26",
    "androidCompileSdk": "37",
    "androidPrfMinSdk": "30",
    "androidPrfCompileSdk": "37",
    "sampleMinSdk": "30",
}
_AUTO_SWIFT_RELEASE = object()


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


@functools.cache
def source_ref() -> str:
    return os.environ.get("GITHUB_SHA") or run("git", "rev-parse", "HEAD")


@functools.cache
def latest_stable_version() -> str:
    tags = run("git", "tag", "--list", "v[0-9]*").splitlines()
    versions: list[tuple[tuple[int, ...], str]] = []
    for tag in tags:
        match = re.fullmatch(r"v(\d+(?:\.\d+)*)", tag)
        if match:
            versions.append((tuple(int(part) for part in match.group(1).split(".")), tag))
    if not versions:
        return "unreleased"
    return max(versions)[1]


def swift_release_manifest_checksum(tag: str, manifest: str) -> str | None:
    if re.fullmatch(r"v\d+(?:\.\d+)*", tag) is None:
        return None
    expected_url = (
        f"{REPOSITORY_URL}/releases/download/{tag}/{SWIFT_ARCHIVE_NAME}"
    )
    if not all(
        fragment in manifest
        for fragment in (
            "// swift-tools-version: 6.0",
            '.binaryTarget(',
            f'url: "{expected_url}"',
            'path: "swift/Sources/WebAuthn"',
            "swiftLanguageModes: [.v6]",
        )
    ):
        return None
    checksum = re.search(r'checksum: "([0-9a-f]{64})"', manifest)
    return checksum.group(1) if checksum is not None else None


def is_swift_release_manifest(tag: str, manifest: str) -> bool:
    return swift_release_manifest_checksum(tag, manifest) is not None


def _github_json(url: str) -> dict[str, object]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "webauthn-kotlin-multiplatform-docs",
        "X-GitHub-Api-Version": "2026-03-10",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(
        url,
        headers=headers,
    )
    with urlopen(request, timeout=15) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("GitHub release response is not an object")
    return payload


def _github_bytes(url: str) -> bytes:
    headers = {"User-Agent": "webauthn-kotlin-multiplatform-docs"}
    request = Request(
        url,
        headers=headers,
    )
    with urlopen(request, timeout=15) as response:
        return response.read()


def github_release_has_swift_assets(
    tag: str,
    checksum: str,
    *,
    fetch_json=_github_json,
    fetch_bytes=_github_bytes,
) -> bool:
    try:
        release = fetch_json(f"{REPOSITORY_API_URL}/releases/tags/{quote(tag, safe='')}")
        if (
            release.get("tag_name") != tag
            or release.get("draft") is not False
            or release.get("prerelease") is not False
        ):
            return False
        raw_assets = release.get("assets")
        if not isinstance(raw_assets, list):
            return False
        assets = {
            asset.get("name"): asset
            for asset in raw_assets
            if isinstance(asset, dict) and isinstance(asset.get("name"), str)
        }
        if set(assets) != {SWIFT_ARCHIVE_NAME, SWIFT_CHECKSUM_NAME}:
            return False

        expected_archive_url = (
            f"{REPOSITORY_URL}/releases/download/{tag}/{SWIFT_ARCHIVE_NAME}"
        )
        expected_urls = {
            SWIFT_ARCHIVE_NAME: expected_archive_url,
            SWIFT_CHECKSUM_NAME: f"{expected_archive_url}.sha256",
        }
        for name, expected_url in expected_urls.items():
            asset = assets[name]
            size = asset.get("size")
            if (
                asset.get("state") != "uploaded"
                or asset.get("browser_download_url") != expected_url
                or not isinstance(size, int)
                or isinstance(size, bool)
                or size <= 0
            ):
                return False

        archive_digest = assets[SWIFT_ARCHIVE_NAME].get("digest")
        if archive_digest != f"sha256:{checksum}":
            return False
        return fetch_bytes(expected_urls[SWIFT_CHECKSUM_NAME]) == f"{checksum}\n".encode()
    except (OSError, TimeoutError, TypeError, ValueError, json.JSONDecodeError):
        return False


@functools.cache
def latest_swift_release_version() -> str | None:
    tags = run("git", "tag", "--list", "v[0-9]*").splitlines()
    versions: list[tuple[tuple[int, ...], str]] = []
    for tag in tags:
        match = re.fullmatch(r"v(\d+(?:\.\d+)*)", tag)
        if match:
            versions.append((tuple(int(part) for part in match.group(1).split(".")), tag))
    for _, tag in sorted(versions, reverse=True):
        manifest_result = subprocess.run(
            ("git", "show", f"{tag}:Package.swift"),
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        source_result = subprocess.run(
            ("git", "cat-file", "-e", f"{tag}:swift/Sources/WebAuthn/PasskeyClient.swift"),
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if manifest_result.returncode != 0 or source_result.returncode != 0:
            continue
        manifest = manifest_result.stdout.strip()
        checksum = swift_release_manifest_checksum(tag, manifest)
        if checksum is not None and github_release_has_swift_assets(tag, checksum):
            return tag
    return None


def render_swift_release_section(
    text: str,
    tag: str | None | object = _AUTO_SWIFT_RELEASE,
) -> str:
    if SWIFT_RELEASE_SECTION_PATTERN.search(text) is None:
        raise ValueError("swift/README.md lacks the public Swift release section markers")
    resolved_tag = latest_swift_release_version() if tag is _AUTO_SWIFT_RELEASE else tag
    if resolved_tag is not None and not isinstance(resolved_tag, str):
        raise TypeError("Swift release tag must be a string or None")
    if resolved_tag is None:
        replacement = """<!-- public-site:swift-release:start -->
## Release status

**The native Swift package has not been released yet.** The existing coordinated Kotlin release tags do
not contain the remote binary manifest and XCFramework assets required by Swift Package Manager. Do not use
an existing Kotlin version for the Swift package; build from this repository only for development and
qualification until the first coordinated Swift release is published.
<!-- public-site:swift-release:end -->"""
    else:
        version = resolved_tag.removeprefix("v")
        replacement = f"""<!-- public-site:swift-release:start -->
## Install

The latest verified native Swift release is **{resolved_tag}**. Add the repository URL as a Swift package
dependency, select the `WebAuthn` product, and pin the exact coordinated version:

```swift
.package(
    url: "{REPOSITORY_URL}.git",
    exact: "{version}"
)
```

The qualifying published release contains the expected XCFramework and checksum assets, and its tag contains a
Swift 6 manifest that identifies them exactly. Branch-based consumption is unsupported because `main` uses a
local development artifact.
<!-- public-site:swift-release:end -->"""
    return SWIFT_RELEASE_SECTION_PATTERN.sub(replacement, text, count=1)


def relative_to_root(path: Path) -> str:
    return path.resolve().relative_to(ROOT.resolve()).as_posix()


def ensure_inside(path: Path, root: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"Path escapes allowed root: {path}") from error
    return resolved


def reset_directory(path: Path) -> None:
    ensure_inside(path, BUILD_ROOT)
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def published_modules() -> list[tuple[Path, Path]]:
    modules: list[tuple[Path, Path]] = []
    for area in PUBLISHED_AREAS:
        for build_file in sorted((ROOT / area).glob("*/build.gradle.kts")):
            build_text = build_file.read_text()
            if not any(
                plugin in build_text
                for plugin in ('id("webauthn.published-library")', 'id("webauthn.published-platform")')
            ):
                continue
            readme = build_file.parent / "README.md"
            if not readme.is_file():
                raise FileNotFoundError(f"Published module lacks README: {relative_to_root(build_file.parent)}")
            artifact_name = "webauthn-bom" if build_file.parent == ROOT / "platform" / "bom" else build_file.parent.name
            output = Path("reference/modules") / f"{artifact_name}.md"
            modules.append((readme, output))
    return modules


def authored_pages() -> list[tuple[Path, Path]]:
    if not AUTHOR_ROOT.is_dir():
        raise FileNotFoundError(f"Missing authored documentation root: {AUTHOR_ROOT}")
    return [(path, path.relative_to(AUTHOR_ROOT)) for path in sorted(AUTHOR_ROOT.rglob("*.md"))]


def source_map() -> dict[Path, Path]:
    mapping = {source.resolve(): output for source, output in authored_pages()}
    mapping.update({source.resolve(): output for source, output in published_modules()})
    for source, output in REPOSITORY_PAGES.items():
        mapping[(ROOT / source).resolve()] = Path(output)
    return mapping


def replace_tokens(text: str) -> str:
    stable_version = latest_stable_version()
    artifact_version = stable_version.removeprefix("v")
    return (
        text.replace("@@STABLE_VERSION@@", stable_version)
        .replace("@@ARTIFACT_VERSION@@", artifact_version)
        .replace("<version>", artifact_version)
        .replace("@@SOURCE_REF@@", source_ref())
    )


def rewrite_links(text: str, source: Path, output: Path, mapping: dict[Path, Path]) -> str:
    def replace(match: re.Match[str]) -> str:
        target = match.group("target")
        parsed = urlsplit(target)
        if parsed.scheme in EXTERNAL_SCHEMES or target.startswith(("#", "//")):
            return match.group(0)

        target_path = unquote(parsed.path)
        if not target_path:
            return match.group(0)
        resolved = ensure_inside(source.parent / target_path, ROOT)
        if not resolved.exists():
            raise FileNotFoundError(
                f"Broken repository link in {relative_to_root(source)}: {target}",
            )

        if resolved in mapping:
            destination = posixpath.relpath(mapping[resolved].as_posix(), output.parent.as_posix())
        else:
            repository_path = relative_to_root(resolved)
            kind = "tree" if resolved.is_dir() else "blob"
            destination = f"{REPOSITORY_URL}/{kind}/{source_ref()}/{repository_path}"

        if parsed.fragment:
            destination += f"#{parsed.fragment}"
        return f"{match.group('prefix')}{destination}{match.group('suffix')}"

    return LINK_PATTERN.sub(replace, text)


def write_page(source: Path, output: Path, mapping: dict[Path, Path], rewrite: bool) -> None:
    source = ensure_inside(source, ROOT)
    repository_path = relative_to_root(source)
    if repository_path.startswith(FORBIDDEN_SOURCE_PREFIXES):
        raise ValueError(f"Forbidden public-site source: {repository_path}")
    text = replace_tokens(source.read_text())
    if repository_path == "swift/README.md":
        text = render_swift_release_section(text)
    if rewrite:
        text = rewrite_links(text, source, output, mapping)
    destination = STAGED_ROOT / output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text)


def first_summary(readme: Path) -> str:
    paragraphs: list[str] = []
    for line in readme.read_text().splitlines()[1:]:
        stripped = line.strip()
        if not stripped:
            if paragraphs:
                break
            continue
        if stripped.startswith(("#", "<!--", "```", "|")):
            if paragraphs:
                break
            continue
        paragraphs.append(stripped)
    return " ".join(paragraphs) or "Published library module."


def write_module_index(modules: list[tuple[Path, Path]]) -> None:
    groups: dict[str, list[tuple[Path, Path]]] = {area: [] for area in PUBLISHED_AREAS}
    for source, output in modules:
        groups[source.relative_to(ROOT).parts[0]].append((source, output))

    lines = [
        "# Artifact catalog",
        "",
        "Start with the recommended mobile or backend setup. Use this catalog when you need to replace a default layer or adopt a lower-level protocol component.",
        "",
        "!!! tip \"Recommended mobile setup\"",
        "    Use `webauthn-client-flow` and `webauthn-client-ktor-kotlinx` in shared code, then `webauthn-client-defaults` in Android and iOS source sets.",
        "",
    ]
    labels = {
        "client": "Mobile and client",
        "core": "Protocol foundation",
        "server": "JVM backend",
        "platform": "Coordinated versions",
    }
    for area in PUBLISHED_AREAS:
        lines.extend([f"## {labels[area]}", ""])
        for source, output in groups[area]:
            name = output.stem
            target = posixpath.relpath(output.as_posix(), "reference")
            lines.extend([f"### [{name}]({target})", "", first_summary(source), ""])
    lines.extend(
        [
            "## Release alignment",
            "",
            "The latest stable coordinated release is **@@STABLE_VERSION@@**. JVM builds can use `webauthn-bom`; Kotlin Multiplatform source sets must keep explicit artifact versions aligned.",
            "",
        ],
    )
    destination = STAGED_ROOT / "reference" / "modules.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(replace_tokens("\n".join(lines)))


def require_number(path: str, pattern: str, label: str) -> str:
    text = (ROOT / path).read_text()
    match = re.search(pattern, text)
    if not match:
        raise ValueError(f"Could not derive {label} from {path}")
    return match.group(1)


def platform_support_values() -> dict[str, str]:
    values = {
        "androidMinSdk": require_number(
            "client/webauthn-client-platform/build.gradle.kts",
            r"minSdk\s*=\s*(\d+)",
            "Android minimum SDK",
        ),
        "androidCompileSdk": require_number(
            "client/webauthn-client-platform/build.gradle.kts",
            r"compileSdk\s*=\s*(\d+)",
            "Android compile SDK",
        ),
        "androidPrfMinSdk": require_number(
            "client/webauthn-client-prf-crypto/build.gradle.kts",
            r"minSdk\s*=\s*(\d+)",
            "Android PRF minimum SDK",
        ),
        "androidPrfCompileSdk": require_number(
            "client/webauthn-client-prf-crypto/build.gradle.kts",
            r"compileSdk\s*=\s*(\d+)",
            "Android PRF compile SDK",
        ),
        "sampleMinSdk": require_number(
            "sample/compose-passkey-android/build.gradle.kts",
            r"minSdk\s*=\s*(\d+)",
            "sample Android minimum SDK",
        ),
        "iosSampleTarget": require_number(
            "sample/compose-passkey-ios/project.yml",
            r'iOS:\s*"(\d+)(?:\.\d+)?"',
            "iOS sample deployment target",
        ),
        "iosPrfMinimum": require_number(
            "client/webauthn-client-platform/src/iosMain/kotlin/dev/webauthn/client/ios/IosAuthorizationBridge.kt",
            r"MIN_PRF_IOS_VERSION\s*=\s*(\d+)",
            "iOS PRF minimum",
        ),
    }
    mismatches = {
        key: {"expected": expected, "actual": values[key]}
        for key, expected in EXPECTED_ANDROID_SUPPORT.items()
        if values[key] != expected
    }
    if mismatches:
        raise ValueError(f"Android support expectations changed; review public documentation: {mismatches}")
    return values


def write_platform_support() -> dict[str, str]:
    values = platform_support_values()
    platform_build = (ROOT / "client/webauthn-client-platform/build.gradle.kts").read_text()
    for target in ("iosArm64()", "iosSimulatorArm64()"):
        if target not in platform_build:
            raise ValueError(f"Missing expected published Apple target: {target}")
    if "iosX64()" in platform_build:
        raise ValueError("Platform support page must be revisited because iosX64 is now published")

    lines = [
        "# Platform support",
        "",
        "These values are generated from the current build and platform bridge sources so the public matrix cannot silently drift.",
        "",
        "| Surface | Current support | Evidence boundary |",
        "| --- | --- | --- |",
        f"| Base Android passkey client | `minSdk {values['androidMinSdk']}`, compiled with SDK {values['androidCompileSdk']} | Compilation and host tests do not prove a provider-backed ceremony |",
        f"| Optional Android PRF crypto | `minSdk {values['androidPrfMinSdk']}`, compiled with SDK {values['androidPrfCompileSdk']} | This optional module has a higher minimum than the base client |",
        f"| Compose PRF sample | `minSdk {values['sampleMinSdk']}` | The sample minimum is not the base library minimum |",
        "| iOS targets | `iosArm64`, `iosSimulatorArm64`; no `iosX64` | Simulator compilation does not prove device entitlements or iCloud Keychain behavior |",
        f"| Committed iOS host | iOS {values['iosSampleTarget']} deployment target | Optional APIs can require newer systems |",
        f"| iOS PRF | iOS {values['iosPrfMinimum']}+ | Runtime capability still must be checked |",
        "",
        "## Runtime prerequisites",
        "",
        "- Android needs a Credential Manager provider, a screen lock, and a passkey-capable device or emulator account.",
        "- Android production association needs a matching package name and signing fingerprint in `/.well-known/assetlinks.json`.",
        "- iOS production association needs Associated Domains and a matching `apple-app-site-association` response.",
        "- Physical-device and provider testing remains necessary before claiming deployment readiness.",
        "",
    ]
    destination = STAGED_ROOT / "reference" / "platform-support.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text("\n".join(lines))
    return values


def copy_assets() -> None:
    if ASSET_ROOT.is_dir():
        shutil.copytree(ASSET_ROOT, STAGED_ROOT / "assets", dirs_exist_ok=True)


def stage() -> None:
    reset_directory(STAGED_ROOT)
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    mapping = source_map()
    staged: list[dict[str, str]] = []

    for source, output in authored_pages():
        write_page(source, output, mapping, rewrite=False)
        staged.append({"source": relative_to_root(source), "output": output.as_posix()})

    modules = published_modules()
    for source, output in modules:
        write_page(source, output, mapping, rewrite=True)
        staged.append({"source": relative_to_root(source), "output": output.as_posix()})

    for source_name, output_name in REPOSITORY_PAGES.items():
        source = ROOT / source_name
        output = Path(output_name)
        write_page(source, output, mapping, rewrite=True)
        staged.append({"source": source_name, "output": output_name})

    write_module_index(modules)
    platform_values = write_platform_support()
    copy_assets()

    report = {
        "sourceRef": source_ref(),
        "stableVersion": latest_stable_version(),
        "swiftReleaseVersion": latest_swift_release_version() or "unreleased",
        "authoredPages": len(authored_pages()),
        "publishedModules": len(modules),
        "stagedSources": staged,
        "platformSupport": platform_values,
    }
    (REPORT_ROOT / "staging.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        f"Public docs staged: {report['authoredPages']} authored pages, "
        f"{report['publishedModules']} published modules",
    )


def install_api() -> None:
    if not (API_ROOT / "index.html").is_file():
        raise FileNotFoundError(f"Missing aggregated Dokka output: {API_ROOT / 'index.html'}")
    destination = SITE_ROOT / "api"
    reset_directory(destination)
    shutil.copytree(API_ROOT, destination, dirs_exist_ok=True)
    remove_omitted_internal_dokka_links(destination)
    print(f"Installed API reference: {destination}")


def remove_omitted_internal_dokka_links(destination: Path) -> None:
    """Render a known internal serializer annotation as text, not a broken public symbol link."""
    link = re.compile(
        r'<a href="(?:\.\./)+core/webauthn-json-kotlinx/dev\.webauthn\.serialization/'
        r'-null-as-empty-credential-descriptor-list-serializer/index\.html">'
        r'NullAsEmptyCredentialDescriptorListSerializer::class</a>',
    )
    replacement = (
        '<span data-omitted-internal-symbol="true">'
        'NullAsEmptyCredentialDescriptorListSerializer::class</span>'
    )
    replacements = 0
    for path in destination.rglob("*.html"):
        content = path.read_text()
        content, count = link.subn(replacement, content)
        if count:
            path.write_text(content)
            replacements += count
    if replacements != 2:
        raise ValueError(
            "Expected two Dokka links to the omitted internal JSON serializer, "
            f"replaced {replacements}",
        )


class AssetParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.targets: list[tuple[str, str]] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(values["id"] or "")
        for attribute in ("href", "src"):
            if values.get(attribute):
                self.targets.append((attribute, values[attribute] or ""))


def parse_html(path: Path) -> AssetParser:
    parser = AssetParser()
    parser.feed(path.read_text(errors="replace"))
    return parser


def resolve_site_target(source: Path, target: str) -> tuple[Path, str]:
    parsed = urlsplit(target)
    if parsed.path.startswith(PAGES_PREFIX):
        relative = parsed.path[len(PAGES_PREFIX) :]
        path = SITE_ROOT / relative
    elif parsed.path.startswith("/"):
        path = SITE_ROOT / parsed.path.lstrip("/")
    else:
        path = source.parent / unquote(parsed.path)
    if not parsed.path:
        path = source
    if path.is_dir() or (not path.suffix and not path.exists()):
        path = path / "index.html"
    return path.resolve(), parsed.fragment


def check_html() -> None:
    if not (SITE_ROOT / "index.html").is_file():
        raise FileNotFoundError(f"Missing built site: {SITE_ROOT / 'index.html'}")
    html_files = sorted(path for path in SITE_ROOT.rglob("*.html") if path.name != "navigation.html")
    parsed_files = {path.resolve(): parse_html(path) for path in html_files}
    failures: list[str] = []
    checked = 0
    for source in html_files:
        unresolved = sorted(set(UNRESOLVED_TOKEN_PATTERN.findall(source.read_text(errors="replace"))))
        for token in unresolved:
            failures.append(f"{source.relative_to(SITE_ROOT)}: unresolved token {token}")
    for source, parser in parsed_files.items():
        for attribute, target in parser.targets:
            parsed = urlsplit(target)
            if parsed.scheme in EXTERNAL_SCHEMES or target.startswith("//"):
                continue
            destination, fragment = resolve_site_target(source, target)
            checked += 1
            if not destination.exists():
                failures.append(f"{source.relative_to(SITE_ROOT)}: missing {attribute} target {target}")
                continue
            if fragment and destination.suffix == ".html":
                target_parser = parsed_files.get(destination)
                if target_parser is None:
                    target_parser = parse_html(destination)
                    parsed_files[destination] = target_parser
                if fragment not in target_parser.ids and unquote(fragment) not in target_parser.ids:
                    failures.append(f"{source.relative_to(SITE_ROOT)}: missing fragment {target}")
    report = {"htmlFiles": len(html_files), "localTargets": checked, "failures": failures}
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    (REPORT_ROOT / "html-links.json").write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        raise ValueError("HTML validation failed:\n" + "\n".join(failures[:50]))
    print(f"HTML validation passed: {len(html_files)} files, {checked} local targets")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage", "install-api", "check-html"))
    args = parser.parse_args()
    if args.command == "stage":
        stage()
    elif args.command == "install-api":
        install_api()
    else:
        check_html()


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Public docs error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
