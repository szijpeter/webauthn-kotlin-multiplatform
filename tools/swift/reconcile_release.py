#!/usr/bin/env python3
"""Validate and reconcile one coordinated Swift GitHub release.

The planning functions are deliberately independent from GitHub so failure and
recovery states can be tested without publishing anything.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any
from urllib.parse import urlsplit


ARCHIVE_NAME = "WebAuthnBridge.xcframework.zip"
CHECKSUM_NAME = f"{ARCHIVE_NAME}.sha256"
PACKAGE_NAME = "Package.swift"
NOTES_NAME = "release-notes.md"
METADATA_NAME = "release-metadata.json"
EXPECTED_ASSET_NAMES = (ARCHIVE_NAME, CHECKSUM_NAME)
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
CHECKSUM_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ReleaseConflict(RuntimeError):
    """Existing remote state conflicts with the requested release."""


@dataclasses.dataclass(frozen=True)
class ExpectedRelease:
    version: str
    tag: str
    source_commit: str
    package_sha256: str
    name: str
    body: str
    asset_sha256: dict[str, str]
    release_dir: Path


@dataclasses.dataclass(frozen=True)
class ReleaseSnapshot:
    release_id: int
    tag: str
    target_commit: str
    name: str
    body: str
    is_draft: bool
    is_prerelease: bool
    asset_sha256: dict[str, str]


@dataclasses.dataclass(frozen=True)
class RepositorySnapshot:
    tag_commit: str | None = None
    tag_parent: str | None = None
    tag_changed_files: tuple[str, ...] = ()
    tag_package_sha256: str | None = None
    release: ReleaseSnapshot | None = None


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_expected(release_dir: Path) -> ExpectedRelease:
    required = {
        ARCHIVE_NAME,
        CHECKSUM_NAME,
        PACKAGE_NAME,
        NOTES_NAME,
        METADATA_NAME,
    }
    missing = sorted(name for name in required if not (release_dir / name).is_file())
    if missing:
        raise ReleaseConflict(f"Release inputs are missing: {', '.join(missing)}")

    try:
        metadata = json.loads((release_dir / METADATA_NAME).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise ReleaseConflict(f"Invalid {METADATA_NAME}: {error}") from error
    if metadata.get("schemaVersion") != 1:
        raise ReleaseConflict("Release metadata must use schemaVersion 1.")
    version = metadata.get("version")
    source_commit = metadata.get("sourceCommit")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        raise ReleaseConflict("Release metadata contains an invalid version.")
    if not isinstance(source_commit, str) or not COMMIT_PATTERN.fullmatch(source_commit):
        raise ReleaseConflict("Release metadata contains an invalid source commit.")
    if metadata.get("physicalDeviceQualified") is not True:
        raise ReleaseConflict("Swift release metadata lacks physical-device qualification.")
    qualification_evidence = metadata.get("qualificationEvidence")
    evidence_url = urlsplit(qualification_evidence) if isinstance(qualification_evidence, str) else None
    if (
        not isinstance(qualification_evidence, str)
        or evidence_url is None
        or evidence_url.scheme != "https"
        or not evidence_url.netloc
        or qualification_evidence.strip() != qualification_evidence
        or any(character.isspace() for character in qualification_evidence)
    ):
        raise ReleaseConflict(
            "Swift release metadata lacks a valid HTTPS physical-device qualification evidence URL."
        )

    checksum_text = (release_dir / CHECKSUM_NAME).read_text(encoding="utf-8")
    checksum = checksum_text.removesuffix("\n")
    if checksum_text != f"{checksum}\n" or not CHECKSUM_PATTERN.fullmatch(checksum):
        raise ReleaseConflict(f"{CHECKSUM_NAME} must contain one lowercase SHA-256 value.")
    archive_path = release_dir / ARCHIVE_NAME
    if sha256_file(archive_path) != checksum:
        raise ReleaseConflict("Swift release archive does not match its checksum file.")

    package_bytes = (release_dir / PACKAGE_NAME).read_bytes()
    package_text = package_bytes.decode("utf-8")
    expected_url = (
        "https://github.com/szijpeter/webauthn-kotlin-multiplatform/"
        f"releases/download/v{version}/{ARCHIVE_NAME}"
    )
    required_manifest_fragments = (
        "// swift-tools-version: 6.0",
        f'url: "{expected_url}"',
        f'checksum: "{checksum}"',
        "swiftLanguageModes: [.v6]",
    )
    if any(fragment not in package_text for fragment in required_manifest_fragments):
        raise ReleaseConflict("Generated Package.swift does not match the release inputs.")

    notes = (release_dir / NOTES_NAME).read_text(encoding="utf-8")
    if not notes.strip():
        raise ReleaseConflict("Curated release notes must not be empty.")

    return ExpectedRelease(
        version=version,
        tag=f"v{version}",
        source_commit=source_commit,
        package_sha256=sha256_bytes(package_bytes),
        name=f"v{version}",
        body=notes,
        asset_sha256={
            ARCHIVE_NAME: sha256_file(archive_path),
            CHECKSUM_NAME: sha256_file(release_dir / CHECKSUM_NAME),
        },
        release_dir=release_dir,
    )


def _validate_tag(snapshot: RepositorySnapshot, expected: ExpectedRelease) -> None:
    if snapshot.tag_parent != expected.source_commit:
        raise ReleaseConflict("Existing release tag is not parented to the expected source commit.")
    if snapshot.tag_changed_files != (PACKAGE_NAME,):
        raise ReleaseConflict("Existing release tag must change only Package.swift.")
    if snapshot.tag_package_sha256 != expected.package_sha256:
        raise ReleaseConflict("Existing release tag contains a different Package.swift.")


def _validate_release_metadata(
    release: ReleaseSnapshot,
    expected: ExpectedRelease,
    _tag_commit: str,
) -> None:
    if release.tag != expected.tag:
        raise ReleaseConflict("Existing release has a different tag.")
    if release.name != expected.name or release.body != expected.body:
        raise ReleaseConflict("Existing release title or notes differ from curated inputs.")
    if release.is_prerelease:
        raise ReleaseConflict("Existing release is unexpectedly marked as a prerelease.")


def plan_reconciliation(snapshot: RepositorySnapshot, expected: ExpectedRelease) -> tuple[str, ...]:
    """Return the safe actions needed, rejecting every conflicting state."""
    if snapshot.tag_commit is None:
        if snapshot.release is not None:
            raise ReleaseConflict("A release exists without a resolvable release tag.")
        return (
            "create-release-commit-and-tag",
            "create-draft-release",
            *(f"upload:{name}" for name in EXPECTED_ASSET_NAMES),
            "publish-release",
        )

    _validate_tag(snapshot, expected)
    if snapshot.release is None:
        return (
            "create-draft-release",
            *(f"upload:{name}" for name in EXPECTED_ASSET_NAMES),
            "publish-release",
        )

    release = snapshot.release
    _validate_release_metadata(release, expected, snapshot.tag_commit)
    unexpected_assets = sorted(set(release.asset_sha256) - set(EXPECTED_ASSET_NAMES))
    if unexpected_assets:
        raise ReleaseConflict(
            f"Existing release has unexpected assets: {', '.join(unexpected_assets)}"
        )
    mismatched_assets = [
        name
        for name in EXPECTED_ASSET_NAMES
        if name in release.asset_sha256
        and release.asset_sha256[name] != expected.asset_sha256[name]
    ]
    if mismatched_assets:
        raise ReleaseConflict(
            f"Existing release has mismatched assets: {', '.join(mismatched_assets)}"
        )
    actions = [
        f"upload:{name}"
        for name in EXPECTED_ASSET_NAMES
        if name not in release.asset_sha256
    ]
    if release.is_draft:
        actions.append("publish-release")
    return tuple(actions)


class GitHubClient:
    def __init__(self, repository: str, executable: str = "gh") -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ReleaseConflict("GITHUB_REPOSITORY must be an owner/repository pair.")
        self.repository = repository
        self.executable = executable

    def _run(
        self,
        arguments: list[str],
        *,
        input_bytes: bytes | None = None,
        allow_not_found: bool = False,
    ) -> bytes | None:
        completed = subprocess.run(
            [self.executable, *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode == 0:
            return completed.stdout
        stderr = completed.stderr.decode("utf-8", errors="replace")
        if allow_not_found and ("HTTP 404" in stderr or "Not Found" in stderr):
            return None
        raise ReleaseConflict(f"GitHub CLI failed: {stderr.strip()}")

    def api_json(
        self,
        endpoint: str,
        *,
        method: str = "GET",
        body: dict[str, Any] | None = None,
        allow_not_found: bool = False,
    ) -> dict[str, Any] | None:
        arguments = ["api", "--method", method, endpoint]
        input_bytes = None
        if body is not None:
            arguments += ["--input", "-"]
            input_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
        output = self._run(
            arguments,
            input_bytes=input_bytes,
            allow_not_found=allow_not_found,
        )
        if output is None:
            return None
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise ReleaseConflict(f"GitHub returned invalid JSON for {endpoint}.") from error
        if not isinstance(value, dict):
            raise ReleaseConflict(f"GitHub returned an unexpected payload for {endpoint}.")
        return value

    def asset_bytes(self, asset_id: int) -> bytes:
        output = self._run(
            [
                "api",
                "-H",
                "Accept: application/octet-stream",
                f"repos/{self.repository}/releases/assets/{asset_id}",
            ]
        )
        assert output is not None
        return output

    def upload_asset(self, tag: str, path: Path) -> None:
        self._run(
            [
                "release",
                "upload",
                tag,
                str(path),
                "--repo",
                self.repository,
            ]
        )


def collect_snapshot(client: GitHubClient, expected: ExpectedRelease) -> RepositorySnapshot:
    commit = client.api_json(
        f"repos/{client.repository}/commits/{expected.tag}",
        allow_not_found=True,
    )
    tag_commit: str | None = None
    tag_parent: str | None = None
    changed_files: tuple[str, ...] = ()
    package_digest: str | None = None
    if commit is not None:
        tag_commit = str(commit.get("sha", ""))
        git_commit = client.api_json(f"repos/{client.repository}/git/commits/{tag_commit}")
        assert git_commit is not None
        parents = git_commit.get("parents", [])
        if len(parents) != 1:
            raise ReleaseConflict("Release commit must have exactly one parent.")
        tag_parent = str(parents[0].get("sha", ""))
        comparison = client.api_json(
            f"repos/{client.repository}/compare/{expected.source_commit}...{tag_commit}"
        )
        assert comparison is not None
        if comparison.get("ahead_by") != 1 or comparison.get("total_commits") != 1:
            raise ReleaseConflict("Release tag must be exactly one commit ahead of its source.")
        changed_files = tuple(sorted(str(item.get("filename", "")) for item in comparison.get("files", [])))
        content = client.api_json(
            f"repos/{client.repository}/contents/{PACKAGE_NAME}?ref={expected.tag}"
        )
        assert content is not None
        try:
            package_bytes = base64.b64decode(str(content["content"]), validate=False)
        except (KeyError, ValueError) as error:
            raise ReleaseConflict("Unable to decode tagged Package.swift.") from error
        package_digest = sha256_bytes(package_bytes)

    release_json = client.api_json(
        f"repos/{client.repository}/releases/tags/{expected.tag}",
        allow_not_found=True,
    )
    release_snapshot: ReleaseSnapshot | None = None
    if release_json is not None:
        assets: dict[str, str] = {}
        for item in release_json.get("assets", []):
            name = str(item.get("name", ""))
            if name in assets:
                raise ReleaseConflict(f"Release contains duplicate asset name: {name}")
            assets[name] = sha256_bytes(client.asset_bytes(int(item["id"])))
        release_snapshot = ReleaseSnapshot(
            release_id=int(release_json["id"]),
            tag=str(release_json.get("tag_name", "")),
            target_commit=str(release_json.get("target_commitish", "")),
            name=str(release_json.get("name", "")),
            body=str(release_json.get("body", "")),
            is_draft=bool(release_json.get("draft")),
            is_prerelease=bool(release_json.get("prerelease")),
            asset_sha256=assets,
        )
    return RepositorySnapshot(
        tag_commit=tag_commit,
        tag_parent=tag_parent,
        tag_changed_files=changed_files,
        tag_package_sha256=package_digest,
        release=release_snapshot,
    )


def create_release_commit_and_tag(client: GitHubClient, expected: ExpectedRelease) -> None:
    source = client.api_json(
        f"repos/{client.repository}/git/commits/{expected.source_commit}"
    )
    assert source is not None
    package_content = base64.b64encode(
        (expected.release_dir / PACKAGE_NAME).read_bytes()
    ).decode("ascii")
    blob = client.api_json(
        f"repos/{client.repository}/git/blobs",
        method="POST",
        body={"content": package_content, "encoding": "base64"},
    )
    assert blob is not None
    tree = client.api_json(
        f"repos/{client.repository}/git/trees",
        method="POST",
        body={
            "base_tree": source["tree"]["sha"],
            "tree": [
                {
                    "path": PACKAGE_NAME,
                    "mode": "100644",
                    "type": "blob",
                    "sha": blob["sha"],
                }
            ],
        },
    )
    assert tree is not None
    commit = client.api_json(
        f"repos/{client.repository}/git/commits",
        method="POST",
        body={
            "message": f"release: prepare Swift package {expected.tag}",
            "tree": tree["sha"],
            "parents": [expected.source_commit],
        },
    )
    assert commit is not None
    client.api_json(
        f"repos/{client.repository}/git/refs",
        method="POST",
        body={"ref": f"refs/tags/{expected.tag}", "sha": commit["sha"]},
    )


def create_draft_release(
    client: GitHubClient,
    expected: ExpectedRelease,
    tag_commit: str,
) -> None:
    client.api_json(
        f"repos/{client.repository}/releases",
        method="POST",
        body={
            "tag_name": expected.tag,
            "target_commitish": tag_commit,
            "name": expected.name,
            "body": expected.body,
            "draft": True,
            "prerelease": False,
        },
    )


def reconcile(client: GitHubClient, expected: ExpectedRelease) -> None:
    snapshot = collect_snapshot(client, expected)
    actions = plan_reconciliation(snapshot, expected)
    if "create-release-commit-and-tag" in actions:
        create_release_commit_and_tag(client, expected)
        snapshot = collect_snapshot(client, expected)
        _validate_tag(snapshot, expected)
    assert snapshot.tag_commit is not None

    if "create-draft-release" in actions:
        create_draft_release(client, expected, snapshot.tag_commit)
        snapshot = collect_snapshot(client, expected)
    if snapshot.release is None:
        raise ReleaseConflict("GitHub release creation did not produce a readable draft.")
    _validate_release_metadata(snapshot.release, expected, snapshot.tag_commit)

    actions = plan_reconciliation(snapshot, expected)
    for action in actions:
        if action.startswith("upload:"):
            name = action.split(":", 1)[1]
            client.upload_asset(expected.tag, expected.release_dir / name)

    snapshot = collect_snapshot(client, expected)
    actions = plan_reconciliation(snapshot, expected)
    remaining_uploads = [action for action in actions if action.startswith("upload:")]
    if remaining_uploads:
        raise ReleaseConflict("Release asset read-back did not match the prepared inputs.")
    if "publish-release" in actions:
        assert snapshot.release is not None
        client.api_json(
            f"repos/{client.repository}/releases/{snapshot.release.release_id}",
            method="PATCH",
            body={"draft": False},
        )

    final_snapshot = collect_snapshot(client, expected)
    final_actions = plan_reconciliation(final_snapshot, expected)
    if final_actions:
        raise ReleaseConflict(
            f"Release read-back is incomplete: {', '.join(final_actions)}"
        )
    print(
        f"Verified {expected.tag}: exact tag manifest, release metadata, and assets."
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--gh", default=os.environ.get("GH_BIN", "gh"))
    parser.add_argument("--validate-only", action="store_true")
    parser.add_argument("--require-empty", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        expected = load_expected(arguments.release_dir.resolve())
        if arguments.validate_only:
            print(f"Validated Swift release inputs for {expected.tag}.")
            return 0
        if not arguments.repository:
            raise ReleaseConflict("GITHUB_REPOSITORY is required for reconciliation.")
        client = GitHubClient(arguments.repository, arguments.gh)
        if arguments.require_empty:
            snapshot = collect_snapshot(client, expected)
            if snapshot.tag_commit is not None or snapshot.release is not None:
                raise ReleaseConflict(
                    "Release state already exists; use finalize-release with the original workflow artifact."
                )
            print(f"Verified that {expected.tag} has no existing tag or release.")
            return 0
        reconcile(client, expected)
        return 0
    except ReleaseConflict as error:
        print(f"Swift release reconciliation failed: {error}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
