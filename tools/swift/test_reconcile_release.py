#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from reconcile_release import (
    ARCHIVE_NAME,
    CHECKSUM_NAME,
    ExpectedRelease,
    ReleaseConflict,
    ReleaseSnapshot,
    RepositorySnapshot,
    load_expected,
    plan_reconciliation,
)


SOURCE_COMMIT = "1" * 40
TAG_COMMIT = "2" * 40


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class ReconcileReleaseTests(unittest.TestCase):
    def create_expected(
        self,
        root: Path,
        *,
        physical_device_qualified: bool = True,
        qualification_evidence: str = "https://github.com/example/repository/issues/123",
    ) -> ExpectedRelease:
        archive = b"reviewed-xcframework"
        checksum = digest(archive)
        (root / ARCHIVE_NAME).write_bytes(archive)
        (root / CHECKSUM_NAME).write_text(f"{checksum}\n", encoding="utf-8")
        (root / "Package.swift").write_text(
            "// swift-tools-version: 6.0\n"
            "import PackageDescription\n"
            "let packageURL = (\n"
            "    url: \"https://github.com/szijpeter/webauthn-kotlin-multiplatform/"
            f"releases/download/v1.2.3/{ARCHIVE_NAME}\",\n"
            f"    checksum: \"{checksum}\"\n"
            ")\n"
            "// swiftLanguageModes: [.v6]\n",
            encoding="utf-8",
        )
        (root / "release-notes.md").write_text("Reviewed notes.\n", encoding="utf-8")
        (root / "release-metadata.json").write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "version": "1.2.3",
                    "sourceCommit": SOURCE_COMMIT,
                    "physicalDeviceQualified": physical_device_qualified,
                    "qualificationEvidence": qualification_evidence,
                }
            ),
            encoding="utf-8",
        )
        return load_expected(root)

    def test_physical_device_qualification_is_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ReleaseConflict, "physical-device qualification"):
                self.create_expected(
                    Path(directory),
                    physical_device_qualified=False,
                )

    def test_physical_device_qualification_evidence_is_required(self) -> None:
        for evidence in (
            "",
            "https://",
            "http://example.invalid/evidence",
            "https://example.invalid/bad evidence",
        ):
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ReleaseConflict, "qualification evidence URL"):
                    self.create_expected(
                        Path(directory),
                        qualification_evidence=evidence,
                    )

    def matching_tag(self, expected: ExpectedRelease) -> RepositorySnapshot:
        return RepositorySnapshot(
            tag_commit=TAG_COMMIT,
            tag_parent=SOURCE_COMMIT,
            tag_changed_files=("Package.swift",),
            tag_package_sha256=expected.package_sha256,
        )

    def test_no_release_plans_full_creation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            self.assertEqual(
                plan_reconciliation(RepositorySnapshot(), expected),
                (
                    "create-release-commit-and-tag",
                    "create-draft-release",
                    f"upload:{ARCHIVE_NAME}",
                    f"upload:{CHECKSUM_NAME}",
                    "publish-release",
                ),
            )

    def test_matching_partial_release_repairs_only_missing_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            tag = self.matching_tag(expected)
            snapshot = RepositorySnapshot(
                **{field: getattr(tag, field) for field in (
                    "tag_commit",
                    "tag_parent",
                    "tag_changed_files",
                    "tag_package_sha256",
                )},
                release=ReleaseSnapshot(
                    release_id=7,
                    tag=expected.tag,
                    target_commit=TAG_COMMIT,
                    name=expected.name,
                    body=expected.body,
                    is_draft=True,
                    is_prerelease=False,
                    asset_sha256={ARCHIVE_NAME: expected.asset_sha256[ARCHIVE_NAME]},
                ),
            )
            self.assertEqual(
                plan_reconciliation(snapshot, expected),
                (f"upload:{CHECKSUM_NAME}", "publish-release"),
            )

    def test_conflicting_tag_is_rejected_without_actions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            snapshot = RepositorySnapshot(
                tag_commit=TAG_COMMIT,
                tag_parent="3" * 40,
                tag_changed_files=("Package.swift",),
                tag_package_sha256=expected.package_sha256,
            )
            with self.assertRaisesRegex(ReleaseConflict, "source commit"):
                plan_reconciliation(snapshot, expected)

    def test_matching_published_release_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            tag = self.matching_tag(expected)
            snapshot = RepositorySnapshot(
                **{field: getattr(tag, field) for field in (
                    "tag_commit",
                    "tag_parent",
                    "tag_changed_files",
                    "tag_package_sha256",
                )},
                release=ReleaseSnapshot(
                    release_id=7,
                    tag=expected.tag,
                    target_commit=TAG_COMMIT,
                    name=expected.name,
                    body=expected.body,
                    is_draft=False,
                    is_prerelease=False,
                    asset_sha256=expected.asset_sha256,
                ),
            )
            self.assertEqual(plan_reconciliation(snapshot, expected), ())

    def test_unexpected_asset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            tag = self.matching_tag(expected)
            snapshot = RepositorySnapshot(
                **{field: getattr(tag, field) for field in (
                    "tag_commit",
                    "tag_parent",
                    "tag_changed_files",
                    "tag_package_sha256",
                )},
                release=ReleaseSnapshot(
                    release_id=7,
                    tag=expected.tag,
                    target_commit=TAG_COMMIT,
                    name=expected.name,
                    body=expected.body,
                    is_draft=False,
                    is_prerelease=False,
                    asset_sha256={"unexpected.txt": digest(b"unexpected")},
                ),
            )
            with self.assertRaisesRegex(ReleaseConflict, "unexpected assets"):
                plan_reconciliation(snapshot, expected)

    def test_mismatched_expected_asset_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            expected = self.create_expected(Path(directory))
            tag = self.matching_tag(expected)
            snapshot = RepositorySnapshot(
                **{field: getattr(tag, field) for field in (
                    "tag_commit",
                    "tag_parent",
                    "tag_changed_files",
                    "tag_package_sha256",
                )},
                release=ReleaseSnapshot(
                    release_id=7,
                    tag=expected.tag,
                    target_commit=TAG_COMMIT,
                    name=expected.name,
                    body=expected.body,
                    is_draft=True,
                    is_prerelease=False,
                    asset_sha256={ARCHIVE_NAME: digest(b"different")},
                ),
            )
            with self.assertRaisesRegex(ReleaseConflict, "mismatched assets"):
                plan_reconciliation(snapshot, expected)


if __name__ == "__main__":
    unittest.main()
