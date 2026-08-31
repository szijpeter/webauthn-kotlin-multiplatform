#!/usr/bin/env python3
"""Focused tests for the public documentation staging boundary."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).with_name("public_site.py")
SPEC = importlib.util.spec_from_file_location("public_site", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {SCRIPT}")
public_site = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_site)


class PublicSiteTest(unittest.TestCase):
    def test_published_catalog_includes_every_release_artifact(self) -> None:
        modules = public_site.published_modules()
        outputs = {output.as_posix() for _, output in modules}

        self.assertEqual(23, len(modules))
        self.assertIn("reference/modules/webauthn-bom.md", outputs)
        self.assertTrue(all(source.name == "README.md" for source, _ in modules))

    def test_source_map_does_not_admit_forbidden_areas(self) -> None:
        repository_sources = {
            public_site.relative_to_root(source)
            for source in public_site.source_map()
        }

        self.assertFalse(
            any(
                source.startswith(public_site.FORBIDDEN_SOURCE_PREFIXES)
                for source in repository_sources
            ),
        )

    def test_containment_rejects_parent_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "public"
            root.mkdir()

            with self.assertRaisesRegex(ValueError, "escapes allowed root"):
                public_site.ensure_inside(root.parent / "private.md", root)

    def test_containment_rejects_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "public"
            outside = base / "private"
            root.mkdir()
            outside.mkdir()
            link = root / "linked-private"
            link.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "escapes allowed root"):
                public_site.ensure_inside(link / "secret.md", root)

    def test_token_replacement_uses_latest_stable_artifact_version(self) -> None:
        stable_version = public_site.latest_stable_version()
        rendered = public_site.replace_tokens(
            "release=@@STABLE_VERSION@@ artifact=@@ARTIFACT_VERSION@@ coordinate=<version>",
        )

        artifact_version = stable_version.removeprefix("v")
        self.assertEqual(
            f"release={stable_version} artifact={artifact_version} coordinate={artifact_version}",
            rendered,
        )

    def test_kotlin_release_manifest_does_not_qualify_as_swift_release(self) -> None:
        self.assertFalse(
            public_site.is_swift_release_manifest(
                "v0.4.0",
                "// swift-tools-version: 6.0\n.binaryTarget(name: \"local\", path: \"local\")",
            ),
        )

    def test_remote_binary_manifest_qualifies_as_swift_release(self) -> None:
        checksum = "a" * 64
        manifest = f"""// swift-tools-version: 6.0
.binaryTarget(
    name: "WebAuthnBridge",
    url: "{public_site.REPOSITORY_URL}/releases/download/v1.2.3/WebAuthnBridge.xcframework.zip",
    checksum: "{checksum}"
)
.target(name: "WebAuthn", path: "swift/Sources/WebAuthn")
.target(name: "WebAuthnFlow", path: "swift/Sources/WebAuthnFlow")
// swiftLanguageModes: [.v6]
"""

        self.assertTrue(public_site.is_swift_release_manifest("v1.2.3", manifest))

    def test_published_swift_assets_must_match_manifest_checksum(self) -> None:
        tag = "v1.2.3"
        checksum = "a" * 64
        archive_url = (
            f"{public_site.REPOSITORY_URL}/releases/download/{tag}/"
            f"{public_site.SWIFT_ARCHIVE_NAME}"
        )
        release = {
            "tag_name": tag,
            "draft": False,
            "prerelease": False,
            "assets": [
                {
                    "name": public_site.SWIFT_ARCHIVE_NAME,
                    "state": "uploaded",
                    "size": 1024,
                    "browser_download_url": archive_url,
                    "digest": f"sha256:{checksum}",
                },
                {
                    "name": public_site.SWIFT_CHECKSUM_NAME,
                    "state": "uploaded",
                    "size": 65,
                    "browser_download_url": f"{archive_url}.sha256",
                },
            ],
        }

        self.assertTrue(
            public_site.github_release_has_swift_assets(
                tag,
                checksum,
                fetch_json=lambda _: release,
                fetch_bytes=lambda _: f"{checksum}\n".encode(),
            ),
        )
        self.assertFalse(
            public_site.github_release_has_swift_assets(
                tag,
                checksum,
                fetch_json=lambda _: release,
                fetch_bytes=lambda _: f"{'b' * 64}\n".encode(),
            ),
        )

    def test_swift_release_rejects_partial_or_unexpected_asset_sets(self) -> None:
        tag = "v1.2.3"
        checksum = "a" * 64
        archive_url = (
            f"{public_site.REPOSITORY_URL}/releases/download/{tag}/"
            f"{public_site.SWIFT_ARCHIVE_NAME}"
        )
        archive = {
            "name": public_site.SWIFT_ARCHIVE_NAME,
            "state": "uploaded",
            "size": 1024,
            "browser_download_url": archive_url,
        }
        checksum_asset = {
            "name": public_site.SWIFT_CHECKSUM_NAME,
            "state": "uploaded",
            "size": 65,
            "browser_download_url": f"{archive_url}.sha256",
        }

        for name, assets in (
            ("missing checksum", [archive]),
            ("missing archive digest", [archive, checksum_asset]),
            ("unexpected asset", [archive, checksum_asset, {"name": "extra.zip"}]),
        ):
            with self.subTest(name=name):
                self.assertFalse(
                    public_site.github_release_has_swift_assets(
                        tag,
                        checksum,
                        fetch_json=lambda _, value=assets: {
                            "tag_name": tag,
                            "draft": False,
                            "prerelease": False,
                            "assets": value,
                        },
                        fetch_bytes=lambda _: f"{checksum}\n".encode(),
                    ),
                )

    def test_latest_swift_release_requires_published_remote_assets(self) -> None:
        checksum = "a" * 64
        manifest = f"""// swift-tools-version: 6.0
.binaryTarget(
    name: "WebAuthnBridge",
    url: "{public_site.REPOSITORY_URL}/releases/download/v1.2.3/WebAuthnBridge.xcframework.zip",
    checksum: "{checksum}"
)
.target(name: "WebAuthn", path: "swift/Sources/WebAuthn")
.target(name: "WebAuthnFlow", path: "swift/Sources/WebAuthnFlow")
// swiftLanguageModes: [.v6]
"""
        manifest_result = public_site.subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=manifest,
            stderr="",
        )
        source_result = public_site.subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout="",
            stderr="",
        )

        for remote_assets_exist, expected in ((False, None), (True, "v1.2.3")):
            with self.subTest(remote_assets_exist=remote_assets_exist):
                public_site.latest_swift_release_version.cache_clear()
                with (
                    mock.patch.object(public_site, "run", return_value="v1.2.3"),
                    mock.patch.object(
                        public_site.subprocess,
                        "run",
                        side_effect=[manifest_result, source_result],
                    ),
                    mock.patch.object(
                        public_site,
                        "github_release_has_swift_assets",
                        return_value=remote_assets_exist,
                    ),
                ):
                    self.assertEqual(expected, public_site.latest_swift_release_version())
        public_site.latest_swift_release_version.cache_clear()

    def test_unreleased_swift_docs_suppress_dependency_snippet(self) -> None:
        source = (
            "before\n<!-- public-site:swift-release:start -->\n"
            "stale\n<!-- public-site:swift-release:end -->\nafter\n"
        )
        rendered = public_site.render_swift_release_section(source, tag=None)

        self.assertIn("has not been released yet", rendered)
        self.assertNotIn(".package(", rendered)

    def test_qualifying_swift_release_renders_exact_version(self) -> None:
        source = (
            "<!-- public-site:swift-release:start -->\n"
            "unreleased\n<!-- public-site:swift-release:end -->"
        )
        rendered = public_site.render_swift_release_section(source, tag="v1.2.3")

        self.assertIn('exact: "1.2.3"', rendered)
        self.assertNotIn("<version>", rendered)

    def test_platform_support_values_keep_base_and_prf_minimums_distinct(self) -> None:
        values = public_site.platform_support_values()

        self.assertEqual("26", values["androidMinSdk"])
        self.assertEqual("37", values["androidCompileSdk"])
        self.assertEqual("30", values["androidPrfMinSdk"])
        self.assertEqual("37", values["androidPrfCompileSdk"])
        self.assertEqual("30", values["sampleMinSdk"])

    def test_dokka_omitted_link_matches_different_relative_depths(self) -> None:
        suffix = (
            "core/webauthn-json-kotlinx/dev.webauthn.serialization/"
            "-null-as-empty-credential-descriptor-list-serializer/index.html"
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary)
            first = destination / "first.html"
            second = destination / "nested" / "second.html"
            second.parent.mkdir()
            first.write_text(
                f'<a href="../../{suffix}">NullAsEmptyCredentialDescriptorListSerializer::class</a>',
            )
            second.write_text(
                f'<a href="../../../../../{suffix}">NullAsEmptyCredentialDescriptorListSerializer::class</a>',
            )

            public_site.remove_omitted_internal_dokka_links(destination)

            self.assertIn('data-omitted-internal-symbol="true"', first.read_text())
            self.assertIn('data-omitted-internal-symbol="true"', second.read_text())

    def test_html_check_rejects_unresolved_release_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            site_root = base / "site"
            report_root = base / "reports"
            site_root.mkdir()
            (site_root / "index.html").write_text("<html><body>@@STABLE_VERSION@@</body></html>")

            with (
                mock.patch.object(public_site, "SITE_ROOT", site_root),
                mock.patch.object(public_site, "REPORT_ROOT", report_root),
                self.assertRaisesRegex(ValueError, "unresolved token @@STABLE_VERSION@@"),
            ):
                public_site.check_html()


if __name__ == "__main__":
    unittest.main(verbosity=2)
