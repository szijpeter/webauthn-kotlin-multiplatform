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
