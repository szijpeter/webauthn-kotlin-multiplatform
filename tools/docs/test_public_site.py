#!/usr/bin/env python3
"""Focused tests for the public documentation staging boundary."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
