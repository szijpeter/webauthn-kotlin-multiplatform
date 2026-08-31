#!/usr/bin/env python3
"""Regression tests for path-independent XcodeGen project comparison."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-xcodegen.sh")


def project_fixture(object_id: str, repository_name: str, package_path: str = "../..") -> str:
    declarations = [
        f'\t\t{object_id} /* {repository_name} */ = {{isa = PBXFileReference; lastKnownFileType = folder; name = "{repository_name}"; path = {package_path}; sourceTree = SOURCE_ROOT; }};',
        '\t\tA595FFCB0850464B5FE043E8 /* PasskeyBackendTests.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = PasskeyBackendTests.swift; sourceTree = "<group>"; };',
    ]
    declarations.sort()
    return f"""\
/* Begin PBXFileReference section */
{chr(10).join(declarations)}
/* End PBXFileReference section */
\t\tchildren = (
\t\t\t{object_id} /* {repository_name} */,
\t\t);
"""


class XcodeGenProjectNormalizationTest(unittest.TestCase):
    def normalize(self, contents: str) -> str:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project.pbxproj"
            project.write_text(contents)
            return subprocess.run(
                ["bash", str(SCRIPT), "--normalize-project", str(project)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout

    def test_repository_directory_and_object_identifier_do_not_drift(self) -> None:
        canonical = self.normalize(
            project_fixture("87E6F21FBC75F5714102068D", "webauthn-kotlin-multiplatform")
        )
        worktree = self.normalize(
            project_fixture(
                "C201194EA529405669EAF87E",
                "webauthn-kotlin-multiplatform-swift-sdk",
            )
        )

        self.assertEqual(canonical, worktree)
        self.assertIn("ROOT_PACKAGE_OBJECT_ID /* ROOT_PACKAGE */", canonical)

    def test_real_package_path_drift_remains_visible(self) -> None:
        expected = self.normalize(
            project_fixture("87E6F21FBC75F5714102068D", "webauthn-kotlin-multiplatform")
        )
        drifted = self.normalize(
            project_fixture(
                "C201194EA529405669EAF87E",
                "webauthn-kotlin-multiplatform-swift-sdk",
                package_path="../../wrong",
            )
        )

        self.assertNotEqual(expected, drifted)

    def test_unrelated_project_identifiers_remain_unchanged(self) -> None:
        normalized = self.normalize(
            project_fixture("87E6F21FBC75F5714102068D", "webauthn-kotlin-multiplatform")
        )

        self.assertIn("A595FFCB0850464B5FE043E8 /* PasskeyBackendTests.swift */", normalized)


if __name__ == "__main__":
    unittest.main()
