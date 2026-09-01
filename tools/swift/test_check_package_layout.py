#!/usr/bin/env python3
"""Negative tests for the reviewed Swift package product topology."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-package-layout.py")
SPEC = importlib.util.spec_from_file_location("check_package_layout", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def dependency(name: str) -> dict[str, list[str | None]]:
    return {"byName": [name, None]}


def valid_manifest() -> dict[str, object]:
    return {
        "name": "WebAuthn",
        "dependencies": [],
        "products": [
            {"name": "WebAuthn", "targets": ["WebAuthn"]},
            {"name": "WebAuthnFlow", "targets": ["WebAuthnFlow"]},
        ],
        "targets": [
            {
                "name": "WebAuthnBridge",
                "type": "binary",
                "path": "artifacts/WebAuthnBridge.xcframework",
                "dependencies": [],
            },
            {
                "name": "WebAuthn",
                "type": "regular",
                "path": "swift/Sources/WebAuthn",
                "dependencies": [dependency("WebAuthnBridge")],
            },
            {
                "name": "WebAuthnFlow",
                "type": "regular",
                "path": "swift/Sources/WebAuthnFlow",
                "dependencies": [dependency("WebAuthn")],
            },
            {
                "name": "WebAuthnTests",
                "type": "test",
                "path": "swift/Tests/WebAuthnTests",
                "dependencies": [dependency("WebAuthn")],
            },
            {
                "name": "WebAuthnFlowTests",
                "type": "test",
                "path": "swift/Tests/WebAuthnFlowTests",
                "dependencies": [dependency("WebAuthnFlow"), dependency("WebAuthn")],
            },
        ],
    }


def target(manifest: dict[str, object], name: str) -> dict[str, object]:
    targets = manifest["targets"]
    assert isinstance(targets, list)
    return next(item for item in targets if isinstance(item, dict) and item.get("name") == name)


class PackageLayoutCheckerTest(unittest.TestCase):
    def test_reviewed_layout_is_accepted(self) -> None:
        layout = CHECKER.validate_package(valid_manifest())
        self.assertEqual(layout["products"], CHECKER.EXPECTED_PRODUCTS)

    def test_checksum_pinned_release_binary_is_accepted(self) -> None:
        manifest = valid_manifest()
        bridge = target(manifest, "WebAuthnBridge")
        bridge.pop("path")
        bridge["url"] = (
            "https://example.invalid/releases/download/v1.2.3/"
            "WebAuthnBridge.xcframework.zip"
        )
        bridge["checksum"] = "a" * 64

        CHECKER.validate_package(manifest)

    def test_unpinned_release_binary_is_rejected(self) -> None:
        manifest = valid_manifest()
        bridge = target(manifest, "WebAuthnBridge")
        bridge.pop("path")
        bridge["url"] = (
            "https://example.invalid/releases/download/v1.2.3/"
            "WebAuthnBridge.xcframework.zip"
        )

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "checksum-pinned remote"):
            CHECKER.validate_package(manifest)

    def test_flow_cannot_leak_into_base_product(self) -> None:
        manifest = valid_manifest()
        products = manifest["products"]
        assert isinstance(products, list)
        products[0]["targets"].append("WebAuthnFlow")

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "product topology drifted"):
            CHECKER.validate_package(manifest)

    def test_base_target_cannot_depend_on_optional_flow(self) -> None:
        manifest = valid_manifest()
        base = target(manifest, "WebAuthn")
        dependencies = base["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.append(dependency("WebAuthnFlow"))

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "WebAuthn dependencies drifted"):
            CHECKER.validate_package(manifest)

    def test_flow_must_depend_on_base_product(self) -> None:
        manifest = valid_manifest()
        target(manifest, "WebAuthnFlow")["dependencies"] = []

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "WebAuthnFlow dependencies drifted"):
            CHECKER.validate_package(manifest)

    def test_base_only_tests_cannot_require_optional_flow(self) -> None:
        manifest = valid_manifest()
        base_tests = target(manifest, "WebAuthnTests")
        dependencies = base_tests["dependencies"]
        assert isinstance(dependencies, list)
        dependencies.append(dependency("WebAuthnFlow"))

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "WebAuthnTests dependencies drifted"):
            CHECKER.validate_package(manifest)

    def test_unreviewed_product_requires_explicit_checker_update(self) -> None:
        manifest = copy.deepcopy(valid_manifest())
        products = manifest["products"]
        targets = manifest["targets"]
        assert isinstance(products, list)
        assert isinstance(targets, list)
        products.append({"name": "Unexpected", "targets": ["Unexpected"]})
        targets.append(
            {
                "name": "Unexpected",
                "type": "regular",
                "path": "swift/Sources/Unexpected",
                "dependencies": [],
            }
        )

        with self.assertRaisesRegex(CHECKER.PackageLayoutError, "product topology drifted"):
            CHECKER.validate_package(manifest)


if __name__ == "__main__":
    unittest.main()
