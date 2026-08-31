#!/usr/bin/env python3
"""Validate the supported Swift package product and target topology."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


class PackageLayoutError(RuntimeError):
    """Raised when a Swift package no longer has the reviewed modular shape."""


EXPECTED_PRODUCTS = {
    "WebAuthn": ("WebAuthn",),
    "WebAuthnFlow": ("WebAuthnFlow",),
}

EXPECTED_TARGETS = {
    "WebAuthnBridge": {
        "type": "binary",
        "artifact": "WebAuthnBridge.xcframework",
        "dependencies": (),
    },
    "WebAuthn": {
        "type": "regular",
        "path": "swift/Sources/WebAuthn",
        "dependencies": ("WebAuthnBridge",),
    },
    "WebAuthnFlow": {
        "type": "regular",
        "path": "swift/Sources/WebAuthnFlow",
        "dependencies": ("WebAuthn",),
    },
    "WebAuthnTests": {
        "type": "test",
        "path": "swift/Tests/WebAuthnTests",
        "dependencies": ("WebAuthn",),
    },
    "WebAuthnFlowTests": {
        "type": "test",
        "path": "swift/Tests/WebAuthnFlowTests",
        "dependencies": ("WebAuthn", "WebAuthnFlow"),
    },
}


def dependency_name(dependency: Any, target_name: str) -> str:
    if not isinstance(dependency, dict) or len(dependency) != 1:
        raise PackageLayoutError(f"Unsupported dependency in target {target_name}: {dependency!r}")
    kind, value = next(iter(dependency.items()))
    if kind not in {"byName", "target"} or not isinstance(value, list) or not value:
        raise PackageLayoutError(f"Unsupported dependency in target {target_name}: {dependency!r}")
    name = value[0]
    if not isinstance(name, str) or not name:
        raise PackageLayoutError(f"Unnamed dependency in target {target_name}")
    return name


def validate_package(manifest: dict[str, Any], label: str = "package") -> dict[str, Any]:
    if manifest.get("name") != "WebAuthn":
        raise PackageLayoutError(f"{label}: expected package name WebAuthn")
    if manifest.get("dependencies") != []:
        raise PackageLayoutError(f"{label}: root package dependencies require explicit review")

    products = manifest.get("products")
    if not isinstance(products, list):
        raise PackageLayoutError(f"{label}: products are missing")
    product_map: dict[str, tuple[str, ...]] = {}
    for product in products:
        if not isinstance(product, dict) or not isinstance(product.get("name"), str):
            raise PackageLayoutError(f"{label}: malformed product declaration")
        name = product["name"]
        targets = product.get("targets")
        if not isinstance(targets, list) or not all(isinstance(item, str) for item in targets):
            raise PackageLayoutError(f"{label}: malformed targets for product {name}")
        if name in product_map:
            raise PackageLayoutError(f"{label}: duplicate product {name}")
        product_map[name] = tuple(targets)
    if product_map != EXPECTED_PRODUCTS:
        raise PackageLayoutError(
            f"{label}: product topology drifted; expected={EXPECTED_PRODUCTS!r}, actual={product_map!r}"
        )

    targets = manifest.get("targets")
    if not isinstance(targets, list):
        raise PackageLayoutError(f"{label}: targets are missing")
    target_map: dict[str, dict[str, Any]] = {}
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("name"), str):
            raise PackageLayoutError(f"{label}: malformed target declaration")
        name = target["name"]
        if name in target_map:
            raise PackageLayoutError(f"{label}: duplicate target {name}")
        target_map[name] = target
    if set(target_map) != set(EXPECTED_TARGETS):
        raise PackageLayoutError(
            f"{label}: target set drifted; expected={sorted(EXPECTED_TARGETS)!r}, "
            f"actual={sorted(target_map)!r}"
        )

    normalized_targets: dict[str, dict[str, Any]] = {}
    for name, expected in EXPECTED_TARGETS.items():
        target = target_map[name]
        actual_type = target.get("type")
        if actual_type != expected["type"]:
            raise PackageLayoutError(
                f"{label}: target {name} type drifted; expected={expected['type']}, actual={actual_type}"
            )
        actual_path = target.get("path")
        expected_path = expected.get("path")
        expected_artifact = expected.get("artifact")
        if expected_path is not None and actual_path != expected_path:
            raise PackageLayoutError(
                f"{label}: target {name} path drifted; expected={expected_path}, actual={actual_path}"
            )
        if expected_artifact is not None:
            actual_url = target.get("url")
            actual_checksum = target.get("checksum")
            local_binary = (
                isinstance(actual_path, str)
                and actual_path.endswith(expected_artifact)
                and actual_url is None
                and actual_checksum is None
            )
            remote_binary = (
                actual_path is None
                and isinstance(actual_url, str)
                and actual_url.endswith(f"/{expected_artifact}.zip")
                and isinstance(actual_checksum, str)
                and len(actual_checksum) == 64
                and all(character in "0123456789abcdef" for character in actual_checksum)
            )
            if not (local_binary or remote_binary):
                raise PackageLayoutError(
                    f"{label}: target {name} must use the reviewed local or checksum-pinned "
                    f"remote {expected_artifact} binary"
                )
        raw_dependencies = target.get("dependencies")
        if not isinstance(raw_dependencies, list):
            raise PackageLayoutError(f"{label}: target {name} dependencies are missing")
        actual_dependencies = tuple(
            sorted(dependency_name(dependency, name) for dependency in raw_dependencies)
        )
        expected_dependencies = tuple(sorted(expected["dependencies"]))
        if actual_dependencies != expected_dependencies:
            raise PackageLayoutError(
                f"{label}: target {name} dependencies drifted; "
                f"expected={expected_dependencies!r}, actual={actual_dependencies!r}"
            )
        normalized_targets[name] = {
            "type": actual_type,
            "path": expected_path or expected_artifact,
            "dependencies": actual_dependencies,
        }

    return {
        "products": product_map,
        "targets": normalized_targets,
    }


def dump_package(package_root: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["swift", "package", "dump-package"],
        cwd=package_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip()
        raise PackageLayoutError(f"{package_root}: swift package dump-package failed: {diagnostic}")
    try:
        manifest = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PackageLayoutError(f"{package_root}: invalid dump-package JSON: {error}") from error
    if not isinstance(manifest, dict):
        raise PackageLayoutError(f"{package_root}: dump-package returned a non-object")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package_roots", nargs="+", type=Path)
    arguments = parser.parse_args()

    reviewed_layout: dict[str, Any] | None = None
    reviewed_root: Path | None = None
    for package_root in arguments.package_roots:
        resolved_root = package_root.resolve()
        layout = validate_package(dump_package(resolved_root), str(resolved_root))
        if reviewed_layout is None:
            reviewed_layout = layout
            reviewed_root = resolved_root
        elif layout != reviewed_layout:
            raise PackageLayoutError(
                f"{resolved_root}: topology differs from reviewed package {reviewed_root}"
            )

    print(
        "Swift package topology is modular: WebAuthnFlow depends on WebAuthn, "
        "and WebAuthn remains independently consumable."
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PackageLayoutError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
