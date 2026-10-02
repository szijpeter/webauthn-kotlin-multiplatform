#!/usr/bin/env python3
"""Negative and parser tests for the complete client-surface parity inventory."""

from __future__ import annotations

import copy
import importlib.util
import tempfile
import unittest
from datetime import date
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-client-parity.py")
SPEC = importlib.util.spec_from_file_location("check_client_parity", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ClientParityCheckerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        (self.root / "client/webauthn-client-example/api").mkdir(parents=True)
        (self.root / "swift").mkdir()
        (self.root / "tests").mkdir()
        (self.root / "docs").mkdir()
        self.api_relative_path = "client/webauthn-client-example/api/example.klib.api"
        self.api_path = self.root / self.api_relative_path
        self.api_path.write_text(
            """// Klib ABI Dump
final class example/Client { // example/Client|null[0]
    final fun operation(): kotlin/String // example/Client.operation|operation(){}[0]
}
"""
        )
        (self.root / "swift/WebAuthn.swiftinterface").write_text(
            "public final class PasskeyClient {}\n"
        )
        (self.root / "tests/ClientTests.swift").write_text("func testOperation() {}\n")
        (self.root / "docs/parity.md").write_text("## Client operations\n")
        symbols = CHECKER.extract_klib_symbols(self.api_path.read_text())
        self.manifest = {
            "schemaVersion": 2,
            "swiftInterfaces": ["swift/WebAuthn.swiftinterface"],
            "scope": {
                "apiDumpGlob": "client/webauthn-client-*/api/*.klib.api",
                "apiDumpPathsSha256": CHECKER.symbol_digest({self.api_relative_path}),
                "monitoredSymbolCount": len(symbols),
                "exclusions": [],
            },
            "modules": [
                {
                    "name": "example-client",
                    "apiDump": self.api_relative_path,
                    "capability": "Example ceremony operations.",
                    "declarations": [
                        {
                            "kotlinRoot": "example/Client",
                            "disposition": "direct",
                            "swiftSymbols": ["public final class PasskeyClient"],
                            "rationale": "The native client exposes the same operation.",
                            "tests": [
                                {
                                    "path": "tests/ClientTests.swift",
                                    "contains": "testOperation",
                                }
                            ],
                            "documentation": [
                                {
                                    "path": "docs/parity.md",
                                    "contains": "## Client operations",
                                }
                            ],
                            "symbolsSha256": CHECKER.symbol_digest(symbols),
                            "symbolCount": len(symbols),
                        }
                    ],
                }
            ],
        }

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def validate(self, manifest: dict | None = None, today: date | None = None) -> None:
        CHECKER.validate_inventory(self.root, manifest or self.manifest, today=today)

    def test_valid_inventory_covers_every_extracted_symbol(self) -> None:
        self.validate()

    def test_new_unmapped_kotlin_operation_is_rejected(self) -> None:
        self.api_path.write_text(
            self.api_path.read_text().replace(
                "\n}\n",
                "\n    final fun added(): kotlin/Unit // example/Client.added|added(){}[0]\n}\n",
            )
        )

        with self.assertRaisesRegex(CHECKER.ClientParityError, "ABI declaration"):
            self.validate()

    def test_new_module_capability_is_rejected(self) -> None:
        self.api_path.write_text(
            self.api_path.read_text()
            + "final class example/Transport { // example/Transport|null[0]\n}\n"
        )

        with self.assertRaisesRegex(CHECKER.ClientParityError, "unmapped=.*Transport"):
            self.validate()

    def test_new_client_api_dump_is_rejected(self) -> None:
        added = self.root / "client/webauthn-client-added/api/added.klib.api"
        added.parent.mkdir(parents=True)
        added.write_text("final class example/Added { // example/Added|null[0]\n}\n")

        with self.assertRaisesRegex(CHECKER.ClientParityError, "API dump scope drifted"):
            self.validate()

    def test_stale_swift_mapping_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["modules"][0]["declarations"][0]["swiftSymbols"] = [
            "public protocol MissingClient"
        ]

        with self.assertRaisesRegex(CHECKER.ClientParityError, "Stale Swift mapping"):
            self.validate(manifest)

    def test_missing_swift_interface_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["swiftInterfaces"] = ["swift/Missing.swiftinterface"]

        with self.assertRaisesRegex(CHECKER.ClientParityError, "Missing client parity input"):
            self.validate(manifest)

    def test_missing_rationale_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["modules"][0]["declarations"][0]["rationale"] = ""

        with self.assertRaisesRegex(CHECKER.ClientParityError, "non-empty rationale"):
            self.validate(manifest)

    def test_two_entries_cannot_claim_the_same_kotlin_declaration(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        duplicate = copy.deepcopy(manifest["modules"][0]["declarations"][0])
        duplicate["swiftSymbols"] = []
        duplicate["disposition"] = "kotlin-specific"
        manifest["modules"][0]["declarations"].append(duplicate)

        with self.assertRaisesRegex(CHECKER.ClientParityError, "same Kotlin declaration root"):
            self.validate(manifest)

    def test_deferred_entry_requires_owner_target_and_tracking(self) -> None:
        for missing_key in ("owner", "targetPhase", "tracking"):
            with self.subTest(missing_key=missing_key):
                manifest = copy.deepcopy(self.manifest)
                declaration = manifest["modules"][0]["declarations"][0]
                declaration.update(
                    {
                        "disposition": "deferred",
                        "swiftSymbols": [],
                        "owner": "Swift SDK maintainers",
                        "targetPhase": "P3",
                        "tracking": "docs/parity.md",
                        "reviewBy": "2027-01-31",
                    }
                )
                declaration.pop(missing_key)

                with self.assertRaisesRegex(CHECKER.ClientParityError, missing_key):
                    self.validate(manifest, today=date(2026, 9, 1))

    def test_expired_deferral_is_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        declaration = manifest["modules"][0]["declarations"][0]
        declaration.update(
            {
                "disposition": "deferred",
                "swiftSymbols": [],
                "owner": "Swift SDK maintainers",
                "targetPhase": "P3",
                "tracking": "docs/parity.md",
                "reviewBy": "2026-08-31",
            }
        )

        with self.assertRaisesRegex(CHECKER.ClientParityError, "deferral expired"):
            self.validate(manifest, today=date(2026, 9, 1))

    def test_missing_test_or_documentation_evidence_is_rejected(self) -> None:
        for key in ("tests", "documentation"):
            with self.subTest(key=key):
                manifest = copy.deepcopy(self.manifest)
                manifest["modules"][0]["declarations"][0][key] = []

                with self.assertRaisesRegex(CHECKER.ClientParityError, "evidence reference"):
                    self.validate(manifest)


if __name__ == "__main__":
    unittest.main()
