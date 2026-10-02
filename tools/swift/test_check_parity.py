#!/usr/bin/env python3
"""Negative and parser tests for the Swift/Kotlin parity checker."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


CHECKER_PATH = Path(__file__).with_name("check-parity.py")
SPEC = importlib.util.spec_from_file_location("check_parity", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class ParityCheckerTest(unittest.TestCase):
    def test_kotlin_signature_includes_parameters_defaults_and_result(self) -> None:
        block = """
        public suspend fun authenticate(
            options: Options,
            context: String = DEFAULT_CONTEXT,
        ): PasskeyResult<Result> {
            error("fixture")
        }
        """

        self.assertEqual(
            CHECKER.function_signatures(block, "kotlin"),
            {
                "authenticate": (
                    "public suspend fun authenticate(options: Options, "
                    "context: String = DEFAULT_CONTEXT): PasskeyResult<Result>"
                )
            },
        )

    def test_swift_signature_includes_defaults_async_and_result(self) -> None:
        block = """
        public func authenticate(
            options: Data,
            context: String = defaultContext
        ) async throws -> Result {
            fatalError()
        }
        """

        self.assertEqual(
            CHECKER.function_signatures(block, "swift"),
            {
                "authenticate": (
                    "public func authenticate(options: Data, context: String = defaultContext) "
                    "async throws -> Result"
                )
            },
        )

    def test_signature_mutation_is_rejected(self) -> None:
        expected = [{"name": "capabilities", "swift": "public func capabilities() async throws -> Caps"}]

        with self.assertRaises(CHECKER.ParityError):
            CHECKER.require_signature_contract(
                "Swift client",
                {"capabilities": "public func capabilities() async -> Caps"},
                expected,
                "swift",
            )

    def test_data_object_error_is_discovered(self) -> None:
        source = """
        public sealed interface PasskeyClientError
        public data object UserCancelled : PasskeyClientError
        public data class Platform(val message: String) : PasskeyClientError
        """

        self.assertEqual(CHECKER.kotlin_error_cases(source), {"UserCancelled", "Platform"})

    def test_capability_namespace_is_part_of_identity(self) -> None:
        actual = {("extension", "securityKey"), ("platform", "securityKey")}
        expected = {("extension", "securityKey"), ("platform", "securityKey")}
        CHECKER.require_equal("capabilities", actual, expected)

        with self.assertRaises(CHECKER.ParityError):
            CHECKER.require_equal("capabilities", actual, {("platform", "securityKey")})


if __name__ == "__main__":
    unittest.main()
