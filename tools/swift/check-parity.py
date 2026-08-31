#!/usr/bin/env python3
"""Check the reviewed semantic contract across Kotlin, bridge, and Swift APIs."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any


class ParityError(RuntimeError):
    """Raised when a reviewed Kotlin/Swift contract drifts."""


def read(root: Path, path: Path) -> str:
    if not path.is_file():
        raise ParityError(f"Missing parity input: {path.relative_to(root)}")
    return path.read_text()


def declaration_block(text: str, marker: str) -> str:
    start = text.find(marker)
    if start < 0:
        raise ParityError(f"Declaration marker not found: {marker}")
    opening = text.find("{", start)
    if opening < 0:
        raise ParityError(f"Declaration body not found: {marker}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index]
    raise ParityError(f"Unbalanced declaration body: {marker}")


def matching_parenthesis(text: str, opening: int) -> int:
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    raise ParityError("Unbalanced function parameter list")


def normalize_signature(signature: str) -> str:
    normalized = re.sub(r"\s+", " ", signature).strip()
    normalized = re.sub(r",\s*\)", ")", normalized)
    normalized = re.sub(r"\(\s+", "(", normalized)
    normalized = re.sub(r"\s+\)", ")", normalized)
    return normalized


def function_signatures(block: str, language: str) -> dict[str, str]:
    if language == "kotlin":
        pattern = re.compile(r"\bpublic\s+(?:suspend\s+)?fun\s+(\w+)\s*\(")
    elif language == "swift":
        pattern = re.compile(r"\bpublic\s+func\s+(\w+)\s*\(")
    else:
        raise ValueError(f"Unsupported language: {language}")

    signatures: dict[str, str] = {}
    for match in pattern.finditer(block):
        name = match.group(1)
        if name in signatures:
            raise ParityError(f"Overloaded {language} function requires an explicit contract key: {name}")
        opening = block.find("(", match.start())
        closing = matching_parenthesis(block, opening)
        end = closing + 1
        suffix = block[end:]
        if language == "kotlin":
            return_match = re.match(r"\s*:\s*([^\n={]+(?:<[^\n={]+>)?)", suffix)
            if return_match:
                end += return_match.end()
        else:
            body = suffix.find("{")
            if body < 0:
                raise ParityError(f"Swift function body not found: {name}")
            end += body
        signatures[name] = normalize_signature(block[match.start() : end])
    return signatures


def enum_cases(block: str) -> set[str]:
    cases: set[str] = set()
    depth = 0
    for line in block.splitlines():
        if depth == 0:
            match = re.match(r"^\s*case\s+(\w+)", line)
            if match:
                cases.add(match.group(1))
        depth += line.count("{") - line.count("}")
    return cases


def kotlin_error_cases(text: str) -> set[str]:
    flattened = " ".join(text.split())
    return set(
        re.findall(
            r"public\s+(?:data\s+)?(?:class|object)\s+(\w+)\b(?:(?!public\s).)*?:\s*PasskeyClientError\b",
            flattened,
        )
    )


def require_equal(label: str, actual: set[Any], expected: set[Any]) -> None:
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ParityError(f"{label} drifted; missing={missing}, unexpected={unexpected}")


def require_signature_contract(
    label: str,
    actual: dict[str, str],
    expected: list[dict[str, str]],
    signature_key: str,
    name_key: str = "name",
) -> None:
    expected_by_name = {item[name_key]: item[signature_key] for item in expected}
    require_equal(f"{label} operations", set(actual), set(expected_by_name))
    for name, signature in expected_by_name.items():
        if actual[name] != signature:
            raise ParityError(
                f"{label} signature drifted for {name}; "
                f"expected={signature!r}, actual={actual[name]!r}"
            )


def require_token(root: Path, path: Path, token: str) -> None:
    if token not in read(root, path):
        raise ParityError(f"Missing token in {path.relative_to(root)}: {token}")


def source_paths(root: Path) -> dict[str, Path]:
    kotlin_client = (
        root
        / "client/webauthn-client-core/src/commonMain/kotlin/dev/webauthn/client/PasskeyClient.kt"
    )
    kotlin_prf_client = (
        root
        / "client/webauthn-client-prf-crypto/src/commonMain/kotlin/dev/webauthn/client/prf/PrfCryptoClient.kt"
    )
    kotlin_bridge = (
        root
        / "client/webauthn-client-swift-bridge/src/iosMain/kotlin/dev/webauthn/client/swift/SwiftPasskeyBridge.kt"
    )
    swift_client = root / "swift/Sources/WebAuthn/PasskeyClient.swift"
    return {
        "kotlin_client": kotlin_client,
        "kotlin_errors": kotlin_client.with_name("PasskeyClientError.kt"),
        "kotlin_capabilities": kotlin_client.with_name("PasskeyCapabilities.kt"),
        "kotlin_capability_types": kotlin_client.with_name("PasskeyCapability.kt"),
        "kotlin_extensions": root
        / "core/webauthn-model/src/commonMain/kotlin/dev/webauthn/model/WebAuthnExtension.kt",
        "kotlin_prf_client": kotlin_prf_client,
        "kotlin_prf": kotlin_prf_client.with_name("PrfCrypto.kt"),
        "kotlin_bridge": kotlin_bridge,
        "kotlin_bridge_models": kotlin_bridge.with_name("SwiftBridgeModels.kt"),
        "swift_client": swift_client,
        "swift_errors": swift_client.with_name("PasskeyClientError.swift"),
        "swift_capabilities": swift_client.with_name("PasskeyCapabilities.swift"),
        "swift_prf_client": swift_client.with_name("PrfCryptoClient.swift"),
        "swift_prf_session": swift_client.with_name("PrfCryptoSession.swift"),
        "swift_api_baseline": root / "swift/api/WebAuthn.swiftinterface",
    }


def actual_contract(root: Path) -> dict[str, Any]:
    paths = source_paths(root)
    return {
        "passkey": {
            "kotlin": function_signatures(
                declaration_block(read(root, paths["kotlin_client"]), "public interface PasskeyClient"),
                "kotlin",
            ),
            "bridge": function_signatures(
                declaration_block(read(root, paths["kotlin_bridge"]), "public class SwiftPasskeyBridge"),
                "kotlin",
            ),
            "swift": function_signatures(
                declaration_block(read(root, paths["swift_client"]), "public final class PasskeyClient"),
                "swift",
            ),
        },
        "prfClient": {
            "kotlin": function_signatures(
                declaration_block(read(root, paths["kotlin_prf_client"]), "public class PrfCryptoClient"),
                "kotlin",
            ),
            "swift": function_signatures(
                declaration_block(read(root, paths["swift_prf_client"]), "public final class PrfCryptoClient"),
                "swift",
            ),
        },
        "prfSession": {
            "kotlin": function_signatures(
                declaration_block(read(root, paths["kotlin_prf"]), "public class PrfCryptoSession"),
                "kotlin",
            ),
            "swift": function_signatures(
                declaration_block(read(root, paths["swift_prf_session"]), "public actor PrfCryptoSession"),
                "swift",
            ),
        },
    }


def validate_capabilities(root: Path, manifest: dict[str, Any], paths: dict[str, Path]) -> None:
    mappings = manifest["capabilityMappings"]
    kotlin_extensions = declaration_block(
        read(root, paths["kotlin_extensions"]),
        "public enum class Standard",
    )
    actual_extensions = {
        (name, identifier)
        for name, identifier in re.findall(
            r'^\s*(\w+)\("([^"]+)"\),?', kotlin_extensions, re.MULTILINE
        )
    }
    expected_extensions = {
        (item["kotlin"], item["id"])
        for item in mappings
        if item["kind"] == "extension"
    }
    require_equal("Kotlin standard extension capabilities", actual_extensions, expected_extensions)

    platform_block = declaration_block(
        read(root, paths["kotlin_capability_types"]),
        "public sealed interface PlatformCapability",
    )
    actual_platform = set(re.findall(r"public\s+(?:data\s+)?object\s+(\w+)", platform_block))
    expected_platform = {
        item["kotlin"] for item in mappings if item["kind"] == "platform"
    }
    require_equal("Kotlin known platform capabilities", actual_platform, expected_platform)

    swift_text = " ".join(read(root, paths["swift_capabilities"]).split())
    bridge_text = " ".join(read(root, paths["kotlin_bridge_models"]).split())
    require_token(root, paths["kotlin_bridge_models"], 'is PasskeyCapability.Extension -> "extension"')
    require_token(root, paths["kotlin_bridge_models"], 'is PasskeyCapability.Platform -> "platform"')
    for item in mappings:
        swift_static = item.get("swiftStatic")
        if swift_static:
            swift_kind = "webAuthnExtension" if item["kind"] == "extension" else "platform"
            token = (
                f'static let {swift_static} = PasskeyCapability(kind: .{swift_kind}, id: "{item["id"]}")'
            )
            if token not in swift_text:
                raise ParityError(f"Swift capability mapping drifted: {item['kind']}:{item['id']}")
        if item["kind"] == "platform":
            token = f'{item["kotlin"]} -> "{item["id"]}"'
            if token not in bridge_text:
                raise ParityError(f"Kotlin platform capability mapping drifted: {item['id']}")


def validate(root: Path, manifest_path: Path) -> None:
    paths = source_paths(root)
    manifest = json.loads(read(root, manifest_path))
    if manifest.get("schemaVersion") != 2:
        raise ParityError("Unsupported Swift parity manifest schema")

    contracts = actual_contract(root)
    passkey = manifest["contracts"]["passkeyOperations"]
    require_signature_contract("Kotlin PasskeyClient", contracts["passkey"]["kotlin"], passkey, "kotlin")
    require_signature_contract("Swift PasskeyClient", contracts["passkey"]["swift"], passkey, "swift")
    bridge_expected = passkey + manifest["contracts"]["bridgeOnlyOperations"]
    require_signature_contract("Kotlin Swift bridge", contracts["passkey"]["bridge"], bridge_expected, "bridge")

    prf_client = manifest["contracts"]["prfClient"]
    require_signature_contract(
        "Kotlin high-level PRF client",
        contracts["prfClient"]["kotlin"],
        prf_client,
        "kotlin",
        "kotlinName",
    )
    require_signature_contract(
        "Swift high-level PRF client",
        contracts["prfClient"]["swift"],
        prf_client,
        "swift",
        "swiftName",
    )

    prf_session = manifest["contracts"]["prfSession"]
    kotlin_session_expected = prf_session + manifest["contracts"]["kotlinOnlySessionConveniences"]
    require_signature_contract(
        "Kotlin PRF session",
        contracts["prfSession"]["kotlin"],
        kotlin_session_expected,
        "kotlin",
        "kotlinName",
    )
    require_signature_contract(
        "Swift PRF session",
        contracts["prfSession"]["swift"],
        prf_session,
        "swift",
        "swiftName",
    )

    require_token(root, paths["swift_client"], "@MainActor\npublic final class PasskeyClient")
    require_token(root, paths["swift_prf_client"], "@MainActor\npublic final class PrfCryptoClient")
    require_token(root, paths["swift_prf_session"], "public actor PrfCryptoSession")

    error_mappings = manifest["errorMappings"]
    kotlin_errors = kotlin_error_cases(read(root, paths["kotlin_errors"]))
    require_equal("Kotlin PasskeyClientError cases", kotlin_errors, {item["kotlin"] for item in error_mappings})
    swift_error_block = declaration_block(read(root, paths["swift_errors"]), "public enum PasskeyClientError")
    require_equal(
        "Swift PasskeyClientError cases",
        enum_cases(swift_error_block),
        {item["swift"] for item in error_mappings} | set(manifest["swiftBoundaryErrors"]),
    )

    kotlin_mapping_text = " ".join(read(root, paths["kotlin_bridge_models"]).split())
    swift_mapping_text = " ".join(read(root, paths["swift_errors"]).split())
    for item in error_mappings:
        kotlin_token = (
            f'is PasskeyClientError.{item["kotlin"]} -> '
            f'SwiftBridgeFailure("{item["code"]}", message)'
        )
        if kotlin_token not in kotlin_mapping_text:
            raise ParityError(f"Kotlin-to-bridge error mapping drifted: {item['code']}")
        swift_pattern = (
            rf'case "{re.escape(item["code"])}":'
            rf'(?:(?!case ").)*return \.{re.escape(item["swift"])}\b'
        )
        if not re.search(swift_pattern, swift_mapping_text):
            raise ParityError(f"Bridge-to-Swift error mapping drifted: {item['code']}")

    bridge_source = "\n".join(
        path.read_text()
        for path in paths["kotlin_bridge"].parent.glob("*.kt")
    )
    produced_codes = set(re.findall(r'SwiftBridgeFailure\("([^"]+)"', bridge_source))
    produced_codes.update(
        re.findall(r'(?:failure|prfFailure)\(\s*(?:code\s*=\s*)?"([^"]+)"', bridge_source)
    )
    expected_codes = {item["code"] for item in error_mappings} | set(manifest["bridgeBoundaryCodes"])
    require_equal("Produced bridge error codes", produced_codes, expected_codes)

    support_mappings = manifest["capabilitySupportMappings"]
    kotlin_support = declaration_block(
        read(root, paths["kotlin_capabilities"]),
        "public enum class CapabilitySupport",
    )
    swift_support = declaration_block(
        read(root, paths["swift_capabilities"]),
        "public enum CapabilitySupport",
    )
    require_equal(
        "Kotlin capability support cases",
        set(re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s*,?\s*$", kotlin_support, re.MULTILINE)),
        set(support_mappings),
    )
    require_equal("Swift capability support cases", enum_cases(swift_support), set(support_mappings.values()))
    for kotlin_case, swift_case in support_mappings.items():
        require_token(
            root,
            paths["kotlin_bridge_models"],
            f'CapabilitySupport.{kotlin_case} -> "{swift_case}"',
        )
    validate_capabilities(root, manifest, paths)

    exceptions = manifest["exceptions"]
    if len({item["id"] for item in exceptions}) != len(exceptions):
        raise ParityError("Parity exception IDs must be unique")
    for item in exceptions:
        if not item["rationale"].strip():
            raise ParityError(f"Parity exception requires a rationale: {item['id']}")

    vector = manifest["prfDerivationVector"]
    input_key_material = bytes.fromhex(vector["prfOutputHex"])
    salt = bytes.fromhex(vector["hkdfSaltHex"])
    context = vector["context"].encode()
    pseudorandom_key = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    derived_key = hmac.new(pseudorandom_key, context + b"\x01", hashlib.sha256).digest()
    if derived_key.hex() != vector["derivedKeyHex"]:
        raise ParityError("PRF HKDF derivation vector drifted")
    fingerprint = hashlib.sha256(derived_key).digest()[:8].hex()
    if fingerprint != vector["keyFingerprint"]:
        raise ParityError("PRF key fingerprint vector drifted")

    baseline = paths["swift_api_baseline"]
    if baseline.is_file():
        leaking_lines = [
            line
            for line in read(root, baseline).splitlines()
            if "WebAuthnBridge." in line and not line.lstrip().startswith("//")
        ]
        if leaking_lines:
            raise ParityError("Generated Kotlin bridge types leaked into the public Swift API baseline")


def main() -> int:
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--dump-contract", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = args.manifest or root / "swift/api/parity.json"
    if args.dump_contract:
        print(json.dumps(actual_contract(root), indent=2, sort_keys=True))
        return 0
    validate(root, manifest)
    print("Swift/Kotlin semantic parity checks passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (json.JSONDecodeError, KeyError, ParityError) as error:
        print(f"Swift/Kotlin semantic parity check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
