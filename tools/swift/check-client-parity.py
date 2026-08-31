#!/usr/bin/env python3
"""Validate the reviewed Kotlin client-surface inventory for the Swift SDK."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path
from typing import Any


class ClientParityError(RuntimeError):
    """Raised when the reviewed client-surface inventory is incomplete or stale."""


KLIB_SYMBOL = re.compile(r"\s//\s+(.+\[[0-9]+\])\s*$")
DISPOSITIONS = {"direct", "adapted", "kotlin-specific", "deferred"}


def read(root: Path, path: Path) -> str:
    if not path.is_file():
        try:
            display = path.relative_to(root)
        except ValueError:
            display = path
        raise ClientParityError(f"Missing client parity input: {display}")
    return path.read_text()


def extract_klib_symbols(text: str) -> set[str]:
    symbols: list[str] = []
    for line in text.splitlines():
        match = KLIB_SYMBOL.search(line)
        if match:
            symbols.append(match.group(1))
    if not symbols:
        raise ClientParityError("KLIB API dump contains no stable declaration symbols")
    duplicates = sorted(symbol for symbol, count in Counter(symbols).items() if count > 1)
    if duplicates:
        raise ClientParityError(f"KLIB API dump contains duplicate symbols: {duplicates}")
    return set(symbols)


def declaration_root(symbol: str) -> str:
    declaration = symbol.split("|", 1)[0]
    if "/" not in declaration:
        raise ClientParityError(f"Unsupported KLIB declaration symbol: {symbol}")
    package_name, declaration_name = declaration.split("/", 1)
    top_level_name = declaration_name.split(".", 1)[0]
    return f"{package_name}/{top_level_name}"


def symbol_digest(symbols: set[str]) -> str:
    payload = "".join(f"{symbol}\n" for symbol in sorted(symbols)).encode()
    return hashlib.sha256(payload).hexdigest()


def require_nonempty_string(item: dict[str, Any], key: str, label: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ClientParityError(f"{label} requires a non-empty {key}")
    return value


def repository_path(root: Path, relative_path: str, label: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ClientParityError(f"{label} must be repository-relative: {relative_path}")
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ClientParityError(f"{label} escapes the repository: {relative_path}") from error
    return resolved


def validate_evidence(root: Path, items: Any, label: str) -> None:
    if not isinstance(items, list) or not items:
        raise ClientParityError(f"{label} requires at least one evidence reference")
    for index, item in enumerate(items):
        evidence_label = f"{label}[{index}]"
        if not isinstance(item, dict):
            raise ClientParityError(f"{evidence_label} must be an object")
        relative_path = require_nonempty_string(item, "path", evidence_label)
        evidence_path = repository_path(root, relative_path, evidence_label)
        contents = read(root, evidence_path)
        contains = require_nonempty_string(item, "contains", evidence_label)
        if contains not in contents:
            raise ClientParityError(
                f"Stale evidence reference for {evidence_label}: {relative_path} lacks {contains!r}"
            )


def validate_inventory(root: Path, manifest: dict[str, Any], today: date | None = None) -> None:
    root = root.resolve()
    if manifest.get("schemaVersion") != 2:
        raise ClientParityError("Unsupported client parity inventory schema")
    scope = manifest.get("scope")
    if not isinstance(scope, dict):
        raise ClientParityError("Client parity inventory requires a scope object")
    api_dump_glob = require_nonempty_string(scope, "apiDumpGlob", "Client parity scope")
    if Path(api_dump_glob).is_absolute() or ".." in Path(api_dump_glob).parts:
        raise ClientParityError("Client parity API dump glob must stay within the repository")
    discovered_api_dumps = {
        path.resolve().relative_to(root).as_posix()
        for path in root.glob(api_dump_glob)
        if path.is_file()
    }
    expected_scope_digest = require_nonempty_string(
        scope, "apiDumpPathsSha256", "Client parity scope"
    )
    actual_scope_digest = symbol_digest(discovered_api_dumps)
    if actual_scope_digest != expected_scope_digest:
        raise ClientParityError(
            "Client parity API dump scope drifted; "
            f"expected {expected_scope_digest}, actual {actual_scope_digest}"
        )
    modules = manifest.get("modules")
    if not isinstance(modules, list) or not modules:
        raise ClientParityError("Client parity inventory requires monitored modules")

    swift_interface_values = manifest.get("swiftInterfaces")
    if not isinstance(swift_interface_values, list) or not swift_interface_values:
        raise ClientParityError("Client parity inventory requires Swift interfaces")
    if not all(isinstance(value, str) and value.strip() for value in swift_interface_values):
        raise ClientParityError("Client parity Swift interfaces must be non-empty paths")
    if len(swift_interface_values) != len(set(swift_interface_values)):
        raise ClientParityError("Client parity Swift interfaces contain duplicates")
    swift_interfaces = []
    for index, relative_path in enumerate(swift_interface_values):
        swift_interface_path = repository_path(
            root,
            relative_path,
            f"Client parity Swift interface[{index}]",
        )
        swift_interfaces.append(read(root, swift_interface_path))
    swift_interface = "\n".join(swift_interfaces)
    effective_today = today or date.today()
    seen_modules: set[str] = set()
    reviewed_api_dumps: set[str] = set()
    claimed_swift_symbols: dict[str, str] = {}
    monitored_symbol_count = 0

    for module in modules:
        if not isinstance(module, dict):
            raise ClientParityError("Every monitored module must be an object")
        name = require_nonempty_string(module, "name", "Monitored module")
        if name in seen_modules:
            raise ClientParityError(f"Duplicate monitored module: {name}")
        seen_modules.add(name)
        require_nonempty_string(module, "capability", f"Module {name}")
        api_dump_text = require_nonempty_string(module, "apiDump", f"Module {name}")
        if api_dump_text in reviewed_api_dumps:
            raise ClientParityError(f"Client API dump is claimed twice: {api_dump_text}")
        reviewed_api_dumps.add(api_dump_text)
        api_dump = repository_path(root, api_dump_text, f"Module {name} API dump")
        symbols = extract_klib_symbols(read(root, api_dump))
        monitored_symbol_count += len(symbols)
        symbols_by_root: dict[str, set[str]] = defaultdict(set)
        for symbol in symbols:
            symbols_by_root[declaration_root(symbol)].add(symbol)

        groups = module.get("declarations")
        if not isinstance(groups, list) or not groups:
            raise ClientParityError(f"Module {name} requires declaration dispositions")
        groups_by_root: dict[str, dict[str, Any]] = {}
        for group in groups:
            if not isinstance(group, dict):
                raise ClientParityError(f"Module {name} contains a non-object declaration group")
            kotlin_root = require_nonempty_string(group, "kotlinRoot", f"Module {name} declaration")
            if kotlin_root in groups_by_root:
                raise ClientParityError(
                    f"Two inventory entries claim the same Kotlin declaration root: {kotlin_root}"
                )
            groups_by_root[kotlin_root] = group

        actual_roots = set(symbols_by_root)
        reviewed_roots = set(groups_by_root)
        if actual_roots != reviewed_roots:
            missing = sorted(actual_roots - reviewed_roots)
            stale = sorted(reviewed_roots - actual_roots)
            raise ClientParityError(
                f"Module {name} declaration scope drifted; unmapped={missing}, stale={stale}"
            )

        for kotlin_root, group in groups_by_root.items():
            label = f"Declaration {kotlin_root}"
            disposition = require_nonempty_string(group, "disposition", label)
            if disposition not in DISPOSITIONS:
                raise ClientParityError(
                    f"{label} has unsupported disposition {disposition!r}"
                )
            require_nonempty_string(group, "rationale", label)
            expected_digest = require_nonempty_string(group, "symbolsSha256", label)
            expected_count = group.get("symbolCount")
            if not isinstance(expected_count, int) or expected_count < 1:
                raise ClientParityError(f"{label} requires a positive integer symbolCount")
            actual_count = len(symbols_by_root[kotlin_root])
            if actual_count != expected_count:
                raise ClientParityError(
                    f"{label} ABI declaration count drifted; expected {expected_count}, "
                    f"actual {actual_count}"
                )
            actual_digest = symbol_digest(symbols_by_root[kotlin_root])
            if actual_digest != expected_digest:
                raise ClientParityError(
                    f"{label} ABI declarations drifted; expected {expected_digest}, "
                    f"actual {actual_digest}"
                )

            swift_symbols = group.get("swiftSymbols", [])
            if not isinstance(swift_symbols, list) or not all(
                isinstance(symbol, str) and symbol.strip() for symbol in swift_symbols
            ):
                raise ClientParityError(f"{label} swiftSymbols must be non-empty strings")
            adaptation = group.get("adaptation")
            has_adaptation = isinstance(adaptation, str) and bool(adaptation.strip())
            if disposition == "direct" and not swift_symbols:
                raise ClientParityError(f"{label} direct mapping requires a Swift symbol")
            if disposition == "adapted" and not swift_symbols and not has_adaptation:
                raise ClientParityError(
                    f"{label} adapted mapping requires a Swift symbol or adaptation"
                )
            for swift_symbol in swift_symbols:
                owner = claimed_swift_symbols.get(swift_symbol)
                if owner is not None:
                    raise ClientParityError(
                        f"Swift symbol {swift_symbol!r} is claimed by both {owner} and {kotlin_root}"
                    )
                claimed_swift_symbols[swift_symbol] = kotlin_root
                if swift_symbol not in swift_interface:
                    raise ClientParityError(
                        f"Stale Swift mapping for {kotlin_root}: {swift_symbol!r} is absent"
                    )

            validate_evidence(root, group.get("tests"), f"{label} tests")
            validate_evidence(root, group.get("documentation"), f"{label} documentation")

            if disposition == "deferred":
                require_nonempty_string(group, "owner", label)
                require_nonempty_string(group, "targetPhase", label)
                require_nonempty_string(group, "tracking", label)
                review_by_text = require_nonempty_string(group, "reviewBy", label)
                try:
                    review_by = date.fromisoformat(review_by_text)
                except ValueError as error:
                    raise ClientParityError(
                        f"{label} reviewBy must use YYYY-MM-DD: {review_by_text}"
                    ) from error
                if review_by < effective_today:
                    raise ClientParityError(
                        f"{label} deferral expired on {review_by_text}; review or reclassify it"
                    )

    expected_symbol_count = scope.get("monitoredSymbolCount")
    if not isinstance(expected_symbol_count, int) or expected_symbol_count < 1:
        raise ClientParityError("Client parity scope requires a positive monitoredSymbolCount")
    if monitored_symbol_count != expected_symbol_count:
        raise ClientParityError(
            "Client parity monitored symbol count drifted; "
            f"expected {expected_symbol_count}, actual {monitored_symbol_count}"
        )

    exclusions = scope.get("exclusions")
    if not isinstance(exclusions, list):
        raise ClientParityError("Client parity scope exclusions must be a list")
    for index, exclusion in enumerate(exclusions):
        label = f"Client parity scope exclusion[{index}]"
        if not isinstance(exclusion, dict):
            raise ClientParityError(f"{label} must be an object")
        api_dump_text = require_nonempty_string(exclusion, "apiDump", label)
        if api_dump_text in reviewed_api_dumps:
            raise ClientParityError(f"Client API dump is claimed twice: {api_dump_text}")
        reviewed_api_dumps.add(api_dump_text)
        api_dump = repository_path(root, api_dump_text, f"{label} API dump")
        extract_klib_symbols(read(root, api_dump))
        require_nonempty_string(exclusion, "rationale", label)
        require_nonempty_string(exclusion, "coveredBy", label)
        validate_evidence(root, exclusion.get("tests"), f"{label} tests")
        validate_evidence(root, exclusion.get("documentation"), f"{label} documentation")

    if discovered_api_dumps != reviewed_api_dumps:
        unaccounted = sorted(discovered_api_dumps - reviewed_api_dumps)
        stale = sorted(reviewed_api_dumps - discovered_api_dumps)
        raise ClientParityError(
            f"Client API dump scope is incomplete; unaccounted={unaccounted}, stale={stale}"
        )


def main() -> int:
    default_root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=default_root)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--today", type=date.fromisoformat)
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_path = args.manifest or root / "swift/api/client-surface-parity.json"
    manifest = json.loads(read(root, manifest_path))
    validate_inventory(root, manifest, args.today)
    print("Swift/Kotlin client-surface parity inventory checks passed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ClientParityError, json.JSONDecodeError, KeyError) as error:
        print(f"Swift/Kotlin client-surface parity check failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
