#!/usr/bin/env python3
"""Minimal python-fido2 bridge for the macOS native CLI POC."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from getpass import getpass
from typing import Any

import fido2.features
from fido2.client import Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.utils import websafe_encode


# Opt-in to python-fido2 JSON mapping that decodes base64url JSON fields to bytes.
fido2.features.webauthn_json_mapping.enabled = True


class CliInteraction(UserInteraction):
    """Prompt interaction handler used by python-fido2."""

    def __init__(self) -> None:
        self._pin: str | None = None

    def prompt_up(self) -> None:
        print("Touch your authenticator device now...", file=sys.stderr)

    def request_pin(self, permissions, rp_id):
        if self._pin is None:
            self._pin = getpass("Enter authenticator PIN (if required): ")
        return self._pin

    def request_uv(self, permissions, rp_id):
        print("User verification required by authenticator.", file=sys.stderr)
        return True


def _first_hid_device():
    devices = list(CtapHidDevice.list_devices())
    if not devices:
        raise RuntimeError("No CTAP HID authenticator detected.")
    return devices[0]


def _client(origin: str) -> Fido2Client:
    device = _first_hid_device()
    interaction = CliInteraction()
    try:
        return Fido2Client(
            device,
            origin=origin,
            user_interaction=interaction,
        )
    except TypeError:
        from fido2.client import DefaultClientDataCollector  # type: ignore

        return Fido2Client(
            device,
            client_data_collector=DefaultClientDataCollector(origin),
            user_interaction=interaction,
        )


def _encode_b64url(value: bytes) -> str:
    return websafe_encode(bytes(value))


def _normalize_extensions(value: Any) -> Any:
    if isinstance(value, bytes):
        return _encode_b64url(value)
    if isinstance(value, Mapping):
        return {k: _normalize_extensions(v) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_normalize_extensions(item) for item in value]
    return value


def _register(origin: str, options_payload: dict[str, Any]) -> dict[str, Any]:
    response = _client(origin).make_credential(options_payload)
    credential_data = response.attestation_object.auth_data.credential_data
    if credential_data is None:
        raise RuntimeError("Credential attestation response did not include credential data.")

    credential_id = credential_data.credential_id
    result: dict[str, Any] = {
        "id": _encode_b64url(credential_id),
        "rawId": _encode_b64url(credential_id),
        "response": {
            "clientDataJSON": _encode_b64url(bytes(response.client_data)),
            "attestationObject": _encode_b64url(bytes(response.attestation_object)),
        },
    }
    extension_results = _normalize_extensions(response.extension_results or {})
    if extension_results:
        result["clientExtensionResults"] = extension_results
    return result


def _authenticate(origin: str, options_payload: dict[str, Any]) -> dict[str, Any]:
    assertion_selection = _client(origin).get_assertion(options_payload)
    response = assertion_selection.get_response(0)

    credential_id = response.credential_id
    if credential_id is None:
        raise RuntimeError("Assertion response did not include credential ID.")

    payload: dict[str, Any] = {
        "id": _encode_b64url(credential_id),
        "rawId": _encode_b64url(credential_id),
        "response": {
            "clientDataJSON": _encode_b64url(bytes(response.client_data)),
            "authenticatorData": _encode_b64url(bytes(response.authenticator_data)),
            "signature": _encode_b64url(bytes(response.signature)),
        },
    }
    if response.user_handle is not None:
        payload["response"]["userHandle"] = _encode_b64url(bytes(response.user_handle))

    extension_results = _normalize_extensions(response.extension_results or {})
    if extension_results:
        payload["clientExtensionResults"] = extension_results
    return payload


def _success(payload: dict[str, Any]) -> int:
    print(json.dumps({"ok": True, "response": payload}, separators=(",", ":")))
    return 0


def _failure(message: str) -> int:
    print(json.dumps({"ok": False, "error": message}, separators=(",", ":")))
    return 1


def main() -> int:
    try:
        request = json.load(sys.stdin)
        command = request["command"]
        origin = request["origin"]
        options = request["options"]

        if command == "register":
            return _success(_register(origin, options))
        if command == "authenticate":
            return _success(_authenticate(origin, options))

        return _failure(f"Unsupported command: {command}")
    except Exception as error:  # noqa: BLE001 - POC bridge returns structured failures.
        return _failure(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
