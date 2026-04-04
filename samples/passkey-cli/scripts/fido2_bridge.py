#!/usr/bin/env python3
"""Minimal python-fido2 bridge for the macOS native CLI POC."""

from __future__ import annotations

import json
import sys
from getpass import getpass
from typing import Any

from fido2.client import DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice
from fido2.webauthn import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


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
    return Fido2Client(
        _first_hid_device(),
        client_data_collector=DefaultClientDataCollector(origin),
        user_interaction=CliInteraction(),
    )


def _register(origin: str, options_payload: dict[str, Any]) -> dict[str, Any]:
    options = PublicKeyCredentialCreationOptions.from_dict(options_payload)
    response = _client(origin).make_credential(options)
    return dict(response)


def _authenticate(origin: str, options_payload: dict[str, Any]) -> dict[str, Any]:
    options = PublicKeyCredentialRequestOptions.from_dict(options_payload)
    assertion_selection = _client(origin).get_assertion(options)
    response = assertion_selection.get_response(0)
    return dict(response)


def _success(payload: dict[str, Any]) -> int:
    print(json.dumps({"ok": True, "response": payload}, separators=(",", ":")))
    return 0


def _failure(message: str) -> int:
    print(json.dumps({"ok": False, "error": message}, separators=(",", ":")), file=sys.stderr)
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
