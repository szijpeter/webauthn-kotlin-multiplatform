#!/usr/bin/env python3
"""Select an available iPhone runtime supported by the selected Xcode SDK."""
import json
import re
import subprocess

sdk = subprocess.check_output(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-version"], text=True)
sdk_major = int(sdk.split(".")[0])
devices = json.loads(subprocess.check_output(["xcrun", "simctl", "list", "devices", "available", "-j"], text=True))["devices"]
candidates = []
for runtime, entries in devices.items():
    version = re.search(r"iOS-(\d+)-(\d+)", runtime)
    if not version or int(version[1]) > sdk_major:
        continue
    for device in entries:
        if device.get("isAvailable") and device["name"].startswith("iPhone"):
            candidates.append((device.get("state") == "Booted", int(version[1]), int(version[2]), device["udid"]))
if not candidates:
    raise SystemExit("No available iPhone simulator supported by the selected Xcode SDK")
print(max(candidates)[3])
