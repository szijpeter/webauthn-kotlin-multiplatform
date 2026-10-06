#!/usr/bin/env python3
"""Write allowlisted fixture metadata; never dump environment or response bodies."""
import argparse
import json
import platform
import subprocess
import time
from pathlib import Path


def output(*command):
    return subprocess.check_output(command, text=True).strip()


parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True)
parser.add_argument("--platform", required=True, choices=["android", "compose-ios", "swift-ios"])
parser.add_argument("--destination", required=True)
parser.add_argument("--status", type=int, required=True)
parser.add_argument("--started-at", type=float)
args = parser.parse_args()
metadata = {
    "schema_version": 1,
    "revision": output("git", "rev-parse", "HEAD"),
    "working_tree_dirty": bool(output("git", "status", "--porcelain")),
    "platform": args.platform,
    "destination": args.destination,
    "configuration": "Debug",
    "scenario": "showcase smoke suite",
    "evidence_kind": "deterministic fixture",
    "expected_result": "all selected tests pass",
    "test_exit_status": args.status,
    "host_os": platform.platform(),
    "provider_evidence": False,
}
if args.started_at is not None:
    metadata["duration_seconds"] = round(time.time() - args.started_at, 2)
try:
    if args.platform == "android":
        metadata["device_os"] = output("adb", "-s", args.destination, "shell", "getprop", "ro.build.version.release")
        metadata["device_sdk"] = output("adb", "-s", args.destination, "shell", "getprop", "ro.build.version.sdk")
        metadata["device_model"] = output("adb", "-s", args.destination, "shell", "getprop", "ro.product.model")
    else:
        metadata["xcode"] = output("xcodebuild", "-version")
        metadata["simulator_sdk"] = output("xcrun", "--sdk", "iphonesimulator", "--show-sdk-version")
        devices = json.loads(output("xcrun", "simctl", "list", "devices", "available", "-j"))["devices"]
        for runtime, entries in devices.items():
            for device in entries:
                if device["udid"] == args.destination:
                    metadata["device_os"] = runtime
                    metadata["device_model"] = device["name"]
except (subprocess.CalledProcessError, OSError, ValueError, KeyError):
    metadata["device_metadata_unavailable"] = True
Path(args.out).write_text(json.dumps(metadata, indent=2) + "\n")
