# Status and compatibility

**Last reviewed: 2026-08-31**

The latest stable coordinated release is **@@STABLE_VERSION@@**. The project is pre-1.0: APIs are usable and tested, but source and binary compatibility can change between minor releases with documented migration guidance.

## Evidence vocabulary

| Statement | Meaning |
| --- | --- |
| Published target | An artifact is produced for the named target |
| Compile-tested | A supported source set or consumer fixture compiles |
| Host-tested | Logic runs in JVM/host tests without a real provider |
| Simulator/emulator-tested | Behavior ran in a virtual platform environment |
| Device-tested | A ceremony ran on the recorded physical configuration |
| Production-ready for your app | Your own identity, domain, backend, provider, and policy release gate passed |

Do not infer device or production support from publication alone. Platform APIs, providers, entitlements, signing, association, account state, and backend policy remain part of the system.

## Version alignment

Published artifacts use a coordinated version train. Use the BOM for JVM dependencies and keep explicit KMP
dependency versions aligned. The native Swift package is currently unreleased; its first release will use the
same coordinated number and resolve a checksum-pinned XCFramework from the matching GitHub release. Snapshot
builds track unreleased source and can differ from the latest stable API; the Swift `main` manifest is for
local repository development rather than branch-based consumption.

## Support policy

Security fixes are best-effort for current `main` and the most recent release. Older commits and snapshots are generally unsupported. Read [Security](security.md) before reporting a vulnerability.
