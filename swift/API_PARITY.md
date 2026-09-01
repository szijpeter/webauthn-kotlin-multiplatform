# Swift API parity

The native facade intentionally mirrors the stable client capabilities of the Kotlin implementation while
using Swift conventions at the application boundary. Parity means the same supported ceremonies, typed
outcomes, capability semantics, cancellation behavior, and PRF lifecycle guarantees; it does not require
generated Kotlin names or Kotlin-only convenience overloads to appear in Swift.

## Automated contract

`swift/api/parity.json` declares the reviewed cross-language mapping. `tools/swift/check-parity.py` derives
normalized contracts from source and fails when:

- a mapped operation's parameters, order, types, nullability, defaults, result type, async behavior, or
  actor isolation differs between Kotlin, the internal bridge, and Swift;
- any Kotlin `PasskeyClientError` declaration lacks a stable bridge code or Swift case, including class and
  object declaration forms;
- capability support states, every standard WebAuthn extension, known platform capabilities, namespaces,
  or stable identifiers drift;
- high-level PRF authentication or session signatures diverge;
- the reviewed Kotlin/Swift HKDF derivation vector changes;
- a generated bridge type leaks into the public Swift baseline.

The manifest separately lists bridge-only operations, Swift-only boundary failures, and Kotlin-only string
conveniences with a required rationale. These are intentional semantic adaptations, not silent omissions.
`tools/swift/test_check_parity.py` contains negative fixtures proving that signature, error-declaration, and
capability-namespace drift is rejected by the checker itself.

## Reviewed client-surface inventory

`swift/api/client-surface-parity.json` expands the direct semantic contract into a complete reviewed inventory
of the public client surface. It derives 416 stable ABI symbols from the checked-in KLIB API dumps for client
core, flow, JSON, defaults, iOS platform behavior, PRF crypto, Ktor transport, and the default Kotlinx transport
contract. Every top-level declaration root has exactly one disposition:

- `direct`: Swift exposes the same behavior as a named native API;
- `adapted`: Swift preserves the behavior through a deliberately different native shape;
- `kotlin-specific`: the declaration is a Kotlin language, framework, or composition concern;
- `deferred`: the native behavior remains planned and has an owner, target phase, tracking reference, and
  review deadline.

Every ABI symbol inherits the reviewed disposition of its top-level declaration root. Each entry records the
exact symbol count, a signature-sensitive digest, rationale, owning tests, and public documentation. The scope
also accounts for the Compose-only integration module and the internal Swift bridge, with explicit reasons and
independent coverage for excluding them from the consumer-surface inventory.

`tools/swift/check-client-parity.py` fails when a declaration, signature, symbol count, or client API-dump scope
changes without review, a new capability root is unmapped, an entry is duplicated, a referenced Swift symbol or
evidence anchor disappears, or a deferral expires. A count or digest update acknowledges ABI drift; it does not
replace reviewing the disposition, native adaptation, tests, and documentation.

`tools/swift/test_check_client_parity.py` supplies negative fixtures for new operations, new module capabilities,
stale Swift mappings, missing rationales or evidence, duplicate claims, incomplete deferrals, and expired
deferrals.

## Planned native parity work

Application-neutral ceremony orchestration is now mapped through the optional source-only `WebAuthnFlow`
product. It preserves opaque backend state, ceremony phase order, single-operation behavior, cancellation,
backend verification ordering, and application-defined output without taking ownership of UI or persistence.

Optional native transport remains deferred behind a consumer-evidence gate and must not mirror Ktor concepts
merely to make module names match. Deferred entries expire on their recorded review date so these decisions
cannot remain silently unresolved.

## Public testing seam

`PasskeyClientProtocol` is the supported application mocking boundary for registration, authentication, and
capability queries. It is `MainActor`-isolated and `Sendable`; `PasskeyClient` conforms without changing its
construction or runtime behavior. Consumer-style tests import `WebAuthn` without `@testable` and prove that a
native fake can drive all three operations under strict Swift 6 concurrency.

The generated bridge protocols and result types remain package-internal implementation seams. They support
facade unit tests and future interop replacement, but applications must not import or reproduce them. PRF
testing stays separate because its public result owns a crypto session that is intentionally absent from the
basic passkey contract.

## Public API compatibility

`swift/api/WebAuthn.swiftinterface` and `swift/api/WebAuthnFlow.swiftinterface` are generated by the Swift
compiler in library-evolution mode. CI compares each normalized interface with its baseline. Any public
declaration, actor isolation, sendability, default argument, error case, or signature change therefore requires
explicit review.

After an intentional compatible API change, build the Release configuration with
`BUILD_LIBRARY_FOR_DISTRIBUTION=YES`, inspect the interface diff, then update the baseline:

<!-- doc-example: id=swift-api-parity-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
DERIVED_DATA=/path/to/DerivedData
tools/swift/check-api.sh --update "$DERIVED_DATA"
tools/swift/check-parity.py
```

Never update the baseline merely to make CI green. Determine whether the change is source compatible,
whether the coordinated release needs a migration note, and whether the Kotlin surface needs a matching
change first.

## Kotlin change workflow

When a Kotlin client API changes:

1. Run the client-surface inventory check and review every added, removed, or changed KLIB symbol.
2. Update its `direct`, `adapted`, `kotlin-specific`, or `deferred` disposition with current rationale, tests,
   documentation, and any required Swift symbol mapping.
3. Decide whether the behavior belongs in the supported native Swift surface.
4. Add or update a stable primitive bridge contract; do not export project-domain graphs directly.
5. Add the Swift-owned API and typed mapping, preserving cancellation and main-actor rules.
6. Update `swift/api/parity.json` and the relevant Kotlin and Swift behavioral tests.
7. Review the generated Swift interface diff.
8. Run the complete Swift and repository quality gates before merging.

An intentionally Kotlin-only API must be recorded as an explicit parity exception with rationale. The check
must still fail first so the omission cannot happen accidentally.

## Local checks

The macOS check runs Kotlin PRF and bridge tests, XCFramework validation, direct semantic and complete
client-surface parity checks, modular Swift package validation, separate clean UIKit base-only and SwiftUI flow
consumers, Debug tests, a Release library-evolution build, and both API baseline comparisons:

<!-- doc-example: id=swift-api-parity-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/swift/ci-check.sh
```

CI gates compilation and tests with both the minimum supported Xcode 16.4 toolchain and the pinned current
Xcode toolchain. The current toolchain additionally owns the normalized public API baseline comparison.
