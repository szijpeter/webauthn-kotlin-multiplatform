# Executed mobile UI checks

The primary showcases are Compose Android, Compose iOS, and native SwiftUI. Both iOS hosts compile
`ShowcaseUITests.swift` from this directory. Android instrumentation exercises the same product states
and adds recreation checks. Rendering fixtures use public example data and never construct a backend,
passkey client, or crypto session.

## Run the checks

Select exactly one Android emulator, or set `WEBAUTHN_ANDROID_TEST_SERIAL` to its `emulator-…` serial.
The fixture driver rejects physical-device targets.

<!-- doc-example: id=sample-mobile-ui-android-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/mobile/check-android-showcase.sh
```

The Compose iOS CI driver selects an available iPhone runtime supported by the selected Xcode SDK.
`WEBAUTHN_IOS_TEST_SIMULATOR` can select an exact simulator. Local Apple work uses XcodeBuildMCP with
an explicit configuration and destination; the driver below is the CI entry point.

<!-- doc-example: id=sample-mobile-ui-compose-ios-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/mobile/check-compose-ios-showcase.sh
```

Native Swift UI execution remains part of the existing package/sample qualification script, alongside
unit tests, Release library evolution, API/parity, consumer, XcodeGen, and XCFramework checks.

<!-- doc-example: id=sample-mobile-ui-swift-ios-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/swift/ci-check.sh
```

## Coverage and evidence

| Journey | Android | Both iOS hosts |
| --- | --- | --- |
| App launch and debug-sheet dismissal | Executed | Executed |
| Busy and terminal action availability | Executed | Executed |
| PRF session/ciphertext control availability | Executed | Executed |
| Configuration and editable-message recreation | Executed | Platform state tests remain separate |
| Large text and reachable configuration | 2× fixture font scale | Largest accessibility Dynamic Type launch setting |
| Pseudolocalized and bidirectional account data | Executed, including RTL layout | Executed, including RTL layout |

Failure screenshots are captured while the app is still open. Android writes into the instrumentation
`additionalTestOutputDir`, which Gradle collects before uninstalling the APK; the driver copies those
outputs into a unique run directory. iOS attaches a `showcase-failure` screenshot to its `.xcresult`.
Fixture CI disables verbose system diagnostics; assertion reports and owned screenshots remain in the result bundle.
Capture and metadata failures never replace a failing test status. Android removes only previous PNG
files in its own fixture screenshot directory before each suite, so an old image cannot impersonate a
new failure.

Results live under `build/mobile-ui/android/`, `build/mobile-ui/compose-ios/`, and
`build/mobile-ui/swift/`. Metadata allowlists revision/dirty state, platform, destination, configuration,
scenario, result, duration, OS/toolchain, and the fixture boundary. No environment dump, response body,
credential, PRF output, key, or plaintext is exported by that writer. CI retains artifacts for seven days.
Fixture screenshots and test reports may include the public synthetic data being tested.

After changing capture, temporarily fail an assertion, verify a useful screenshot and the original
nonzero result, restore the assertion, and rerun. Keep the deliberate failure out of commits. Require
three consecutive clean runs of each enabled route on the final source revision as an initial stability
check; this does not establish a statistical flake rate. The iOS suite waits for a scrolled control's frame
to settle before tapping, because Compose deceleration can continue after XCTest reports the app idle.

## Runtime budget and qualification boundaries

The workflow caps Android UI at 20 runner minutes, Compose iOS compilation/UI at its existing 25 minutes,
and each native Swift qualification lane at its existing 45 minutes. Record actual hosted duration
before making a new route required in branch protection. No protection rule is changed by these scripts.
Revisit the harness if it repeatedly approaches its cap; do not hide a regression with automatic retries.
The Android headless CI route checks phone fixtures. Local rotation and adaptive-window checks require
a demonstrated compatible emulator and remain distinct from headless CI.

These checks establish deterministic presentation and transitions only. Signed app association, provider
support, actual system prompts, biometrics, and PRF behavior require separate attended Android and
physical iPhone runs. See the [Compose readiness checklist](../compose-passkey/READINESS_CHECKLIST.md)
and [native Swift setup](../swift-passkey/README.md). Do not describe these results
as physical-device proof or conformance certification.

## Product decisions

| Candidate | Decision and reopening condition |
| --- | --- |
| Session lifetime | Deliver reproduced clear/late-completion corrections and host cleanup; keep platform prompts usable. |
| Outcome guidance | Deliver category-based safe guidance and privacy tests. A retry starts a new ceremony through the existing actions. |
| Durable encrypted note | Defer the feature until same-credential PRF output is qualified across restart on intended providers and the app-owned storage contract has security review. The [PRF guide](../../docs/site/content/guides/prf.md#durable-encrypted-note-contract) records the contract and failure matrix. |
| Diagnostic export | Defer until a recorded support problem cannot be diagnosed with the existing safe logs. |
| Dependency notices | Retain current static distribution notices and packaging checks. No new runtime dependency is needed. Reassess the resolved notice graph when a dependency or distributed artifact changes. |
| Translation infrastructure | Defer until supported languages and a maintenance owner are defined; deliver text/layout fixtures now. |
| Recovery across credentials | Defer until enrollment, loss, revocation, wrapping, migration, and provider guarantees have a reviewed threat model. |
| Architecture/crypto/DI/database/image/scanner rewrites | Reject for this scope: no independently demonstrated need or measured bottleneck supports them. |

The repository maintainer owns reassessment of deferred items. CI/mobile review applies to the harness;
mobile/security review applies to session lifetime, and storage/recovery require security review.
Each implementation can be reviewed and reverted with its targeted tests; a revert must preserve the
truthful ephemeral-storage and recovery limits.
