# Kotlin unused return value checker decision

Date: 2026-07-22

Issue: [#208](https://github.com/szijpeter/webauthn-kotlin-multiplatform/issues/208)

## Decision

Adopt Kotlin 2.4.10's experimental unused return value checker in `check` mode for every KMP, JVM, and Android compilation. Treat `RETURN_VALUE_NOT_USED` as an error and mark cohesive security-critical API scopes with `@MustUseReturnValues`.

Do not enable `full` mode in regular builds yet. It correctly exposes intentional discards, but it also reports side-effect-oriented and third-party results that are not actionable enough for a repository-wide error policy.

## Audit coverage

Both modes were evaluated with the repository's Kotlin 2.4.10 toolchain. The audit compiled common code through JVM and native consumers, an iOS Simulator ARM64 target, Android KMP targets, and Android debug/library targets.

The one-off `full` audit used:

<!-- doc-example: id=docs-unused-return-value-checker-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew --console=plain --warning-mode=all --rerun-tasks \
  compileKotlinMetadata compileKotlinJvm compileKotlin \
  compileKotlinIosSimulatorArm64 compileAndroidMain \
  compileDebugKotlin compileDebugUnitTestKotlin
```

The final `check` configuration was then compiled directly for the affected model, core, crypto, iOS Simulator ARM64, and Android surfaces before the repository quality gates.

## Diagnostic inventory

The `full` audit produced 11 unique ignored-return sites:

| Category | Count | Example | Classification |
| --- | ---: | --- | --- |
| Likely bugs | 0 | A downstream probe intentionally ignores `validateRegistration(...)` and `SignatureVerifier.verify(...)`; the checker rejects both. | No equivalent ignored security result exists in repository production code. |
| Useful API-safety warnings | 1 | `Base64UrlBytes.parse(...)` discarded the result of `Base64.decode(...)` while validating syntax. | The call is intentional, but the warning made the discard implicit; it is now expressed as `val _ = ...`. |
| Intentional ignored results | 6 | Android Key Attestation parsing discards four version/security-level integers and one unique ID after validating their DER types; `DerParser.skip(...)` discards one parsed header while advancing. | Correct cursor-advancing behavior. These are only noisy in `full` mode. |
| Third-party or side-effect noise | 4 | Exposed store writes ignore the generic `ioTransaction` result when the transaction's final insert/update/delete expression returns a row count. | The public store contract returns `Unit`; the database side effect is the intended outcome. |

The ordinary `check` audit initially reported only the Kotlin standard-library `Base64.decode(...)` discard. After making that discard explicit, the adopted configuration is clean.

## Public API scope review

The following published scopes are marked:

- `WebAuthnCoreValidator` and `WebAuthnExtensionHook`, because every validation result controls whether a ceremony may continue.
- `webauthn-crypto-api/CryptoApi.kt`, covering signature, attestation, trust-anchor, RP-ID hashing, and algorithm conversion results.
- The model files containing typed parsing/construction APIs and `ValidationResult.getOrNull()` / `getOrThrow()`.

Data-only protocol model constructors and side-effect-oriented store APIs remain unmarked. This keeps annotation scope cohesive and avoids pretending the entire repository has completed a `full`-mode migration.

## Downstream consumer and compatibility

`tools/agent/check-published-consumer-smoke.sh` consumes the Maven-local artifacts from a separate Kotlin project with `check` mode enabled. Its normal source must compile cleanly, while a second source intentionally ignores `validateRegistration(...)` and `SignatureVerifier.verify(...)`; compilation must fail with both unused-result diagnostics.

The annotations use binary retention and their callable status is propagated through Kotlin metadata. Kotlin's proposal states that the metadata is backward- and forward-compatible and does not make artifacts pre-release binaries. The change is source-compatible for consumers with the checker disabled; consumers using `check` gain warnings or errors according to their warning policy.

## IDE and CI recommendation

The feature still uses raw compiler options rather than a stable Gradle DSL, and IDE presentation can vary with the installed Kotlin tooling. Compiler diagnostics are therefore the authority. Keeping `check` mode in the shared conventions makes Gradle import and command-line behavior consistent, while the targeted error policy prevents ignored marked results in CI without turning unrelated warnings into errors.

Revisit `full` mode after Kotlin stabilizes the feature and after intentional parser/persistence discards have an agreed repository-wide convention.
