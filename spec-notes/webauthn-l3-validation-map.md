# WebAuthn L3 Validation Map

This document maps currently implemented validation behavior to normative requirements.

## Implemented rules

| Rule | Normative source | Implementation | Negative-path test coverage |
|---|---|---|---|
| `clientData.type` must match ceremony (`webauthn.create` for registration, `webauthn.get` for authentication). | W3C WebAuthn Level 3, registration/assertion verification procedures and CollectedClientData processing. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateClientData`) | `clientDataFailsForTypeMismatch`, `validateRegistrationFailsWhenClientDataIsInvalid`, `validateAuthenticationFailsWhenClientDataIsInvalid` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| `clientData.challenge` must exactly match server challenge. | W3C WebAuthn Level 3, registration/assertion verification procedures. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateClientData`) | `clientDataFailsForChallengeMismatch` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| `clientData.origin` must equal expected RP origin. | W3C WebAuthn Level 3, origin verification in ceremony processing. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateClientData`) | `clientDataFailsForOriginMismatch` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| `authenticatorData.rpIdHash` must represent a SHA-256 digest (32 octets). | W3C WebAuthn Level 3, Authenticator Data structure (`rpIdHash`). | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateAuthenticatorData`) | `authenticatorDataFailsForInvalidRpIdHashLength` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| User Presence (UP) flag must be set for processed ceremonies. | W3C WebAuthn Level 3, Authenticator Data flags handling. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateAuthenticatorData`) | `authenticatorDataFailsForMissingUserPresenceFlag` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| Signature counter non-increase is treated as invalid when both prior and current counters are non-zero. | W3C WebAuthn Level 3, Signature Counter guidance. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateAuthenticatorData`) | `authenticatorDataFailsForNonIncreasingSignCount` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| Unpadded base64url input must reject padding and invalid alphabet; impossible unpadded length (`len % 4 == 1`) is rejected. | RFC 4648 (`base64url` alphabet and padding behavior). | `webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlBytes.kt`, `webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlCodec.kt` | `parseRejectsPadding`, `parseRejectsInvalidAlphabetCharacter`, `parseRejectsImpossibleUnpaddedLength`, `parseRejectsWhitespace` in `webauthn-model/src/commonTest/kotlin/dev/webauthn/model/Base64UrlBytesTest.kt` |
| Assertion credential must be in `allowCredentials` if `allowCredentials` is non-empty. | W3C WebAuthn Level 3 assertion verification semantics. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`requireAllowedCredential`) | `requireAllowedCredentialFailsForCredentialOutsideAllowList` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| User Verification (UV) flag must be set when RP policy is `REQUIRED`. | W3C WebAuthn Level 3, Authenticator Data flags and RP UV requirement. | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateAuthenticatorData` with `UserVerificationPolicy`) | `authenticatorDataFailsWhenUvRequiredButNotSet`, `authenticatorDataPassesWhenUvRequiredAndSet`, `authenticatorDataPassesWhenUvPreferredAndNotSet` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| Backup State (BS) flag must not be set when Backup Eligible (BE) flag is clear. | W3C WebAuthn Level 3, Authenticator Data flags (BE/BS semantics). | `webauthn-core/src/commonMain/kotlin/dev/webauthn/core/WebAuthnCoreValidator.kt` (`validateAuthenticatorData`) | `authenticatorDataFailsWhenBackupStateSetWithoutBackupEligible`, `authenticatorDataPassesWhenBackupStateAndEligibleBothSet` in `webauthn-core/src/commonTest/kotlin/dev/webauthn/core/WebAuthnCoreValidatorTest.kt` |
| `authenticatorData.rpIdHash` must match RP ID during registration. | W3C WebAuthn Level 3, registration ceremony verification procedure. | `webauthn-server-core-jvm/src/main/kotlin/dev/webauthn/server/Services.kt` (`RegistrationService.finish`) | `registrationFinishFailsForRpIdHashMismatch` in `webauthn-server-core-jvm/src/test/kotlin/dev/webauthn/server/ServiceSmokeTest.kt` |
| Attestation statement `fmt: "none"` must have empty `attStmt`. | W3C WebAuthn Level 3, §8.7 None Attestation Statement Format. | `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/NoneAttestationStatementVerifier.kt` | `verifyPassesForNoneFmtWithEmptyAttStmt`, `verifyFailsForNoneFmtWithNonEmptyAttStmt`, `verifyFailsForUnsupportedFmt` in `webauthn-server-jvm-crypto/src/test/kotlin/dev/webauthn/server/crypto/NoneAttestationStatementVerifierTest.kt` |

## Positive-path sanity checks

- `clientDataPassesForExactMatch`
- `authenticatorDataAllowsZeroCounterCases`
- `requireAllowedCredentialPassesWhenAllowListIsEmpty`
- `requireAllowedCredentialPassesForCredentialInAllowList`
- `validateRegistrationReturnsCredentialIdAndSignCountForValidInput`
- `validateAuthenticationReturnsCredentialIdAndSignCountForValidInput`
- `roundTripEncodesAndDecodesForMultipleLengths`

## Pending coverage

- Full attestation statement format verification (`packed`, `tpm`, `android-key`, `android-safetynet`, `apple`) with trust path checks
- CBOR/COSE structural parsing against RFC 8949 and RFC 9052/9053 vectors
- Level 3 extension-specific checks (PRF, `largeBlob`, Related Origins)
