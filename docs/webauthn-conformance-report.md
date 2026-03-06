# Conformance & Conceptual Comparison Report

This report evaluates the conceptual standing of the `webauthn-kotlin-multiplatform` library relative to established passkey ecosystems, assessing design decisions, adherence to W3C WebAuthn standards, and architectural alignment.

## 1. Ecosystem Implementations Considered

- **webauthn4j**
  - **Environment**: Java / Kotlin JVM (Heavy Spring Boot integration focus).
  - **Paradigm**: Highly Object-Oriented, mutable builder-heavy, tightly coupled to Jackson. Extensive internal class hierarchies for attestation parsing.
- **twilio-passkeys (react-native-passkey base)**
  - **Environment**: React Native, iOS (Swift), Android (Kotlin).
  - **Paradigm**: Bridging standard W3C JSON structures back to native OS APIs. Mostly concerned with translation and serialization rather than deep spec enforcement.
- **SimpleWebAuthn (TypeScript)**
  - **Environment**: Node.js & Browser JS.
  - **Paradigm**: Functional validation, lightweight DTOs, direct adherence to the W3C spec naming conventions. Very close to the metal of the WebAuthn standard regarding type definitions.

## 2. Conceptual Comparison

### 2.1. Serialization and Data Modeling
- **webauthn4j** handles all serialization via Jackson mix-ins and complex polymorphic deserializers implicitly tied to the validation logic.
- **SimpleWebAuthn** relies entirely on native JSON/CBOR handling in JS, keeping type defs purely as interfaces.
- **Our Approach (webauthn-kotlin-multiplatform)** distinguishes tightly between internal domain models (`webauthn-model`) and Data Transfer Objects (`webauthn-serialization-kotlinx`). This provides a cleaner separation of concerns than webauthn4j, ensuring that changes to standard external representations don't corrupt internal evaluation logic, aligning closer to SimpleWebAuthn's strict type safety but backed by Kotlin multiplatform capabilities.

### 2.2. Validation Logic
- **webauthn4j** utilizes a monolithic `WebAuthnManager` that parses, validates, and evaluates attestation paths almost concurrently.
- **webauthn-kotlin-multiplatform** isolates validation into pure functional layers (`WebAuthnCoreValidator`). This enforces strict adherence to WebAuthn L3 rules (like `Origin`, `challenge`, `rpIdHash`, `userPresence`, `userVerification`) without side effects. Our `webauthn-l3-validation-map.md` heavily proves that this pure functional separation guarantees correct rule application per the spec.

### 2.3. Extension Processing
- Like most implementations (including webauthn4j and SimpleWebAuthn), our implementation supports `prf` and `largeBlob`. By isolating extension processing into `WebAuthnExtensionValidator`, our library scales smoothly into future WebAuthn extensions without diluting core authentication/registration logic.

### 2.4. Attestation Processing
- **Our Approach**: `webauthn-server-jvm-crypto` modularizes statement verification (`AndroidKey`, `Apple`, `Packed`, etc.) using explicit, injected strategies (`FidoU2fAttestationStatementVerifier`, `AndroidSafetyNetAttestationStatementVerifier`, etc.). This model is easier to audit for specific cryptography bugs than monolithic parsers and strongly mirrors the explicit specification sections (e.g., W3C §8.8 for Apple Attestation).

### 2.5. Client Execution
- Instead of just raw bridging like React Native libraries (which often just inject JS into WebViews or blind-pass JSON strings to native SDKs), `PasskeyClient` acts as an orchestrated, typed KMP client bridging typed models down to `Credential Manager` (Android) and `ASAuthorizationController` (iOS).

## 3. Conformance Gaps & Findings

Based on current documentation (`webauthn-l3-validation-map.md`) and standard mappings:
1. **Core Verification**: The implementation strongly adheres to WebAuthn Level 3 normative verification procedures for both Registration and Assertion.
2. **Missing Features**:
   - ECDAA attestation logic is explicitly rejected (correct for L3, but notable).
   - Enterprise attestation pathways (e.g., `devicePubKey` extension validation) are not yet implemented.
3. **Naming Convention Alignment**: The use of Kotlin Multiplatform forces slight deviations from pure JS syntax (e.g., working heavily with `Base64UrlBytes` instead of JS `ArrayBuffer`), but conceptually maps directly to W3C dictionary types.

## 4. Conclusion
`webauthn-kotlin-multiplatform` sits ideally between the raw, pure functional nature of TypeScript libraries (`SimpleWebAuthn`) and the heavy, enterprise stability of JVM libraries (`webauthn4j`), making it an excellent bridge for full-stack Kotlin development. The strict separation of models, DTOs, and pure functional validators makes it highly compliant with the WebAuthn W3C specification.
