# Architecture

The repository uses replaceable layers. The recommended mobile stack follows the main path; lower-level modules remain available for custom transports, codecs, verification, and persistence.

<!-- diagram: public-architecture-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-architecture-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../../diagrams/assets/public-architecture-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-architecture-1-desktop-dark.svg">
  <img alt="Architecture. Application, server and shared foundation responsibilities." src="../../../diagrams/assets/public-architecture-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: Architecture</summary>
<p>Application, server and shared foundation responsibilities.</p>
<p>Nodes: Android and iOS application; Product UI and state; Compose helpers; Client flow; Ktor contract adapter; Passkey client core; Android and iOS bridge; JVM relying-party backend; Ktor routes; Registration and authentication services; JVM crypto and attestation; Challenge, credential, and account stores; Shared protocol foundation; Models; Binary protocol and validation; JSON API and implementation; Extension hooks.</p>
<p>Product UI and state belongs to Android and iOS application.</p>
<p>Compose helpers belongs to Android and iOS application.</p>
<p>Client flow belongs to Android and iOS application.</p>
<p>Ktor contract adapter belongs to Android and iOS application.</p>
<p>Passkey client core belongs to Android and iOS application.</p>
<p>Android and iOS bridge belongs to Android and iOS application.</p>
<p>Ktor routes belongs to JVM relying-party backend.</p>
<p>Registration and authentication services belongs to JVM relying-party backend.</p>
<p>JVM crypto and attestation belongs to JVM relying-party backend.</p>
<p>Challenge, credential, and account stores belongs to JVM relying-party backend.</p>
<p>Models belongs to Shared protocol foundation.</p>
<p>Binary protocol and validation belongs to Shared protocol foundation.</p>
<p>JSON API and implementation belongs to Shared protocol foundation.</p>
<p>Extension hooks belongs to Shared protocol foundation.</p>
<p>1. Product UI and state → Compose helpers.</p>
<p>2. Compose helpers → Client flow.</p>
<p>3. Product UI and state → Client flow.</p>
<p>4. Client flow → Ktor contract adapter.</p>
<p>5. Client flow → Passkey client core.</p>
<p>6. Passkey client core → Android and iOS bridge.</p>
<p>7. Ktor routes → Registration and authentication services.</p>
<p>8. Registration and authentication services → JVM crypto and attestation.</p>
<p>9. Registration and authentication services → Challenge, credential, and account stores.</p>
<p>10. Ktor contract adapter ↔ Ktor routes.</p>
<p>11. Passkey client core → Shared protocol foundation.</p>
<p>12. Registration and authentication services → Shared protocol foundation.</p>
</details>
<!-- /diagram -->

## Dependency direction

High-level modules depend inward on neutral contracts. Default implementations are opt-in where replacement is useful: Kotlinx JSON, Ktor payloads, JVM crypto, and Exposed stores do not need to become mandatory dependencies of every lower layer.

## Trust direction

The platform returns untrusted raw credential data. The mobile flow transports it without becoming a verifier. Server services decode signed client data, bind it to one-time state, perform cryptographic verification, apply account and policy checks, and only then return an application output.

## Generated detail

Use the [artifact catalog](modules.md) for per-module responsibilities and the [API reference](api.md) for symbols and signatures.
