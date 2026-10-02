# Architecture

## Design goals

- Standards-first WebAuthn L3 behavior.
- Strict separation between protocol model, shared foundation, cryptography, client orchestration, and JVM server services.
- Thin platform and transport adapters with optional features kept out of the core path.
- Architecture documentation that explains both repository structure and real application adoption.

## How to read the diagrams

The repository overview shows logical responsibility relationships. The focused
module diagrams show direct internal Gradle project dependencies for a selected
slice. In module diagrams, arrows point from the consumer to its dependency.

Diagrams are maintained through the [shared diagram pipeline](diagrams/README.md), with
responsive SVGs and complete expandable text on GitHub and the public site.

External Maven dependencies are omitted. Optional adapters are labelled
explicitly. The diagrams are intentionally curated rather than exhaustive.

## Repository overview

The [repository overview in the root README](../README.md#repository-structure)
shows the five logical responsibility areas. It intentionally omits individual
projects, samples, documentation utilities, and transitive dependencies.

## Reference integration

This view shows where the library is used in a typical passkey application. The
SDK is represented inside the client and backend descriptions rather than as a
separate runtime system.

<!-- diagram: docs-architecture-1 -->
<a href="diagrams/assets/docs-architecture-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/assets/docs-architecture-1-desktop-dark.svg">
  <img alt="Reference integration. Application and platform responsibilities, with optional metadata explicitly marked." src="diagrams/assets/docs-architecture-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Reference integration</summary>
<p>Phone view: <a href="diagrams/assets/docs-architecture-1-mobile-light.svg">light</a> · <a href="diagrams/assets/docs-architecture-1-mobile-dark.svg">dark</a>.</p>
<p>Application and platform responsibilities, with optional metadata explicitly marked.</p>
<p>Nodes: End user; Reference passkey application; Client application — webauthn-client-flow over client-core and an Android or iOS bridge; Relying-party backend — webauthn-server-core-jvm plus optional adapters; Credential store; Platform passkey API — Credential Manager or AuthenticationServices; Attestation metadata service — (optional).</p>
<p>Client application webauthn-client-flow over client-core and an Android or iOS bridge belongs to Reference passkey application.</p>
<p>Relying-party backend webauthn-server-core-jvm plus optional adapters belongs to Reference passkey application.</p>
<p>Credential store belongs to Reference passkey application.</p>
<p>1. End user → Client application webauthn-client-flow over client-core and an Android or iOS bridge: initiates registration or authentication.</p>
<p>2. Client application webauthn-client-flow over client-core and an Android or iOS bridge → Relying-party backend webauthn-server-core-jvm plus optional adapters: requests ceremony options and submits credential responses.</p>
<p>3. Relying-party backend webauthn-server-core-jvm plus optional adapters → Client application webauthn-client-flow over client-core and an Android or iOS bridge: returns ceremony options and verification results.</p>
<p>4. Client application webauthn-client-flow over client-core and an Android or iOS bridge → Platform passkey API Credential Manager or AuthenticationServices: invokes the passkey ceremony.</p>
<p>5. Relying-party backend webauthn-server-core-jvm plus optional adapters → Credential store: stores registered credentials.</p>
<p>6. Relying-party backend webauthn-server-core-jvm plus optional adapters → Attestation metadata service (optional): optionally obtains attestation metadata (dashed).</p>
</details>
<!-- /diagram -->

## Shared foundation

The shared foundation keeps protocol contracts, validation, serialization,
runtime helpers, and cryptographic contracts separated.

<!-- diagram: docs-architecture-2 -->
<a href="diagrams/assets/docs-architecture-2-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/assets/docs-architecture-2-desktop-dark.svg">
  <img alt="Shared foundation. Arrows point from a consumer to its direct internal dependency. Runtime is intentionally isolated." src="diagrams/assets/docs-architecture-2-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Shared foundation</summary>
<p>Phone view: <a href="diagrams/assets/docs-architecture-2-mobile-light.svg">light</a> · <a href="diagrams/assets/docs-architecture-2-mobile-dark.svg">dark</a>.</p>
<p>Arrows point from a consumer to its direct internal dependency. Runtime is intentionally isolated.</p>
<p>Nodes: webauthn-crypto-api — Kotlin/JVM; webauthn-core; webauthn-json-kotlinx; webauthn-json-api; webauthn-protocol; webauthn-cbor-core; webauthn-model; webauthn-runtime-core — No internal project dependencies.</p>
<p>1. webauthn-crypto-api Kotlin/JVM → webauthn-core.</p>
<p>2. webauthn-crypto-api Kotlin/JVM → webauthn-model.</p>
<p>3. webauthn-core → webauthn-model.</p>
<p>4. webauthn-json-kotlinx → webauthn-json-api.</p>
<p>5. webauthn-json-kotlinx → webauthn-protocol.</p>
<p>6. webauthn-json-api → webauthn-model.</p>
<p>7. webauthn-protocol → webauthn-model.</p>
<p>8. webauthn-protocol → webauthn-cbor-core.</p>
</details>
<!-- /diagram -->

The isolated runtime node is intentional. It communicates that this module has
no internal project dependencies without inventing an edge.

## Client stack

`webauthn-client-core` owns typed platform-operation contracts, shared input validation, and error
classification. `webauthn-client-flow` owns application-neutral start/prompt/finish orchestration,
opaque backend-state forwarding, and concurrency rejection. JSON, Android, iOS, Compose, PRF, and
network modules build around those boundaries. Platform bridges use the neutral codec API only where
an OS integration requires JSON and return byte-preserving raw responses.

<!-- diagram: docs-architecture-3 -->
<a href="diagrams/assets/docs-architecture-3-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/assets/docs-architecture-3-desktop-dark.svg">
  <img alt="Client stack. Focused dependency views. Repeated modules provide context; each relationship appears once." src="diagrams/assets/docs-architecture-3-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Client stack</summary>
<p>Phone view: <a href="diagrams/assets/docs-architecture-3-mobile-light.svg">light</a> · <a href="diagrams/assets/docs-architecture-3-mobile-dark.svg">dark</a>.</p>
<p>Focused dependency views. Repeated modules provide context; each relationship appears once.</p>
<p>Nodes: webauthn-client-compose; webauthn-client-platform — (androidMain and iosMain); webauthn-client-json-core; webauthn-client-prf-crypto — (optional); webauthn-client-defaults — (recommended composition); webauthn-client-ktor-kotlinx — (default JSON contract); webauthn-client-ktor — (codec-neutral transport); webauthn-client-flow; webauthn-client-core; webauthn-json-api; webauthn-json-kotlinx; webauthn-runtime-core; webauthn-model.</p>
<p>1. webauthn-client-compose → webauthn-client-core.</p>
<p>2. webauthn-client-compose → webauthn-client-flow.</p>
<p>3. webauthn-client-compose → webauthn-client-platform (androidMain and iosMain).</p>
<p>4. webauthn-client-compose → webauthn-json-kotlinx: androidMain.</p>
<p>5. webauthn-client-defaults (recommended composition) → webauthn-client-platform (androidMain and iosMain): androidMain and iosMain.</p>
<p>6. webauthn-client-defaults (recommended composition) → webauthn-json-api.</p>
<p>7. webauthn-client-defaults (recommended composition) → webauthn-json-kotlinx.</p>
<p>8. webauthn-client-platform (androidMain and iosMain) → webauthn-client-core.</p>
<p>9. webauthn-client-platform (androidMain and iosMain) → webauthn-json-api.</p>
<p>10. webauthn-client-json-core → webauthn-client-core.</p>
<p>11. webauthn-client-json-core → webauthn-json-api.</p>
<p>12. webauthn-client-prf-crypto (optional) → webauthn-client-core.</p>
<p>13. webauthn-client-prf-crypto (optional) → webauthn-runtime-core.</p>
<p>14. webauthn-client-ktor-kotlinx (default JSON contract) → webauthn-client-ktor (codec-neutral transport).</p>
<p>15. webauthn-client-ktor-kotlinx (default JSON contract) → webauthn-json-kotlinx.</p>
<p>16. webauthn-client-ktor (codec-neutral transport) → webauthn-client-flow.</p>
<p>17. webauthn-client-flow → webauthn-client-core.</p>
<p>18. webauthn-client-core → webauthn-runtime-core.</p>
<p>19. webauthn-client-core → webauthn-model.</p>
</details>
<!-- /diagram -->

External libraries, platform APIs, source-set details, and samples are
intentionally omitted from this module dependency view.

The view focuses on direct project dependencies among published client modules.
Platform adapters remain separate from shared typed behavior, and optional features remain outside
the core path. Target-labelled edges represent source-set-specific project dependencies.

For platform-specific behavior, see the reference integration and module
READMEs. For runnable adoption paths, see the sample documentation.



## JVM server stack

The server core remains framework-agnostic and depends on the neutral protocol
layer rather than a JSON implementation. Ktor, Exposed, and metadata support
are optional adapters around the core and cryptographic boundaries.

<!-- diagram: docs-architecture-4 -->
<a href="diagrams/assets/docs-architecture-4-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="diagrams/assets/docs-architecture-4-desktop-dark.svg">
  <img alt="JVM server stack. Direct internal dependencies. HTTP, storage and metadata remain optional adapters." src="diagrams/assets/docs-architecture-4-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: JVM server stack</summary>
<p>Phone view: <a href="diagrams/assets/docs-architecture-4-mobile-light.svg">light</a> · <a href="diagrams/assets/docs-architecture-4-mobile-dark.svg">dark</a>.</p>
<p>Direct internal dependencies. HTTP, storage and metadata remain optional adapters.</p>
<p>Nodes: webauthn-server-ktor — (optional adapter); webauthn-server-store-exposed — (optional adapter); webauthn-attestation-mds — (optional adapter); webauthn-server-core-jvm; webauthn-protocol; webauthn-server-jvm-crypto; Shared foundation; Cryptography boundary.</p>
<p>1. webauthn-server-ktor (optional adapter) → webauthn-server-core-jvm.</p>
<p>2. webauthn-server-store-exposed (optional adapter) → webauthn-server-core-jvm.</p>
<p>3. webauthn-server-store-exposed (optional adapter) → Shared foundation.</p>
<p>4. webauthn-server-store-exposed (optional adapter) → Cryptography boundary.</p>
<p>5. webauthn-attestation-mds (optional adapter) → Cryptography boundary.</p>
<p>6. webauthn-server-core-jvm → Shared foundation.</p>
<p>7. webauthn-server-core-jvm → webauthn-protocol.</p>
<p>8. webauthn-server-core-jvm → Cryptography boundary.</p>
<p>9. webauthn-server-jvm-crypto → Shared foundation.</p>
<p>10. webauthn-server-jvm-crypto → Cryptography boundary.</p>
</details>
<!-- /diagram -->

## Distribution and samples

| Project | Role |
| --- | --- |
| `platform:bom` | Aligns versions across the published WebAuthn artifacts as `webauthn-bom`. |
| `platform:constraints` | Internal dependency constraints used by the build. It is not published. |
| `sample:*` | Runnable backend, client, Android, iOS, Compose, and CLI examples. Samples are not published runtime libraries. |
| `documentation:*` | Documentation example and verification tooling. These projects are not part of the published SDK surface. |
| `docs/site` | Mobile-first public documentation authored for the generated site. The staging task adds allowlisted repository guides, sample pages, module indexes, and Dokka output without changing the published SDK surface. |

The published modules remain grouped under `core/`, `client/`, and `server/` by
responsibility. Distribution projects and samples are intentionally omitted
from the overview because they explain packaging and adoption rather than the
reusable library architecture.

The public documentation pipeline is a distribution layer over those sources. `docsSiteStage`
selects and rewrites allowlisted content, the root Dokka task aggregates published modules, and
`docsSiteBuild` assembles both into one validated static site. Generated site files remain build
artifacts; authored content and the source allowlist stay reviewable in the repository. The root
build owns these tasks and resolves their scripts and inputs from the repository root, so their
behavior does not depend on the directory from which Gradle was invoked.

## Dependency rules

- `webauthn-model` remains independent of the rest of the repository.
- `webauthn-json-api` is the serialization-library-neutral JSON contract; implementations such as `webauthn-json-kotlinx` depend on it.
- `webauthn-protocol` interprets raw WebAuthn binary data using only the model and strict CBOR scanner; codecs depend on it rather than owning protocol parsing.
- `webauthn-client-core` owns typed platform-operation validation and error classification; Android and iOS source sets remain thin bridges that return raw output.
- `webauthn-client-flow` depends only on client-core and keeps backend state/output generic; transport and UI modules build over it.
- `webauthn-client-ktor` adapts flow backends to caller-owned Ktor transport without choosing an engine or serializer; `webauthn-client-ktor-kotlinx` is the opt-in default JSON contract.
- `webauthn-client-defaults` selects the recommended Kotlinx/platform composition without changing the replaceable lower-level seams.
- `webauthn-server-core-jvm` remains framework-agnostic; Ktor and Exposed are adapters.
- `webauthn-crypto-api` stays vendor-neutral; implementations belong behind the crypto boundary.
- Optional adapters must not become hidden prerequisites of core modules.
- Direct project dependencies shown here must be checked against the owning `build.gradle.kts` whenever the module graph changes.

## Diagram maintenance

Architecture diagrams are maintained directly as Mermaid blocks beside their
supporting prose.

Keep each diagram focused on one concern. Prefer a small curated view over a
complete repository dependency graph. Module dependency arrows point from the
consumer to its dependency, and optional modules must be labelled explicitly.

When changing a diagram:

1. Check direct project dependencies against the relevant `build.gradle.kts` files.
2. Run `./gradlew docsUpdate docsCheck --stacktrace`.
3. Run `tools/agent/quality-gate.sh --mode strict --scope changed --block true`.
4. Inspect the rendered diagram on GitHub for readability and edge crossings.
