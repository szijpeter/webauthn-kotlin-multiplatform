# Mobile-First Public Documentation Site Execution Plan

Status: proposed execution map

Owner: repository maintainers

Last updated: 2026-08-24

Target branch family: `docs/*`

Removal condition: delete this temporary execution map after the public site is live, the maintenance workflow is documented in permanent contributor guidance, and all follow-up work is tracked elsewhere.

## 1. Executive Decision

Build a public documentation site that leads with Android, iOS, and Compose Multiplatform passkey adoption.

The site remains a standards-first documentation product for the entire repository, but its first promise and primary navigation path are mobile:

> Add standards-first passkeys to Android and iOS with shared Kotlin orchestration and an explicit server trust boundary.

The backend remains essential. It is introduced as the trusted counterpart required to complete a mobile WebAuthn ceremony, not as the first product journey. Developers who arrive specifically for JVM/Ktor support still get a direct backend entry point from the homepage and top-level navigation.

The implementation stack remains:

- Material for MkDocs for the authored documentation shell.
- The repository's existing Dokka 2.2 Gradle integration for public API reference.
- GitHub Pages for static hosting.
- Existing `docsUpdate` and `docsCheck` infrastructure as the authority for example ownership and verification.

All repository content produced by this initiative must be original and derived from this project's code, architecture, standards obligations, samples, and user needs.

## 2. Outcomes

The initiative is successful when a Kotlin mobile developer can:

1. Recognize within 30 seconds that the library supports shared Android/iOS passkey work.
2. Choose Android, iOS, Compose Multiplatform, or full-stack sample setup without first understanding the full module graph.
3. Add the correct shared and platform dependencies without accidentally resolving server modules into a client app.
4. Understand that the application owns UI state, navigation, Ktor engine selection, backend exception policy, and production domain configuration.
5. Run a verified registration or authentication path with the sample backend in approximately 15 minutes, excluding external account, signing, entitlement, or DNS setup.
6. Understand the signed-data trust boundary before handling a finish response.
7. Find exact mobile APIs, platform limitations, and troubleshooting guidance through site navigation or search.
8. Continue from the mobile guide into server, protocol, storage, crypto, attestation, and API reference material without changing documentation systems.

The initiative is successful for backend developers when they can:

1. Open a direct JVM/Ktor path from the homepage.
2. Understand the four default mobile-facing endpoints and their trust responsibilities.
3. Replace the default route, storage, JSON, or transport layers without reverse-engineering the module graph.
4. Verify which inputs are trusted, which inputs are signed, and which values must be derived on the server.

## 3. Non-Goals for Initial Launch

- Do not build a custom application server for the documentation site.
- Do not build an interactive browser WebAuthn playground in the first release.
- Do not present simulator compilation as physical-device or provider proof.
- Do not claim universal Android OEM, Credential Manager provider, Apple entitlement, or external security-key compatibility.
- Do not document unpublished modules as consumer artifacts.
- Do not publish internal agent instructions, cost policies, implementation trackers, or temporary planning documents as consumer navigation.
- Do not replace module `README.md` files, `SECURITY.md`, the changelog, or normative standards with duplicate site-only copies.
- Do not introduce documentation version archives until the current-version site is stable and maintainers agree to support multiple release lines.
- Do not enable GitHub Pages or change repository homepage settings before explicit go-live approval.

## 4. Current Mobile Baseline

All initial content and acceptance tests must reflect the current `origin/main` implementation rather than older module names or removed controller APIs.

### 4.1 Supported platform surface

- `webauthn-client-platform` bridges Android Credential Manager and iOS AuthenticationServices.
- `webauthn-client-defaults` is the recommended shortest platform construction path.
- `webauthn-client-flow` owns generic start, platform prompt, and finish sequencing.
- `webauthn-client-ktor` is codec-neutral.
- `webauthn-client-ktor-kotlinx` implements the repository's default `/webauthn/*` contract.
- `webauthn-client-compose` provides lifecycle-aware `rememberPasskeyClient()` and `rememberPasskeyFlow(...)` helpers while leaving UI state application-owned.
- `webauthn-client-prf-crypto` is optional and must never appear in the minimum passkey setup.

### 4.2 Android boundaries to state explicitly

- The base Android passkey client currently uses `minSdk 26` and `compileSdk 37`.
- The optional published `webauthn-client-prf-crypto` module uses `minSdk 30` and `compileSdk 37`.
- The Compose PRF sample also uses `minSdk 30`; neither PRF minimum may be presented as the minimum for the base client library.
- The host application must include a Credential Manager provider, normally `androidx.credentials:credentials-play-services-auth`.
- The library owns the Credential Manager bridge but deliberately does not select the provider runtime for the host application.
- Android app origins are tied to package identity and the signing certificate. Domain setup must explain `/.well-known/assetlinks.json`, package name, and SHA-256 fingerprint alignment.
- A provider-capable device or emulator, screen lock, and a passkey-capable account/provider are runtime prerequisites.
- Android compilation and host tests do not prove a real provider prompt or end-to-end ceremony.

### 4.3 iOS boundaries to state explicitly

- Published Apple targets are `iosArm64` and `iosSimulatorArm64`; `iosX64` is not published.
- The committed Compose iOS host currently targets iOS 16.
- PRF use through AuthenticationServices requires iOS 18 or newer.
- Real passkey success requires an HTTPS relying-party domain, Associated Domains capability, and a matching `apple-app-site-association` response.
- A free Apple signing account can build and launch the sample but may not support the entitlement/domain setup required for real registration and sign-in.
- Applications with non-default window ownership must provide the correct presentation anchor.
- Simulator compilation and unit tests do not prove physical-device keychain, account, entitlement, or security-key behavior.

### 4.4 Default mobile/backend contract

The first mobile quickstart should use the current default contract:

- `POST /webauthn/registration/start`
- `POST /webauthn/registration/finish`
- `POST /webauthn/authentication/start`
- `POST /webauthn/authentication/finish`

The site must explain that mobile receives start options, invokes the platform authenticator, and forwards the resulting raw credential response. The server derives ceremony type, challenge, and origin from the signed `clientDataJSON`; the client must not duplicate those values as independent claims.

## 5. Audience Priority

Design and review every page in this order:

1. Kotlin Multiplatform mobile engineer adding passkeys to Android and iOS.
2. Android engineer using Credential Manager directly.
3. iOS/Kotlin Native engineer using AuthenticationServices.
4. Compose Multiplatform engineer integrating lifecycle and presentation state.
5. JVM/Ktor engineer implementing the trusted backend.
6. Security reviewer validating ceremony boundaries and production assumptions.
7. Library adopter replacing default codecs, transports, stores, crypto, or attestation sources.
8. Repository contributor or maintainer.

Contributor-only information must not dominate consumer pages. Link to contributor material from the project section.

## 6. Mobile-First Experience Contract

The site is not mobile-first merely because Android and iOS appear first in a list. All of the following must be true.

### 6.1 Homepage

- The hero names Android and iOS before JVM/Ktor.
- The primary call to action is `Start mobile setup`.
- The secondary call to action is `Explore the backend`.
- The first four path cards are:
  1. Compose Multiplatform
  2. Android
  3. iOS
  4. Complete mobile + backend sample
- A backend card remains visible in the first viewport on common desktop widths but is visually secondary.
- The first architecture illustration shows `Mobile app -> Platform authenticator -> Trusted backend`.
- The homepage includes a short, visible limitations statement: Beta status, platform/provider prerequisites, and physical-device boundaries.
- Existing Android/iOS recordings may be used only with captions, poster images, no autoplay, and accessible fallback text.

### 6.2 Navigation

Top-level navigation order:

1. Mobile
2. Backend
3. Understand WebAuthn
4. Guides
5. Reference
6. Project

On desktop, this hierarchy is presented as a persistent vertical sidebar rather than horizontal
navigation tabs. The sidebar uses compact spacing, clear active states, and expandable sections
without competing with the article. On mobile, the same hierarchy moves into a conventional
drawer opened from the header. API reference and GitHub links remain persistent header actions.

### 6.3 Search

- Guide search must rank mobile quickstarts and mobile troubleshooting above low-level module pages for general terms such as `install`, `register`, `sign in`, `origin`, and `provider`.
- Exact artifact and class names must still resolve directly.
- MkDocs search covers authored guides and staged module reference pages.
- Dokka retains its own API search under `/api/`.
- The site must label these as `Documentation search` and `API search` instead of implying a single unified index when there are two indexes.

### 6.4 Page structure

Every mobile integration page uses this order:

1. Outcome
2. Supported targets and maturity
3. Prerequisites
4. Dependencies
5. Minimum wiring
6. Backend contract
7. Domain/application association
8. Run
9. Verify
10. Expected failures and fixes
11. Production responsibilities
12. Next step

Platform-specific requirements must not be hidden inside generic KMP tabs. Tabs are appropriate only for parallel code that has equivalent meaning.

## 7. Public Information Architecture

- Home
  - Mobile
    - Choose your mobile path
    - Mobile quickstart
    - Compose Multiplatform
    - Android
      - Install and construct the client
      - Credential Manager provider setup
      - Digital Asset Links and app origin
      - Android troubleshooting
    - iOS
      - Install and construct the client
      - Presentation anchors
      - Associated Domains and AASA
      - iOS troubleshooting
    - Full mobile + backend sample
    - Mobile capabilities and extensions
    - Mobile production checklist
  - Backend
    - Ktor quickstart
    - Default endpoint contract
    - Ceremony state and storage
    - Custom routes and transport
    - Backend production checklist
  - Understand WebAuthn
    - Registration and authentication
    - Mobile-to-server trust boundary
    - RP IDs, origins, and app association
    - Discoverable credentials
    - Counters and replay resistance
    - Attestation and metadata
  - Guides
    - Choose modules
    - Custom JSON codec
    - Custom Ktor contract codec
    - Custom persistence
    - Compose lifecycle and UI state
    - PRF application crypto
    - Large Blob
    - FIDO Metadata Service
    - Migration from removed client APIs
    - Troubleshooting index
  - Reference
    - Artifact catalog
    - Platform support matrix
    - Maturity matrix
    - Result and error model
    - Default HTTP contract
    - Architecture
    - API reference
  - Project
    - Releases and compatibility
    - Security
    - Contributing
    - Changelog
    - Roadmap

## 8. Required Page Catalog

### 8.1 Launch-critical pages

| URL | Primary reader | Required outcome | Canonical inputs | Verification |
| --- | --- | --- | --- | --- |
| `/` | Mobile evaluator | Understand value, support, maturity, and choose a path | Root README, architecture, implementation status | Responsive/accessible rendered review |
| `/mobile/` | Mobile engineer | Choose Compose, Android, iOS, or full-stack | Client module READMEs, client-first execution | Link and navigation tests |
| `/mobile/quickstart/` | KMP engineer | Add common/platform dependencies and run one ceremony | Consumer-smoke defaults fixture, flow/defaults/Ktor examples | Consumer compile plus site build |
| `/mobile/compose/` | Compose engineer | Retain client/flow safely while owning UI state | Compose README and sample source region | Sample build plus rendered review |
| `/mobile/android/` | Android engineer | Configure provider, construct client, run and diagnose | Platform/defaults READMEs, Android examples, sample host | Android platform compile plus device-boundary disclosure check |
| `/mobile/ios/` | iOS engineer | Configure host, anchor, association, run and diagnose | Platform/defaults READMEs, iOS examples, host sample | iOS simulator compile plus device-boundary disclosure check |
| `/mobile/full-stack/` | Mobile engineer | Run sample backend and mobile hosts | Backend and Compose sample READMEs | Sample commands syntax plus link check |
| `/mobile/production/` | Tech lead/security reviewer | Identify everything still application/deployment-owned | Security, client-first execution, sample readiness | Security review checklist |
| `/backend/quickstart/` | JVM/Ktor engineer | Serve the default four endpoints | Server consumer fixture and Ktor example | JVM consumer compile/test |
| `/concepts/trust-boundary/` | All adopters | Understand raw response and signed-client-data authority | Root README, architecture, server/core docs | Security reviewer approval |
| `/reference/modules/` | Advanced adopter | Select the smallest correct module set | Published module READMEs and steering surface | Catalog completeness check |
| `/reference/platform-support/` | Evaluator | See targets, minimums, prerequisites, and limits | Gradle configuration and module status | Generated-value drift check |
| `/reference/api/` | API consumer | Enter curated Dokka output | KDoc and Dokka configuration | Dokka aggregate build and link smoke |

### 8.2 Second-wave pages

- Android provider and Digital Asset Links deep dive.
- iOS Associated Domains, AASA, and presentation-anchor deep dive.
- Custom backend contract and codec guide.
- Discoverable authentication guide.
- PRF application-crypto guide with data-loss warning.
- Attestation policy and FIDO MDS guide.
- Storage and replay/race requirements.
- Migration guide from removed controller/server-client APIs.
- Troubleshooting index with platform, network, association, ceremony, and provider categories.

### 8.3 Page acceptance template

Every authored page must answer:

- What will the reader achieve?
- Is the path Beta, Experimental, or production-leaning?
- Which targets and versions does it cover?
- Which artifact belongs in which source set?
- Which example owns each code block?
- What does the library own?
- What does the application own?
- Which values cross a trust boundary?
- How does the reader verify success?
- Which runtime conditions are not proven by CI?
- What should the reader do next?

## 9. Content Ownership and Drift Prevention

| Content type | Authority | Site behavior |
| --- | --- | --- |
| Mobile learning journeys | `docs/site/**` | Authored specifically for public site |
| Consumer dependency blocks | `documentation/consumer-smoke/**` | Rendered from verified configuration regions |
| Kotlin examples | `documentation/examples/**` or sample source regions | Rendered by `docsUpdate`; never duplicated manually |
| Module details | Module `README.md` | Staged into reference pages during build |
| Public API | KDoc | Rendered by Dokka |
| Architecture diagrams | Mermaid in canonical repository docs or site source | Kept text-reviewable and GitHub-renderable |
| Platform support values | Gradle build files plus explicit generated site data | Build fails when generated values drift |
| Maturity | `docs/IMPLEMENTATION_STATUS.md` and module status sections | Curated into stable public labels with an exact review date |
| Security reporting | `SECURITY.md` | Linked directly; short public summary only |
| Release history | Git tags, changelog, Maven publication metadata | Latest stable version shown separately from snapshot development |

Rules:

1. Never maintain the same executable snippet in both a site page and a module README.
2. New site fences require `doc-example` ownership and a verification level.
3. Source/configuration-owned blocks are edited at their source region, followed by `./gradlew docsUpdate`.
4. `./gradlew docsCheck` remains the aggregate content authority.
5. Generated staging and HTML output live under `build/docs-site/` and are never committed.
6. A staged Markdown link to a repository file must be rewritten either to its public-site location or to a commit-pinned GitHub source link.
7. Unknown or unmapped local links fail staging instead of becoming broken production links.
8. Pages derived from status or roadmap content include an exact `Last reviewed` date.

## 10. Proposed Repository Layout

- `mkdocs.yml`: site configuration and checked-in navigation.
- `docs/site/requirements.in`: direct Python documentation dependencies.
- `docs/site/requirements.lock`: fully pinned Python documentation environment.
- `docs/site/content/`: authored public pages, organized under `mobile`, `backend`, `concepts`, `guides`, `reference`, and `project`.
- `docs/site/assets/`: site stylesheets, images, and minimal JavaScript.
- `docs/site/data/navigation.yml`: explicit public navigation manifest if navigation is generated rather than kept directly in `mkdocs.yml`.
- `documentation/tooling/`: public-site staging and validation code next to existing documentation verification.
- `tools/docs/site.sh`: isolated local environment and preview entry point.
- `.github/workflows/docs-site.yml`: build, artifact, and approval-gated deployment workflow.
- `build/docs-site/staged/`: generated Markdown staging tree.
- `build/docs-site/api/`: generated Dokka API tree.
- `build/docs-site/site/`: final static site artifact.
- `build/docs-site/reports/`: staging, links, accessibility, and performance reports.

`docs/site/content` contains authored public pages. Staged module/reference pages are generated only under `build/docs-site/staged`.

## 11. Local Commands and Gradle Contract

Expose one obvious command per operation.

### 11.1 Contributor commands

- Update synchronized content: `./gradlew docsSiteUpdate`
- Build and verify the complete site: `./gradlew docsSiteCheck`
- Run a local preview: `tools/docs/site.sh serve`

Expected behavior:

- `docsSiteUpdate`
  - Runs existing `docsUpdate`.
  - Regenerates tracked public-site metadata or inventories that are intentionally source-controlled.
  - Never builds or commits HTML.
- `docsSiteCheck`
  - Runs existing `docsCheck`.
  - Stages authored and canonical content in `build/docs-site/staged`.
  - Builds the published-module Dokka aggregate.
  - Runs `mkdocs build --strict`.
  - Runs internal link, anchor, generated-value, and public-content-boundary checks.
  - Fails on a dirty generated diff when updateable tracked content is stale.
- `tools/docs/site.sh serve`
  - Creates or refreshes an isolated local Python environment from the pinned lock file.
  - Stages the current source tree.
  - Starts MkDocs with the repository-site base path.
  - Prints the local URL and exits with actionable setup errors.

### 11.2 Dependency management

- Pin Material for MkDocs and required plugins in `requirements.lock`.
- Keep the unpinned intent in `requirements.in`.
- Update the lock through one documented command.
- CI installs only from the lock.
- Do not use floating container tags or unbounded `pip install` commands.
- Avoid plugins when equivalent MkDocs/Material functionality exists.

## 12. Site Staging Implementation

Extend the repository-owned documentation tooling instead of adding an unrelated Markdown copier.

### 12.1 Staging responsibilities

The staging task must:

1. Delete and recreate only the explicit `build/docs-site/staged` directory.
2. Copy authored content and assets from `docs/site`.
3. Copy the curated public module README set into stable `/reference/modules/<artifact>/` paths.
4. Copy selected sample READMEs into `/guides/samples/` paths.
5. Rewrite repository-relative links deterministically.
6. Preserve external links, fragment identifiers, fenced code, `doc-example` directives, and Mermaid blocks.
7. Generate navigation metadata from a checked-in manifest, not filesystem ordering.
8. Generate platform-support data from current build configuration or verify checked-in values against it.
9. Generate the latest stable release label from the most recent stable `v*` Git tag; never present the snapshot version as the latest published release.
10. Emit a machine-readable staging report listing source page, output page, rewritten links, and excluded files.

### 12.2 Publication boundary

The staging task must fail if any included file resolves under:

- `docs/ai/`
- `spec-cache/`
- `spec-notes/`
- internal build reports
- local properties or environment files
- Gradle caches
- temporary worktrees

Project links may still point to selected permanent files such as `SECURITY.md`, `CONTRIBUTING.md`, and `CHANGELOG.md` on GitHub.

Use the same lexical-plus-canonical path containment model already used by documentation source verification. Never trust a staged source solely because its lexical path appears to be inside an allowed directory.

### 12.3 Link rewriting

For each relative Markdown link:

1. Resolve and canonicalize the source target.
2. Reject traversal or symlink escape.
3. Map included documentation to its stable site URL.
4. Map non-included repository sources to a commit-pinned GitHub blob URL.
5. Preserve and verify fragments when the target is Markdown.
6. Fail when no mapping exists.

Add unit tests for same-directory links, parent-directory links, anchors, images, GitHub user attachments, source-region comments, spaces, URL encoding, and symlinked parents.

## 13. Dokka API Reference Plan

### 13.1 Scope

- Aggregate projects applying `webauthn.published-library` that contain documentable Kotlin sources.
- Exclude samples, build logic, platform constraints, documentation tooling, and unpublished artifacts.
- The BOM may have a narrative reference page but does not need empty Dokka output.
- Document public and protected declarations only unless a module has an explicit reason otherwise.

### 13.2 Configuration

- Set module names to published artifact IDs.
- Include each module README as its module landing content where supported.
- Configure source links to the exact build commit.
- Use `GITHUB_SHA` in CI and `git rev-parse HEAD` locally.
- Keep Dokka output under `build/docs-site/api`.
- Copy the final API tree under the site artifact's `/api/` path.
- Add a visible return link from API pages to the guide site.
- Do not fork Dokka templates for launch unless configuration and small CSS overrides are insufficient.

### 13.3 KDoc quality rollout

Do not block the site foundation on undocumented declarations across every module. Establish a baseline report, then close gaps in this order:

1. `webauthn-client-defaults`
2. `webauthn-client-flow`
3. `webauthn-client-core`
4. `webauthn-client-platform`
5. `webauthn-client-compose`
6. `webauthn-client-ktor-kotlinx`
7. `webauthn-client-ktor`
8. `webauthn-server-core-jvm`
9. `webauthn-server-ktor`
10. protocol/model/core/crypto modules
11. optional storage, PRF, and attestation modules

For launch-critical APIs, KDoc must state purpose, caller ownership, result/error behavior, platform availability, and security-sensitive preconditions. After the agreed baseline is clean, make new undocumented public declarations a blocking failure.

## 14. Mobile Content Workstream

### 14.1 Homepage

Tasks:

- Write an original mobile-first value proposition using existing product language.
- Add `Start mobile setup` and `Explore the backend` actions.
- Add four mobile journey cards and one visible backend card.
- Add one Mermaid ceremony diagram emphasizing the server trust boundary.
- Add concise Beta/platform prerequisites.
- Add Android/iOS media with captions and non-autoplay behavior if current recordings remain representative.
- Add a `What the library owns / What your app owns` split.
- Add latest stable release and API reference links.

Acceptance:

- Mobile is unmistakably the primary product path at 360 px and 1440 px.
- Backend remains discoverable without scrolling on standard desktop.
- No unqualified production-readiness statement appears.
- Homepage content does not require knowledge of artifact names.

### 14.2 Mobile path chooser

Tasks:

- Ask whether the reader uses Compose Multiplatform, direct Android, direct iOS, or wants the runnable sample.
- Explain that all paths require a compatible server start/finish contract.
- Show recommended modules first and lower-level modules second.
- Link to the custom-codec/transport path without inserting it into the quickstart.

Acceptance:

- Each choice leads to exactly one recommended next page.
- The shortest supported setup uses `webauthn-client-defaults` rather than low-level manual construction.
- No legacy artifact or removed controller API appears except in migration material.

### 14.3 Shared mobile quickstart

Tasks:

- Add `webauthn-client-flow` and `webauthn-client-ktor-kotlinx` to `commonMain`.
- Add `webauthn-client-defaults` to `androidMain` and `iosMain`.
- Explain that the app supplies its own Ktor `HttpClient` and engine.
- Construct `KotlinxKtorPasskeyBackend` against a configurable HTTPS base URL.
- Construct or remember the platform client and flow.
- Execute registration and authentication with application-owned state.
- Handle deliberate platform and already-in-progress outcomes separately from propagated backend/callback exceptions.
- Link to platform association steps before claiming a real-device success path.

Acceptance:

- Dependency blocks come from consumer-smoke fixtures.
- Common Kotlin blocks compile.
- Android/iOS construction blocks pass platform compilation.
- Error guidance matches current flow behavior and preserves coroutine cancellation.

### 14.4 Android guide

Tasks:

- State library `minSdk 26` and current `compileSdk 37` separately from sample `minSdk 30`.
- Add the Credential Manager API and provider dependencies in the correct host scope.
- Provide recommended and explicit-codec construction paths.
- Explain current-activity ownership and lifecycle-aware context resolution.
- Explain package/signing-certificate app origin and Digital Asset Links.
- Document emulator/device/provider prerequisites.
- Add verification steps for provider availability, start response, prompt, raw response forwarding, and server finish.
- Add troubleshooting for missing provider, invalid RP ID, wrong fingerprint, local-network permission in the sample, cancellation, and activity recreation.

Acceptance:

- Base integration does not inherit the PRF sample's API 30 minimum.
- Provider selection is clearly host-owned.
- Signing fingerprint instructions never encourage committing private signing material.
- Runtime claims are limited to evidence actually exercised.

### 14.5 iOS guide

Tasks:

- State supported published targets and the absence of `iosX64`.
- State the committed sample host's iOS 16 target without presenting it as a guarantee for every optional API.
- Provide recommended and explicit-anchor construction paths.
- Explain default and application-owned presentation anchor behavior.
- Explain Associated Domains and AASA requirements.
- Separate free-account build/launch from entitlement-capable E2E success.
- State iOS 18+ for PRF guidance.
- Add verification steps for framework build, host launch, association, platform prompt, raw response forwarding, and server finish.
- Add troubleshooting for missing entitlement, AASA mismatch, RP ID requirement, presentation window, cancellation, and simulator/device differences.

Acceptance:

- The page never implies that simulator success proves a real passkey ceremony.
- PRF availability is runtime-gated and not conflated with base passkey support.
- Association examples use placeholder team and bundle identifiers, never real credentials.

### 14.6 Compose Multiplatform guide

Tasks:

- Explain `rememberPasskeyClient()` and `rememberPasskeyFlow(...)` ownership.
- Keep UI state, navigation, dialogs, retries, and exception policy application-owned.
- Show one minimal state model around registration/sign-in.
- Explain client identity and concurrency behavior across recomposition.
- Explain Android activity recreation and iOS presentation-anchor implications.
- Link to the sample's static previews as UI contract evidence, not runtime proof.

Acceptance:

- The primary snippet is sample-backed or independently compiled.
- No example stores backend exceptions or screen state inside `PasskeyFlow`.
- Cancellation is rethrown or allowed to propagate.

### 14.7 Full-stack sample guide

Tasks:

- Start `sample/backend-ktor`.
- Offer local emulator, physical-device tunnel, and iOS associated-domain paths separately.
- Explain generated `local.properties` values and their ownership.
- Document Android certificate-origin derivation.
- Document iOS AASA identity alignment.
- Show expected log stages without enabling unsafe body logging.
- Include a clear success checklist for register, sign in, and optional PRF.

Acceptance:

- No secret or credential is printed or requested for publication.
- Unsafe body logging is visibly opt-in, local-only, and disabled before sharing logs.
- The guide distinguishes Android emulator, physical Android, iOS simulator, and physical iOS evidence.

### 14.8 Mobile production checklist

Cover:

- HTTPS and relying-party domain ownership.
- Digital Asset Links and AASA deployment.
- Android signing-certificate rotation considerations.
- Apple team/bundle/entitlement ownership.
- Session/authentication and CSRF posture.
- Challenge lifecycle and server-side state.
- Trusted `clientDataJSON` parsing.
- Counter and credential storage behavior.
- Attestation policy selection.
- Cancellation and retry UX.
- Sensitive logging and crash-report hygiene.
- Provider/device support matrix testing.
- Recovery when a passkey or PRF-derived key is removed.

Every checklist item must link to a guide, canonical repository document, or primary standard source.

## 15. Backend and Concept Workstream

Backend content follows the mobile launch-critical pages but remains part of the same launch.

### 15.1 Ktor quickstart

- Use BOM-aligned JVM dependencies.
- Create registration/authentication services and stores.
- Install default routes.
- Explain TLS/session/CSRF deployment responsibilities.
- Run focused server tests.
- Show the four endpoints expected by the default mobile adapter.

### 15.2 Trust-boundary concept page

- Diagram start, platform prompt, and finish.
- Explain why raw credential responses cross the client/server boundary.
- Explain that type, challenge, and origin come from signed `clientDataJSON`.
- Identify server-owned validation and policy decisions.
- Identify client-owned presentation and platform invocation.
- Link each claim to repository architecture or primary specifications.

### 15.3 Module selection guide

- Begin with three recipes: recommended mobile, custom mobile, JVM/Ktor server.
- Reveal lower-level artifacts only after the recipes.
- Provide a `Do I need this?` decision row for every published artifact.
- Mark optional adapters and trust sources.
- Keep samples and constraints visibly unpublished.

## 16. Visual and Interaction Direction

Create an original, restrained identity based on protocol clarity and trust:

- Use a clean light canvas by default: white articles, a quiet slate-gray navigation rail, subtle
  borders, clear blue links/actions, and warm yellow selection and focus accents.
- Keep the header compact and largely white; it provides utilities rather than acting as a hero.
- Keep article width readable and typography calm, with generous whitespace and minimal ornament.
- Use a simple project-owned mark and direct repository naming without oversized brand treatment.
- Preserve an accessible dark option without making it the default visual direction.
- Minimal icon use; icons clarify Android, Apple, shared Kotlin, server, warning, and API paths.
- No emoji-led navigation.
- No badge wall in the hero.
- No gradients, floating promotional cards, oversized shadows, or horizontal category tabs.
- Desktop navigation is a persistent vertical menu; mobile navigation is a compact drawer.
- Security warnings use consistent severity and are never color-only.
- Code blocks include copy controls and visible language/source-set labels.
- Mermaid diagrams use one project-owned palette across light and dark themes.
- Motion is optional, subtle, and disabled under `prefers-reduced-motion`.
- Videos never autoplay.

Required viewports:

- 360 x 800 mobile
- 768 x 1024 tablet
- 1280 x 800 laptop
- 1440 x 1000 desktop

Required interaction checks:

- Keyboard-only navigation
- Visible focus
- Search open/use/close
- Mobile navigation open/use/close
- Theme switch
- Copy-code controls
- Anchor navigation
- Previous/next links
- API-return link

## 17. Accessibility, SEO, and Performance Gates

### 17.1 Accessibility

- WCAG 2.2 AA color contrast.
- One `h1` per page and ordered heading hierarchy.
- Meaningful link labels.
- Alternative text for informative images.
- Captions/transcripts for recordings where needed.
- Tables usable on narrow screens and understandable with headers.
- Callouts announced semantically.
- No content available only through hover.
- Automated axe audit of launch-critical pages with zero serious or critical findings.

### 17.2 SEO and metadata

- Unique title and description per authored page.
- Canonical URL using the repository Pages base path.
- Open Graph metadata for homepage and major entry pages.
- Sitemap and robots file.
- Stable, lowercase, hyphenated URLs.
- Redirect manifest for any URL moved after launch.
- Structured page summaries that name Android, iOS, Kotlin Multiplatform, WebAuthn, and passkeys naturally rather than through keyword stuffing.

### 17.3 Performance

- Static assets fingerprinted and compressed by the site build or Pages serving path.
- No third-party analytics at launch.
- No blocking third-party fonts; prefer system fonts or committed, licensed subsets.
- Optimize poster images and screenshots.
- Keep launch homepage JavaScript minimal.
- Lighthouse launch targets:
  - Accessibility: 95+
  - Best Practices: 95+
  - SEO: 95+
  - Performance: 90+

## 18. CI and GitHub Pages Workflow

Create `.github/workflows/docs-site.yml` with separate build and deploy jobs.

### 18.1 Pull-request build job

- Check out full history when stable-release tag discovery is required.
- Set up Java and the pinned Python environment.
- Run `./gradlew docsSiteCheck --stacktrace`.
- Start the built site locally for browser smoke checks.
- Run accessibility and responsive smoke checks on launch-critical pages.
- Upload the static site and reports as a short-retention workflow artifact.
- Do not deploy a public preview from untrusted pull-request code.
- Keep permissions read-only.

### 18.2 Main build job

- Rebuild from a clean checkout.
- Run all pull-request checks.
- Run full external-link validation with bounded retries and a report that distinguishes external availability from internal broken links.
- Upload the Pages artifact.

### 18.3 Deploy job

- Run only for approved `main` pushes or explicit workflow dispatch after go-live approval.
- Depend on the successful build job.
- Use the protected `github-pages` environment.
- Grant only `pages: write` and `id-token: write` at job scope.
- Use explicit supported action versions consistent with repository workflow policy.
- Publish the deployment URL as an output.
- Use a deployment concurrency group that cancels superseded queued builds without interrupting an active deployment.

### 18.4 Failure attribution

Reports must distinguish:

- Authored-content error
- Example verification failure
- Dokka/KDoc failure
- Internal link/anchor failure
- External site unavailability
- Accessibility regression
- Pages configuration/deployment failure
- Dependency/setup/infrastructure failure

Do not report a setup failure as evidence that mobile examples or API behavior failed.

## 19. Implementation Phases and PR Slices

### Phase 0: Approve execution map

Deliverables:

- This plan approved.
- Final URL base and initial hosting decision approved.
- Mobile-first sitemap approved.
- Original visual direction approved.
- Launch-critical page list frozen.

Exit criteria:

- No unresolved decision changes technical stack, URL structure, or public scope.

### PR 1: Public-site foundation and Android vertical slice

Suggested branch: `docs/public-site-foundation`

Deliverables:

- Pinned MkDocs environment.
- Site staging tooling and tests.
- `docsSiteUpdate`, `docsSiteCheck`, and local serve command.
- Mobile-first homepage.
- Mobile path chooser.
- Complete Android guide.
- One trusted-backend concept page.
- CI build and preview artifact, with deployment disabled.

Required validation:

- `./gradlew docsCheck`
- `./gradlew docsSiteCheck`
- Fast changed-scope quality gate during iteration.
- Strict changed-scope quality gate before PR readiness.
- Responsive and accessibility review of homepage and Android guide.

### PR 2: Complete mobile journey and backend counterpart

Suggested branch: `docs/mobile-integration-guides`

Deliverables:

- Shared mobile quickstart.
- Compose Multiplatform guide.
- iOS guide.
- Full-stack sample guide.
- Mobile capabilities/extensions guide.
- Mobile production checklist.
- Ktor quickstart and default endpoint contract.
- Mobile/backend troubleshooting index.

Required validation:

- Existing documentation example checks.
- Android platform compilation.
- iOS simulator compilation.
- Relevant sample builds/tests.
- Rendered mobile/iOS/Compose review.
- Explicit audit that device/provider claims match evidence.

### PR 3: Reference, hardening, and launch readiness

Suggested branch: `docs/public-site-launch`

Deliverables:

- Published-module reference staging.
- Platform and maturity matrices.
- Multi-module Dokka aggregation.
- Launch-critical KDoc improvements.
- Link, accessibility, SEO, and performance gates.
- Pages build/deploy workflow with deployment still approval-gated.
- Permanent contributor maintenance guidance.
- Final public-content boundary audit.

Required validation:

- Full `docsSiteCheck` from a clean checkout.
- Strict changed-scope quality gate.
- `apiCheck` only if public API or API baselines change; KDoc-only edits do not require API dumps.
- `publishToMavenLocal` only if publishing/build metadata changes; documentation-only site changes do not trigger a Maven release.
- Pages artifact inspection before enabling deployment.

### Go-live action

Requires explicit approval because it changes external repository state.

Actions:

1. Enable GitHub Pages with GitHub Actions as the source.
2. Approve the protected `github-pages` environment deployment.
3. Verify the production base path, canonical URLs, search, API links, assets, and redirects.
4. Set the repository homepage URL only after the production read-back passes.
5. Monitor the first deployment and one subsequent ordinary documentation change.
6. Convert permanent maintenance rules into contributor guidance.
7. Delete this temporary execution map once remaining follow-ups are tracked.

## 20. Validation Matrix

| Surface | Local/CI proof | What it does not prove |
| --- | --- | --- |
| Shared client snippets | KMP compilation and documentation tests | Platform prompt/runtime behavior |
| Android construction | Android platform compilation and host tests | Provider availability or real credential ceremony |
| Android sample | Sample build, instrumentation where available | Every OEM/account/provider combination |
| iOS construction | iOS simulator compilation and tests | Physical device, entitlement, keychain, or security-key behavior |
| Compose state example | Sample/common tests and compilation | Full lifecycle behavior on every host |
| Backend quickstart | JVM consumer compilation and server tests | Production TLS/session/CSRF deployment correctness |
| Module catalog | Generated completeness check | API semantic correctness |
| API reference | Dokka aggregate build and source-link check | Runtime support for every public API |
| Internal links | Strict site/link checker | Availability of external services |
| External links | Scheduled/main link report | Future availability |
| Accessibility | axe/Lighthouse plus manual keyboard review | Every assistive-technology combination |

## 21. Risk Register

### Duplicate or drifting examples

- Risk: public guides diverge from compiled APIs.
- Mitigation: source/configuration ownership, `docsUpdate`, `docsCheck`, and no manually duplicated executable blocks.

### Mobile support overstatement

- Risk: compilation is presented as physical-device proof.
- Mitigation: evidence labels, explicit device/provider boundaries, and platform readiness review on every launch-critical page.

### Android library/sample minimum confusion

- Risk: the API 30 PRF sample requirement is misreported as the base library minimum.
- Mitigation: generate or validate platform values and show base and optional-sample requirements separately.

### iOS entitlement ambiguity

- Risk: readers assume a free signing account can complete real passkey E2E.
- Mitigation: separate build/launch instructions from entitlement-capable E2E instructions.

### Staged README link breakage

- Risk: relative module links fail after relocation.
- Mitigation: deterministic canonical link rewriting, unit tests, and strict anchor checks.

### Snapshot/release version confusion

- Risk: main's snapshot version appears as the latest Maven release.
- Mitigation: derive the public release label from stable Git tags and label main-generated API docs as current-development when appropriate.

### API reference overload

- Risk: a 23-artifact API tree obscures the recommended mobile path.
- Mitigation: curated API landing page, client-first module ordering, and artifact-level search.

### CI cost and duration

- Risk: full Dokka and browser audits slow every change.
- Mitigation: measure first; keep correctness gates intact, then split cheap authored-site checks from conditional API generation only with a tested change classifier.

### External-link flakiness

- Risk: third-party availability blocks unrelated pull requests.
- Mitigation: internal links block PRs; full external checks run on main/schedule and report availability separately.

### Internal content exposure

- Risk: staging accidentally publishes `docs/ai`, spec caches, secrets, or local configuration.
- Mitigation: allowlist staging, canonical path containment, forbidden-path tests, and final artifact inventory.

## 22. Definition of Ready for Implementation

- [ ] Maintainer approves mobile-first hero and navigation order.
- [ ] Maintainer approves Material for MkDocs + Dokka + GitHub Pages.
- [ ] Maintainer approves initial default Pages URL versus a custom domain.
- [ ] Maintainer approves the three-PR delivery sequence.
- [ ] No unresolved product decision requires a different information architecture.
- [ ] Current `origin/main` remains the implementation base.
- [ ] Work proceeds in isolated worktrees without modifying unrelated local changes.

## 23. Definition of Done

- [ ] Homepage leads with mobile at all required viewports.
- [ ] Android, iOS, Compose, and full-stack journeys are complete and cross-linked.
- [ ] Backend quickstart completes the mobile ceremony story.
- [ ] Trust-boundary documentation is security-reviewed.
- [ ] All public artifacts are represented in the reference catalog.
- [ ] Launch-critical public APIs have useful KDoc and source links.
- [ ] Every executable consumer example is owned and verified.
- [ ] `./gradlew docsCheck` passes.
- [ ] `./gradlew docsSiteCheck` passes from a clean checkout.
- [ ] Strict changed-scope quality gate passes.
- [ ] Internal links and anchors have zero failures.
- [ ] Accessibility, SEO, and performance thresholds pass.
- [ ] Android/iOS support claims match current source and evidence.
- [ ] Generated site contains no forbidden internal content or secrets.
- [ ] Public source, comments, assets, commits, and PR text contain only project-relevant content and dependency/source links.
- [ ] Pages deployment is explicitly approved and production-read back.
- [ ] Repository homepage points to the verified site.
- [ ] Permanent maintenance documentation exists.
- [ ] This temporary execution map is deleted after follow-ups are tracked.

## 24. Decision Log

### 2026-08-24

- The public site will lead with mobile rather than server adoption.
- Android, iOS, Compose Multiplatform, and the full-stack sample are the primary launch journeys.
- Backend documentation remains launch-critical but is framed as the trusted counterpart to mobile ceremonies.
- The previously selected site architecture remains unchanged.
- Publication remains approval-gated; this plan does not authorize enabling GitHub Pages.
