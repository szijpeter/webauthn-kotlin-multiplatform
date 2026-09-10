---
title: Passkeys for Kotlin mobile apps
description: Build standards-first passkey registration and sign-in for Android, iOS, Compose Multiplatform, and Ktor.
hide:
  - toc
---

<div class="docs-home" markdown>

<img class="docs-home__mark" src="assets/images/mark.svg" alt="">

# Passkeys for Kotlin mobile apps

<p class="docs-home__lead">Build standards-first registration and sign-in for Android, iOS, and Compose Multiplatform, backed by authoritative verification on a JVM/Ktor server.</p>

<div class="docs-home__actions">
  <a class="md-button md-button--primary" href="mobile/quickstart/">Mobile quickstart</a>
  <a class="md-button" href="mobile/full-stack/">Run the complete sample</a>
</div>

</div>

> One shared Kotlin ceremony flow, platform-native passkey prompts, and a server boundary that remains responsible for challenges, origins, signatures, account binding, and replay prevention.

## Start with mobile

<div class="docs-paths" markdown>

<div markdown>

### Compose Multiplatform

Share orchestration and UI while keeping platform prompt lifecycles explicit. [Start the Compose path →](mobile/compose.md)

</div>

<div markdown>

### Android

Integrate Credential Manager, Digital Asset Links, and provider-backed device tests. [Read the Android guide →](mobile/android.md)

</div>

<div markdown>

### iOS

Bridge Authentication Services, Associated Domains, and the presentation anchor. [Read the iOS guide →](mobile/ios.md)

</div>

<div markdown>

### Mobile + backend

Run registration and authentication across the included app and Ktor service. [Run the full stack →](mobile/full-stack.md)

</div>

</div>

## The shortest production-shaped path

<!-- diagram: public-home-flow-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../diagrams/assets/public-home-flow-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../diagrams/assets/public-home-flow-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../diagrams/assets/public-home-flow-1-desktop-dark.svg">
  <img alt="From user action to verified result. The platform supplies a credential response; the server makes the verification decision." src="../../diagrams/assets/public-home-flow-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: From user action to verified result</summary>
<p>The platform supplies a credential response; the server makes the verification decision.</p>
<p>Nodes: Mobile UI; PasskeyFlow; Ktor backend contract; Registration or authentication service; Credential and ceremony stores; Android or iOS platform prompt.</p>
<p>1. Mobile UI → PasskeyFlow.</p>
<p>2. PasskeyFlow → Ktor backend contract.</p>
<p>3. Ktor backend contract → Registration or authentication service.</p>
<p>4. Registration or authentication service → Credential and ceremony stores.</p>
<p>5. PasskeyFlow → Android or iOS platform prompt.</p>
<p>6. Android or iOS platform prompt → PasskeyFlow.</p>
</details>
<!-- /diagram -->

1. Add the shared flow and transport artifacts, plus platform defaults.
2. Construct the platform client at the host lifecycle boundary.
3. Call the backend start endpoint, show the platform prompt, then send the response to the finish endpoint.
4. Configure Android Digital Asset Links and iOS Associated Domains for the production RP ID.
5. Verify both happy paths and failure paths on real provider-backed devices.

The latest stable coordinated release is **@@STABLE_VERSION@@**. All published artifacts use the `io.github.szijpeter` group.

!!! note "Project maturity"
    The API is evolving. Pin a release, read the [changelog](project/changelog.md), and treat compatibility statements as release-specific.

## Start where you are

| You are building… | Start here | Then verify |
| --- | --- | --- |
| Compose Multiplatform app | [Mobile quickstart](mobile/quickstart.md) | [Compose lifecycle](guides/compose-lifecycle.md) |
| Android app | [Android integration](mobile/android.md) | Digital Asset Links and provider-backed device behavior |
| iOS app | [iOS integration](mobile/ios.md) | Associated Domains, presentation anchor, and physical-device behavior |
| Mobile app plus backend | [Full sample](mobile/full-stack.md) | Registration and authentication end to end |
| Existing JVM service | [Ktor quickstart](backend/index.md) | Ceremony state, replay protection, and trusted origins |
| Custom protocol stack | [Artifact catalog](reference/modules.md) | Every replaced default and its security ownership |
