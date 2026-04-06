# Project Overview

Last reviewed: 2026-04-06

`webauthn-kotlin-multiplatform` is a standards-first Kotlin Multiplatform library for WebAuthn and passkey integrations.

The project is not a single SDK. It is a layered set of modules that can be adopted separately for:

- typed protocol models
- strict ceremony validation
- crypto and attestation verification
- JVM server orchestration
- Android and iOS passkey clients
- transport and sample integrations

## North Star

The canonical project goal is in [`docs/ai/STEERING.md`](../ai/STEERING.md): build the most robust and standards-first WebAuthn Kotlin Multiplatform library, and ship it as a trustworthy public open-source project.

Important consequences:

- standards alignment is more important than convenience wrappers
- security-critical validation paths must not regress
- KMP layering boundaries are intentional, especially around `webauthn-model`, `webauthn-core`, and `webauthn-client-core`
- documentation, compatibility, and release hygiene matter because the public release posture is active

## Who This Is For

- Kotlin teams building passwordless or passkey-backed sign-in flows
- teams that want to share logic across JVM backend, Android, and iOS
- teams that prefer typed APIs and modular adoption instead of a single all-in-one SDK

## Fast Orientation Path

1. Read [`module-map.md`](./module-map.md) for the layer model and published surface.
2. Read [`client-stack.md`](./client-stack.md) or [`server-stack.md`](./server-stack.md) depending on your integration direction.
3. Read [`samples-and-demos.md`](./samples-and-demos.md) for runnable examples.
4. Read [`quality-and-release.md`](./quality-and-release.md) before making changes that affect public modules.

## Canonical Source Anchors

- Root product overview: [`README.md`](../../README.md)
- Architecture overview: [`docs/architecture.md`](../architecture.md)
- Implementation status: [`docs/IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md)
- Roadmap: [`docs/ROADMAP.md`](../ROADMAP.md)
- Contribution workflow: [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
