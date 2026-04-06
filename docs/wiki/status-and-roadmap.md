# Status And Roadmap

Last reviewed: 2026-04-06

This page compresses the current project maturity into a quick scan. For exact wording and deeper detail, follow the canonical source links below.

## Current Snapshot

- Core protocol model and validation baselines are implemented and heavily tested.
- JVM server ceremony flow is implemented and comparatively mature.
- Client-side shared orchestration plus Android and iOS bridges are in place and usable.
- Publication, compatibility baselines, and Maven Central workflow are active.
- The project is publicly released but still pre-1.0.

## Maturity Pattern

- Production-leaning: core validation paths and `webauthn-network-ktor-client`
- Beta: most server, client, crypto, and adapter modules
- Scaffold: not the dominant status right now; most major module families already exceed scaffold level

## Near-Term Priorities

- continue attestation trust-path hardening, especially remaining matrix depth
- keep assertion and interoperability vector coverage strong while dependencies evolve
- keep outreach-facing and adoption-facing docs aligned with sample and release evolution

## How To Read Change Pressure

If work touches any of the following, expect higher review and documentation burden:

- standards-facing validation behavior
- crypto or attestation verification
- public module APIs
- release and publishing workflow
- client/server integration paths shown in root docs and samples

## Canonical Source Anchors

- Full implementation status: [`docs/IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md)
- Roadmap: [`docs/ROADMAP.md`](../ROADMAP.md)
- Validation trace: [`spec-notes/webauthn-l3-validation-map.md`](../../spec-notes/webauthn-l3-validation-map.md)
- Steering done criteria: [`docs/ai/STEERING.md`](../ai/STEERING.md)
