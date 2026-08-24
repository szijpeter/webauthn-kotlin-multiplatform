# Changelog

The project follows a coordinated pre-1.0 release train across published artifacts. Minor releases can contain breaking API changes; migration notes identify replacements and changed ownership.

## Current release

The latest stable tag detected while building this site is **@@STABLE_VERSION@@**.

[Read the complete changelog](https://github.com/szijpeter/webauthn-kotlin-multiplatform/blob/@@SOURCE_REF@@/CHANGELOG.md){ .md-button .md-button--primary }

## Upgrade discipline

1. Read every **Breaking**, **Security**, **Changed**, and **Removed** entry between your pinned and target versions.
2. Align all artifacts; do not mix release trains without explicit compatibility evidence.
3. Run compile and API checks for every target.
4. Exercise registration and authentication against both the old and new backend and mobile combinations in your rollout window.
5. Repeat association and provider-backed device tests when platform dependencies, targets, signing, or RP configuration changed.

For the major client restructuring introduced in `v0.4.0`, use the [migration guide](../guides/migration.md).
