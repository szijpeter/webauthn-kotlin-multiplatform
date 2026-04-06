# Specs And Sources

Last reviewed: 2026-04-06

This project is standards-first. The wiki should summarize and connect information, but normative behavior comes from the standards and the repository's canonical implementation docs.

## Normative Standards

Per repository steering, the primary standards set is:

- W3C WebAuthn Level 3
- RFC 4648
- RFC 8949
- RFC 9052 and RFC 9053

These govern behavior and public API intent more strongly than convenience or ecosystem precedent.

## High-Value Repository Sources

- [`README.md`](../../README.md): product-level overview, module catalog, install guidance, sample entry points
- [`docs/architecture.md`](../architecture.md): layer boundaries and dependency shape
- [`docs/IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md): current maturity snapshot by module
- [`docs/ROADMAP.md`](../ROADMAP.md): next-phase priorities and definitions of done
- [`docs/dependency-decisions.md`](../dependency-decisions.md): crypto/backend dependency policy and rationale
- [`docs/ai/STEERING.md`](../ai/STEERING.md): canonical contributor and agent policy
- [`spec-cache/README.md`](../../spec-cache/README.md): local spec cache index
- [`spec-notes/webauthn-l3-validation-map.md`](../../spec-notes/webauthn-l3-validation-map.md): trace of implemented validation rules

## How The Wiki Should Use Sources

- Treat source docs as canonical and the wiki as synthesis.
- Prefer linking to module and sample `README.md` files rather than restating full API usage.
- Use exact dates when summarizing status from roadmap or implementation docs.
- When a source appears stale or contradictory, note the tension and update the wiki only after checking the authoritative file.

## Suggested Ingest Pattern For Future Updates

When a substantial repo change lands:

1. read the changed canonical docs and nearby module/sample READMEs
2. update the matching wiki page summaries
3. refresh [`index.md`](./index.md) if the page catalog changed
4. append a dated note to [`log.md`](./log.md)

## Related Wiki Pages

- [`project-overview.md`](./project-overview.md)
- [`module-map.md`](./module-map.md)
- [`quality-and-release.md`](./quality-and-release.md)
