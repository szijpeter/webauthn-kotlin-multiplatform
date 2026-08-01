# Documentation example verification

The repository manages every user-facing fenced block in Markdown and every fenced Kotlin example in KDoc.
The generated [example inventory](../documentation/example-inventory.md) records the stable identifier,
purpose, audience, owner, source of truth, verification level, and any exception for each block.

## Ownership

Each block has one inline `doc-example` directive:

- `source`: the visible block is generated from a `docs-region` in compiled example source.
- `sample`: the block is generated from a region in a runnable sample.
- `configuration`: the block is generated from a committed Gradle consumer fixture.
- `markdown`: Markdown owns a non-Kotlin block that has a direct verifier, currently shell syntax.
- `illustrative`: execution is not meaningful, so the directive must include a reason.

Kotlin blocks cannot be Markdown-owned. Use source-backed compiled code for focused API examples, a sample
region for an excerpt from a complete application, or a configuration fixture for Gradle Kotlin DSL.
Prefer a link to the complete sample when an excerpt would be too large to teach one idea clearly.

For source-, sample-, and configuration-owned examples, the source path and region in a directive are
canonical: edit that file between its matching `docs-region` and `docs-endregion` markers, then run
`./gradlew docsUpdate`. Markdown-owned shell examples are edited directly in Markdown. Illustrative blocks
are also edited directly in Markdown and must include a concise reason explaining why executable verification
is not applicable. Do not edit the generated inventory directly.

## Verification

`./gradlew docsCheck` is the aggregate check. It rejects unmanaged or duplicate identifiers, stale generated
content, invalid directives, missing regions, and invalid shell syntax. It also runs the extractor tests,
compiles and behavior-tests public API examples on JVM, compiles Android and iOS examples, builds the
canonical Compose sample targets, and confirms that documentation projects are absent from publication
plugins and the BOM.

Verification levels describe the strongest guarantee: `syntax` parses shell syntax; `compile` compiles
repository-owned Kotlin examples against project dependencies; `platform-compile` compiles Android or iOS
source sets; `unit` compiles and exercises an explicitly allow-listed behavior test; `sample-build` is covered
by a real sample build; `consumer-compile` compiles configuration in the separate Maven-local consumer
fixture; and `illustrative` makes no executable correctness claim. Platform compilation does not claim that
Credential Manager, AuthenticationServices, entitlements, associated domains, providers, or hardware work
on a real device. Illustrative blocks require a reason.

Run `./gradlew docsUpdate` after changing a canonical region or adding a managed block. Review the generated
diff, then run `./gradlew docsCheck`. Prose-only changes run the fast catalog check through the changed-scope
quality gate; blocking CI always runs the full repository-wide check.

## Tool choice

Compatibility spikes used the repository's Kotlin 2.4.10 syntax, including collection literals. Kotlinx
Knit 0.5.1 successfully generated and compiled a documentation-owned example. Korro 0.2.2 successfully
extracted a source-owned example, but its plugin currently brings Kotlin Analysis API 2.3.20 into a
Kotlin 2.4.10 build. Neither tool covers shell blocks, Gradle consumer fixtures, the complete inventory,
explicit illustrative classifications, or mixed Markdown and KDoc ownership by itself.

The selected repository-owned verifier is syntax-agnostic and region-based. It avoids parser-version
coupling, gives Kotlin syntax to the actual project compilers, and supplies the remaining inventory,
configuration, and unmanaged-block guarantees without a second overlapping generator. The tooling is
isolated under `documentation/tooling`; compilable examples live under `documentation/examples`; the
Maven-local fixture lives under `documentation/consumer-smoke`.
