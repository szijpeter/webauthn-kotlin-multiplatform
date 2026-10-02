# Public documentation maintenance

The public site leads with Android, iOS, and Compose adoption, then completes the trust boundary with the JVM/Ktor backend. Authored guide pages live in `docs/site/content`; the build stages release-artifact READMEs, selected runnable sample READMEs, generated platform facts, and aggregated Dokka output without copying those sources into a second maintained tree.

## Source boundaries

- `docs/site/content` contains curated public journeys and reference landing pages.
- Published artifact pages are discovered from the repository's publishing plugins and require a module README.
- The native Swift package and ceremony-flow guides plus four selected end-to-end sample READMEs are staged.
- `docs/ai`, spec caches/notes, Gradle state, build output, and arbitrary repository Markdown are excluded.
- Relative links in relocated repository READMEs are rewritten to another staged page or a commit-pinned repository URL.
- Platform baselines and stable artifact versions are derived during staging and fail when expected source declarations drift.

Every user-facing fenced block remains subject to the repository documentation-example contract. Edit canonical source regions for source-, sample-, and configuration-owned examples, then update and verify them through Gradle.

## Commands

Update synchronized example bodies:

<!-- doc-example: id=site-maintenance-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew docsSiteUpdate --stacktrace
```

Run unit tests, documentation verification, strict static rendering, Dokka generation, and internal link/anchor checks:

<!-- doc-example: id=site-maintenance-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew docsSiteCheck --stacktrace
```

Build and serve the complete site locally:

<!-- doc-example: id=site-maintenance-bash-3; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/docs/site.sh serve
```

Re-resolve the hash-locked Python environment only when intentionally updating the documentation toolchain:

<!-- doc-example: id=site-maintenance-bash-4; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/docs/site.sh lock
```

Review the entire lock diff and rebuild from a fresh virtual environment after a toolchain update.

## Deployment gate

Pull requests and `main` build the same artifact. Pull requests receive only a private workflow artifact; they never deploy untrusted code. The deploy job also requires the `DOCS_PAGES_DEPLOYMENT_ENABLED` repository variable, a successful build, and the protected `github-pages` environment. Enabling Pages, changing the repository homepage, and approving the first public deployment remain explicit maintainer actions.

## Change checklist

- Keep mobile first in the homepage, primary navigation, search vocabulary, and launch review.
- Label compilation, simulator/emulator, physical-device, and production evidence precisely.
- Keep Android library and optional-sample minimums distinct.
- Keep iOS target publication, host deployment target, and optional-feature minimums distinct.
- Update the owning module README when its public responsibility or integration changes.
- Add new published artifacts through the existing publishing plugin so catalog completeness remains testable.
- Inspect the built artifact for unintended files before enabling deployment.
