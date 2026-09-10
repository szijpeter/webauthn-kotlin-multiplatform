# Documentation diagrams

This is the maintained diagram collection for GitHub and the public documentation site. It replaces the 30 Mermaid fences in the root README, architecture guide, public journeys, and module READMEs. Both hosts use the same committed SVGs; neither needs a diagram service or client-side renderer.

The visual language adapts [Diagram Design 2.6.21](https://github.com/cathrynlavery/diagram-design/tree/562dbdf93ff3c3da630be4f90f4f6c2548175058) to the documentation site's palette and system fonts. The approved repository overview keeps its hand-authored orthogonal layout. Other graphs use reviewed routing proposals, sequences use lifelines, and small-screen views expose each relationship in readable cards. Dense graphs are split into focused panels. Attribution is in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Sources and generated files

| File | Ownership and purpose |
| --- | --- |
| `catalog.json` | One stable diagram ID and owning Markdown page per entry. |
| `sources/*.json` | Authoritative labels, node types, group membership, directed relationships, optional/dashed relationships, ordered messages and panel assignments. Review these semantic diffs first. |
| `layouts/*.json` | Reviewed desktop coordinates and connector control points. A semantic digest prevents reuse after a graph changes. These are authoring inputs, not build outputs. |
| `templates/overview.html` | Hand-authored overview in desktop and mobile arrangements. The exporter checks its labels and directed edges against `sources/readme-2.json`. |
| `assets/*.svg` | Generated desktop/mobile × light/dark exports; never edit directly. |
| `gallery.html`, `manifest.json` | Generated offline review gallery and export hashes. |
| Markdown `diagram` blocks | Generated responsive pictures and expandable text equivalents. The surrounding prose belongs to the page author. |

The schema is intentionally a small repository contract, not a general Mermaid parser or drawing application. A node records `id`, `label`, `shape`, `parent` and `container`. An edge records its endpoints, label, style and direction flags. Panels partition edges exactly once; repeated nodes supply context. Sequence phases retain global message order. Add a renderer test before introducing a new semantic construct.

## Author and update

The author who changes a module boundary or ceremony also updates its diagram source and owning guide in the same PR. Reviewers check architecture meaning and visual clarity together. No special account, AI model, remote font, or paid service is needed to maintain the collection.

1. Edit the owning JSON source. Preserve optionality, source-set labels, group membership, isolated nodes, and message order. Add new IDs to the catalog and place a paired `<!-- diagram: id -->` / `<!-- /diagram -->` block in the owning page.
2. For a graph change, review and adjust its layout. The optional helper below uses a locally installed Graphviz to propose coordinates; it records the tool version. The migration used Graphviz 14.1.4. Different authoring versions may propose different layouts, so inspect their diffs. Graphviz is not installed or invoked by normal builds, CI, or releases. Sequence and mobile-card geometry is computed by the exporter. For the bespoke overview, update its HTML template too.
3. Export, inspect the gallery at desktop and phone widths in both themes, then run the checks. Read complete labels, trace arrows in both directions, and inspect cancellation/error paths. Numeric edge keys refer to the adjacent label legend; group membership is explicit below the graph.
4. Commit sources, reviewed layouts, exports, embeds and the manifest together. Run `docsUpdate` before `docsCheck` as separate invocations.

Optional layout proposal, for one changed graph:

<!-- doc-example: id=diagram-maintenance-layout; owner=markdown; verify=syntax; audience=contributor -->
```bash
python3 tools/docs/diagrams_layout.py docs-architecture-3
```

Fast offline export and validation, using Python's standard library:

<!-- doc-example: id=diagram-maintenance-export; owner=markdown; verify=syntax; audience=contributor -->
```bash
python3 tools/docs/diagrams.py update
python3 tools/docs/diagrams.py check
python3 tools/docs/test_diagrams.py
```

Repository integration and full site verification:

<!-- doc-example: id=diagram-maintenance-gradle; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew docsUpdate --stacktrace
./gradlew docsSiteCheck --stacktrace
```

Open `docs/diagrams/gallery.html` in a browser for the offline gallery. GitHub displays HTML source when that file is opened through the repository UI; the generated pictures in Markdown are the GitHub viewing surface. The [original comparison](../experiments/architecture-visuals/README.md) retains the before/after evidence for the approved overview.

## GitHub, accessibility and the public site

GitHub uses desktop previews capped at 640 CSS pixels, with light/dark sources and a desktop light fallback. Click a preview for the full-size SVG; phone-view links are inside its expandable text. Keep width conditions out of GitHub's theme sources: GitHub rewrites theme media queries and can discard a combined width condition, causing a tall phone image to appear at desktop size. The offline gallery and public site retain responsive phone layouts at 720 CSS pixels.

Every image has meaningful alternative text. Expandable text includes all labels, group memberships and relationships even when images are unavailable. Standalone SVGs also contain titles and descriptions. Small-screen relationship cards repeat nodes deliberately; their direction and relationship labels retain the desktop graph's meaning.

Site staging replaces registered blocks with local picture paths appropriate to the built page, including relocated module READMEs. CSS follows Material's explicit light/dark theme switch, independently of system preference. Only registered SVG assets enter the site. The HTML check validates `srcset` as well as `src`, and rejects asset paths outside the site. Authoring templates, sources and tools are not added to the public site.

Automated checks cover catalog completeness, current exports and embeds, semantic/layout synchronization, panel coverage, sequence order, isolated nodes, node overlap and canvas bounds, accessible SVG metadata, forbidden active/external SVG content, and responsive asset links. These checks do not establish visual perfection or prove runtime security behavior. Human review at both widths and themes remains required.

## CI and releases

`docsCheck` and `docsSiteStage` depend on `docsDiagramsCheck`, including focused Python tests. `docsUpdate` includes `docsDiagramsUpdate`. New public Mermaid fences and unregistered diagram blocks fail the freshness check. The documentation workflow watches the collection and owning root/architecture pages, builds the complete site, and uploads a review artifact containing the site, reports and an offline diagram bundle.

The manual publishing workflow verifies diagrams **before Maven Central publication**. For `publish-and-release`, the existing separate GitHub-release job attaches `webauthn-diagrams.zip` to the release. It contains the sources, reviewed layouts, SVGs, offline gallery, attribution and a `provenance.json` with the exact release commit and file hashes. ZIP timestamps are fixed so the same inputs and commit reproduce the same archive. The archive is a GitHub release asset; it does not enter Maven artifacts or change SDK versions.

The release bundle records a source snapshot. The live documentation site still follows its existing protected Pages deployment flow and can advance independently of a release. Creating a release, tag or deployment remains a maintainer action. A documentation-only migration does not require a Maven release.
