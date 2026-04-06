# Wiki Maintenance Schema

This file defines how agents should maintain `docs/wiki/`.

Repository-wide policy remains authoritative in [`docs/ai/STEERING.md`](../ai/STEERING.md). This file only adds wiki-specific structure and workflow.

## Purpose

This is a project wiki, not a personal wiki.

The goal is to keep a compact, cross-linked knowledge layer above the repository's canonical source documents so future contributors can answer questions quickly without rediscovering the same context.

## Three Layers

1. Raw sources
   - Canonical project docs under `docs/`
   - Root `README.md`
   - Module and sample `README.md` files
   - `spec-cache/` and `spec-notes/`
   - Relevant build files and source code
2. Wiki
   - Markdown pages in `docs/wiki/`
   - These pages summarize, connect, and contextualize raw sources
3. Schema
   - This file plus repository-level agent guidance

Agents may summarize and cross-link raw sources, but should not treat the wiki as more authoritative than the original files it cites.

## Operations

### Ingest

When new project docs, modules, samples, or major implementation changes land:

1. Read the changed source docs first.
2. Update the most relevant existing wiki pages before creating new ones.
3. Add new pages only when a concept cannot fit cleanly into the current structure.
4. Update [`index.md`](./index.md) if page inventory or summaries changed.
5. Append an exact-date entry to [`log.md`](./log.md).

### Query

When answering questions from the wiki:

1. Read [`index.md`](./index.md) first.
2. Open the most relevant wiki pages.
3. Follow links back to raw sources when precision or freshness matters.
4. Prefer exact dates over relative time words.

### Lint

Periodically check for:

- stale status statements
- pages that duplicate each other
- missing links between related pages
- wiki claims that no longer match canonical docs
- module or sample additions not reflected in [`module-map.md`](./module-map.md) or [`index.md`](./index.md)

## Page Conventions

- Keep pages short and synthesis-oriented.
- Use relative markdown links between wiki pages and back to source docs.
- Prefer exact module names and exact dates.
- Note when a page reflects current status rather than a permanent architectural truth.
- Avoid copying large code examples from source docs unless they are essential.
- Preserve append-only behavior in [`log.md`](./log.md).

## Current Page Set

- `README.md`: human landing page
- `index.md`: wiki catalog
- `log.md`: chronological change log
- `project-overview.md`: repo mission and quick orientation
- `module-map.md`: module families and adoption paths
- `client-stack.md`: client architecture and integration flow
- `server-stack.md`: server architecture and integration flow
- `samples-and-demos.md`: runnable reference apps and demos
- `quality-and-release.md`: quality gates, compatibility, release workflow
- `status-and-roadmap.md`: maturity snapshot and priorities
- `specs-and-sources.md`: standards and canonical source map
