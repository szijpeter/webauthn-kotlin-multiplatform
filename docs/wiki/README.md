# Project Wiki

This directory is a project wiki for `webauthn-kotlin-multiplatform`.

It follows the [LLM wiki pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f), but adapted for a repository-maintained project wiki instead of a personal knowledge base:

- Raw sources stay in the rest of the repository: root docs, module `README.md` files, `spec-cache/`, `spec-notes/`, build files, and code.
- The wiki in `docs/wiki/` is the synthesized layer: short, cross-linked pages that explain how the project fits together.
- The schema for maintaining this wiki lives in [`AGENTS.md`](./AGENTS.md).

Start here:

- [`index.md`](./index.md): catalog of wiki pages.
- [`project-overview.md`](./project-overview.md): what the project is and how to orient quickly.
- [`module-map.md`](./module-map.md): module families, publication boundaries, and adoption paths.
- [`client-stack.md`](./client-stack.md): shared and platform client flow.
- [`server-stack.md`](./server-stack.md): server, crypto, storage, and Ktor adapter flow.
- [`quality-and-release.md`](./quality-and-release.md): quality gates, API compatibility, and release posture.
- [`status-and-roadmap.md`](./status-and-roadmap.md): current maturity and next priorities.
- [`specs-and-sources.md`](./specs-and-sources.md): normative standards and high-value repo source docs.
- [`log.md`](./log.md): append-only record of wiki changes.

Use this wiki as the navigation layer. When detail matters, follow links back to the canonical source files.
