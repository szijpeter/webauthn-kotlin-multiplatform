# Spec Cache

This directory stores local references to standards used by this repository.

## Purpose

1. Keep the WebAuthn spec close to implementation work.
2. Reduce context switching while mapping code to normative behavior.
3. Preserve dated snapshots used for review discussions.

## Policy

1. Normative source of truth remains upstream W3C specs.
2. Cached files are convenience artifacts only.
3. Include snapshot metadata (source URL and date) alongside cached files.

## Layout

- `webauthn/` WebAuthn-specific cached references and metadata.

## Update

Run:

```bash
tools/spec-cache/update-webauthn-cache.sh
```
