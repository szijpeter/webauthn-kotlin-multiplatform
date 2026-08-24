# Capabilities and extensions

WebAuthn extensions are negotiated capabilities, not compile-time promises. Probe at runtime, keep the base passkey ceremony useful without optional extensions, and design fallback behavior before enabling extension-dependent UI.

## Capability-driven UI

- Probe support before presenting PRF, Large Blob, or security-key-specific actions.
- Cache capability observations only as hints; re-check when platform or account state can change.
- Keep the ordinary registration and authentication paths independent of optional extension success.
- Treat an extension output as credential-bound input requiring its own validation and storage policy.

## PRF

The pseudo-random function extension can derive credential-bound material after authentication. It does not automatically become a general password vault. Salt persistence, key-derivation context, encrypted data lifecycle, recovery, credential deletion, and fallback UX remain application responsibilities.

!!! danger "Plan for irrecoverability"
    If encrypted data depends only on a passkey's PRF output and that credential is deleted or becomes unavailable, the data can become unrecoverable. Design recovery and account migration before shipping.

Use the [PRF application crypto guide](../guides/prf.md) for the full ownership model.

## Evidence levels

| Evidence | What it establishes | What remains unproven |
| --- | --- | --- |
| Common-source compilation | API and type compatibility | Platform availability |
| Platform-source compilation | Bridge availability for target SDK | Provider or entitlement behavior |
| Simulator/emulator tests | Selected runtime and lifecycle behavior | Production signing/account state |
| Physical-device ceremony | Provider-backed behavior for tested configuration | All device/account/provider combinations |

Record the tested OS, provider, account state, signing identity, RP domain, and extension outcome when reporting compatibility.
