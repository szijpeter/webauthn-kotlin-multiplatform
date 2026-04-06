# samples:passkey-cli

Experimental CLI sample for end-to-end WebAuthn ceremonies with two authenticator modes.

This sample is intentionally scoped as a **POC**:

- browser-orchestrated platform passkeys (`browser`, default)
- native CTAP security-key interaction via `python-fido2` (`ctap`, optional)
- no published module/API impact

## Prerequisites

- Browser mode:
  - any modern browser with WebAuthn support
  - endpoint/origin must match (`--origin` defaults to endpoint origin)
- CTAP mode:
  - Python 3 (`python3`)
  - a compatible CTAP authenticator (for example, a USB security key)

Recommended self-contained setup (sample-local virtualenv):

```bash
./gradlew :samples:passkey-cli:bootstrapVenv
```

This creates `samples/passkey-cli/.venv` and installs dependencies from `requirements.txt`.
When this venv exists, the CLI auto-selects `samples/passkey-cli/.venv/bin/python` unless `--python-bin` is explicitly provided.

## Commands

Run with Gradle:

```bash
./gradlew :samples:passkey-cli:run --args="<command and options>"
```

Available commands:

- `doctor` checks environment readiness.
- `register` starts registration, invokes authenticator flow, and calls finish endpoint.
- `authenticate` starts authentication, invokes authenticator flow, and calls finish endpoint.

Common options:

- `--endpoint <url>` (default: `local.properties` `WEBAUTHN_DEMO_ENDPOINT`, else `http://localhost:8080`)
- `--rp-id <rpId>` (default: `local.properties` `WEBAUTHN_DEMO_RP_ID`, else endpoint host)
- `--origin <origin>` (default: `local.properties` `WEBAUTHN_DEMO_ORIGIN`, else endpoint origin)
- `--authenticator <browser|ctap>` (default: `browser`)
- `--python-bin <path>` (`ctap` mode only; default auto-detect local `.venv/bin/python`, then `python3`)
- `--python-bridge <path>` (`ctap` mode only; default resolves to `samples/passkey-cli/scripts/fido2_bridge.py`)

## Local Smoke Path (opt-in)

1. Start backend sample:

```bash
./gradlew :samples:backend-ktor:run
```

2. Verify CLI environment:

```bash
./gradlew :samples:passkey-cli:run --args="doctor"
```

3. Register with browser/platform passkey flow:

```bash
./gradlew :samples:passkey-cli:run --args="register --user-name alice --user-display-name Alice"
```

4. Authenticate with browser/platform passkey flow:

```bash
./gradlew :samples:passkey-cli:run --args="authenticate --user-name alice"
```

5. Optional CTAP security-key mode:

```bash
./gradlew :samples:passkey-cli:run --args="register --authenticator ctap --user-name alice --user-display-name Alice"
```

## Caveats

- Browser mode requires endpoint-origin alignment for WebAuthn origin checks.
- `python-fido2` behavior and HID access can vary by host permissions and hardware (`ctap` mode).
- This sample is intentionally not a production-grade native desktop authenticator SDK.
