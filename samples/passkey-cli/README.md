# samples:passkey-cli

Experimental macOS-first CLI sample for end-to-end WebAuthn ceremonies without a browser prompt.

This sample is intentionally scoped as a **POC**:

- macOS-first support path
- native CTAP security-key interaction via `python-fido2`
- no published module/API impact
- synced platform passkeys are not covered in this first iteration

## Prerequisites

- Python 3 (`python3`)
- A compatible CTAP authenticator (for example, a USB security key)

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
- `register` starts registration, invokes native authenticator flow, and calls finish endpoint.
- `authenticate` starts authentication, invokes native authenticator flow, and calls finish endpoint.

Common options:

- `--endpoint <url>` (default: `http://127.0.0.1:8080`)
- `--rp-id <rpId>` (default: `localhost`)
- `--origin <origin>` (default: `https://localhost`)
- `--python-bin <path>` (default: auto-detect local `.venv/bin/python`, then `python3`)
- `--python-bridge <path>` (default resolves to `samples/passkey-cli/scripts/fido2_bridge.py`)

## Local Smoke Path (opt-in)

1. Start backend sample:

```bash
./gradlew :samples:backend-ktor:run
```

2. Verify CLI environment:

```bash
./gradlew :samples:passkey-cli:run --args="doctor"
```

3. Register:

```bash
./gradlew :samples:passkey-cli:run --args="register --user-name alice --user-display-name Alice"
```

4. Authenticate:

```bash
./gradlew :samples:passkey-cli:run --args="authenticate --user-name alice"
```

## Caveats

- `python-fido2` behavior and HID access can vary by host permissions and hardware.
- This sample is intentionally not a production-grade native desktop authenticator SDK.
