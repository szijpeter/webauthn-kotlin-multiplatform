# samples:passkey-cli

Experimental macOS-first CLI sample for end-to-end WebAuthn ceremonies without a browser prompt.

This sample is intentionally scoped as a **POC**:

- macOS-first support path
- native CTAP security-key interaction via `python-fido2`
- no published module/API impact
- synced platform passkeys are not covered in this first iteration

## Prerequisites

- Python 3 (`python3`)
- `python-fido2`:

```bash
python3 -m pip install fido2
```

Optional virtualenv flow:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install fido2
./gradlew :samples:passkey-cli:run --args="doctor --python-bin $(pwd)/.venv/bin/python"
```

- A compatible CTAP authenticator (for example, a USB security key)

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
- `--python-bin <path>` (default: `python3`)
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
