# Security Policy

## Supported Versions

This project is currently pre-1.0 and evolves quickly. Security fixes are applied on a best-effort basis to:

- the latest commit on `main`
- the most recent release tag, when available

Older commits and snapshots are generally unsupported.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for this repository:

1. Open the repository Security tab.
2. Choose "Report a vulnerability".
3. Submit a private report with impact, reproduction steps, and any proof of concept.

Please do not open public issues for suspected vulnerabilities.

## Disclosure Process

- Initial maintainer response target: within 3 business days.
- Triage and severity assessment target: within 7 business days.
- Fix timeline depends on severity and scope; critical issues are prioritized first.
- After remediation, disclosure details are coordinated through GitHub Security Advisories.

## Scope Notes

When reporting, include affected module(s), threat model assumptions, and whether behavior conflicts with WebAuthn/RFC requirements. This helps triage quickly for security-sensitive validation and attestation paths.

## Automated Security Checks

- CodeQL runs on GitHub Actions workflow files (`language: actions`).
- Java/Kotlin CodeQL scanning is temporarily disabled while the current CodeQL CLI toolchain does not support Kotlin `2.3.10`.
- Dependency risk is enforced on pull requests via `actions/dependency-review-action`.
