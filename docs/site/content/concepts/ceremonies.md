# Registration and authentication

WebAuthn defines two server-authoritative ceremonies. The authenticator creates or uses a credential, but the relying-party server decides whether the signed result satisfies its challenge, origin, RP ID, account, and policy constraints.

## Registration

<!-- diagram: public-ceremonies-registration-1 -->
<a href="../../../diagrams/assets/public-ceremonies-registration-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-ceremonies-registration-1-desktop-dark.svg">
  <img alt="Registration. The private key stays with the authenticator; the server validates the public credential." src="../../../diagrams/assets/public-ceremonies-registration-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Registration</summary>
<p>Phone view: <a href="../../../diagrams/assets/public-ceremonies-registration-1-mobile-light.svg">light</a> · <a href="../../../diagrams/assets/public-ceremonies-registration-1-mobile-dark.svg">dark</a>.</p>
<p>The private key stays with the authenticator; the server validates the public credential.</p>
<p>Nodes: Mobile app; RP server; Platform credential API; Authenticator.</p>
<p>1. Mobile app → RP server: registration/start(account context).</p>
<p>2. RP server → RP server: store short-lived challenge state.</p>
<p>3. RP server → Mobile app: creation options (dashed).</p>
<p>4. Mobile app → Platform credential API: create credential(options).</p>
<p>5. Platform credential API → Authenticator: user verification and key creation.</p>
<p>6. Authenticator → Platform credential API: public-key credential response (dashed).</p>
<p>7. Platform credential API → Mobile app: raw registration response (dashed).</p>
<p>8. Mobile app → RP server: registration/finish(raw response).</p>
<p>9. RP server → Mobile app: accepted account result or rejection (dashed).</p>
</details>
<!-- /diagram -->

The private key stays with the authenticator. The server stores the public credential and its account binding after validation.

## Authentication

The server creates an assertion challenge. The authenticator signs authenticator data together with the hash of the exact `clientDataJSON`. The server resolves the credential, verifies the signature and signed context, applies ownership and policy, consumes ceremony state, and only then establishes a product session.

## Identified versus discoverable

An identified flow starts with an account hint and normally restricts `allowCredentials`. A discoverable flow starts without a username, lets the authenticator select a resident credential, and resolves the authoritative account after receiving the credential. Neither mode permits the client to assert account ownership.

## Cancellation and retries

User cancellation is expected control flow. A retry should start a fresh ceremony unless your backend explicitly supports safe reuse; never replay a signed response against a new challenge or silently resubmit a consumed finish request.
