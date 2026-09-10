# Mobile troubleshooting

Diagnose the first failing boundary. A generic “passkey error” often hides whether the failure occurred before the platform prompt, inside the platform API, in transport, or during authoritative server validation.

## Boundary-first flow

<!-- diagram: public-troubleshooting-flow-1 -->
<a href="../../../diagrams/assets/public-troubleshooting-flow-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-troubleshooting-flow-1-desktop-dark.svg">
  <img alt="Find the failing boundary. Follow each labelled branch before investigating the next integration boundary." src="../../../diagrams/assets/public-troubleshooting-flow-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Find the failing boundary</summary>
<p>Phone view: <a href="../../../diagrams/assets/public-troubleshooting-flow-1-mobile-light.svg">light</a> · <a href="../../../diagrams/assets/public-troubleshooting-flow-1-mobile-dark.svg">dark</a>.</p>
<p>Follow each labelled branch before investigating the next integration boundary.</p>
<p>Nodes: User starts ceremony; Start endpoint succeeds?; Inspect network, auth, and backend start logs; Platform prompt appears?; Inspect host lifecycle, provider, entitlement, and association; Platform returns a credential?; Classify cancellation, invalid options, or platform error; Finish endpoint accepts?; Inspect challenge, origin, RP ID, signature, state, and policy; Update product session.</p>
<p>1. User starts ceremony → Start endpoint succeeds?.</p>
<p>2. Start endpoint succeeds? → Inspect network, auth, and backend start logs: no.</p>
<p>3. Start endpoint succeeds? → Platform prompt appears?: yes.</p>
<p>4. Platform prompt appears? → Inspect host lifecycle, provider, entitlement, and association: no.</p>
<p>5. Platform prompt appears? → Platform returns a credential?: yes.</p>
<p>6. Platform returns a credential? → Classify cancellation, invalid options, or platform error: no.</p>
<p>7. Platform returns a credential? → Finish endpoint accepts?: yes.</p>
<p>8. Finish endpoint accepts? → Inspect challenge, origin, RP ID, signature, state, and policy: no.</p>
<p>9. Finish endpoint accepts? → Update product session: yes.</p>
</details>
<!-- /diagram -->

## Collect safe evidence

Capture the platform, OS version, Android package or iOS bundle identity, signing environment, RP ID, endpoint host, result category, and the first causal server or platform error. Do not capture raw attestation objects, authenticator data, signatures, PRF output, cookies, bearer tokens, or full request/response bodies in shared logs.

## Frequent causes

### The prompt never appears

Check the foreground host, Activity/window availability, configured provider, device lock, account state, entitlements, and association files. If start options are malformed, the client can reject them before prompting.

### Registration works but authentication does not

Confirm the credential is stored under the account being queried, the authentication allow-list or discoverable-credential policy is intentional, and the server resolves the returned credential ID to the correct user and RP.

### Works locally, fails on production domain

Fetch the deployed association documents over HTTPS, verify redirects and content type behavior, and compare the exact signed app identity. Also compare production RP ID and allowed origins with the values used to generate the ceremony.

### Cancellation becomes an error banner

Preserve the typed cancellation outcome through shared Kotlin and the host facade. Reset active UI state without automatic retry.

### Finish is rejected

Inspect server-side validation. Common boundaries include expired or consumed ceremony state, challenge mismatch, unexpected origin, RP ID hash mismatch, credential/account mismatch, signature failure, and policy rejection.
