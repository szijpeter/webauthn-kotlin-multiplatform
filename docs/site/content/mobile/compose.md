# Compose Multiplatform

The Compose adapter creates and remembers a passkey client and flow without placing product state inside the library. Use it at a stable screen or feature boundary and keep the active ceremony visible to users.

## Lifecycle model

<!-- diagram: public-compose-lifecycle-1 -->
<a href="../../../diagrams/assets/public-compose-lifecycle-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-compose-lifecycle-1-desktop-dark.svg">
  <img alt="Ceremony lifecycle. Product UI owns state, cancellation and the signed-in session." src="../../../diagrams/assets/public-compose-lifecycle-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Ceremony lifecycle</summary>
<p>Phone view: <a href="../../../diagrams/assets/public-compose-lifecycle-1-mobile-light.svg">light</a> · <a href="../../../diagrams/assets/public-compose-lifecycle-1-mobile-dark.svg">dark</a>.</p>
<p>Product UI owns state, cancellation and the signed-in session.</p>
<p>Nodes: [start]; Idle; Starting; PlatformPrompt; Finishing; Failed; SignedIn.</p>
<p>1. [start] → Idle.</p>
<p>2. Idle → Starting: user action.</p>
<p>3. Starting → PlatformPrompt: start response.</p>
<p>4. PlatformPrompt → Finishing: signed response.</p>
<p>5. Starting → Failed: network or contract error.</p>
<p>6. PlatformPrompt → Idle: user cancellation.</p>
<p>7. PlatformPrompt → Failed: platform error.</p>
<p>8. Finishing → SignedIn: server accepts.</p>
<p>9. Finishing → Failed: server rejects.</p>
<p>10. SignedIn → Idle: product logout.</p>
</details>
<!-- /diagram -->

Your UI should disable duplicate actions while a ceremony is active, expose cancellation as a normal outcome, and avoid retaining response payloads in logs or saveable UI state.

## Minimal state wiring

The repository sample keeps the flow stable across recomposition and leaves coordinator, session, and presentation state in the app.

<!-- doc-example: id=site-compose-kotlin-1; owner=sample; verify=sample-build; audience=consumer; source=sample/compose-passkey/src/commonMain/kotlin/dev/webauthn/samples/composepasskey/ui/screens/auth/AuthRoute.kt#compose-sample-auth-route -->
```kotlin
    val flow = rememberPasskeyFlow(passkeyClient)
    val scope = rememberCoroutineScope()
    val coordinator = remember(config, debugLogs, sessionStore) {
        AuthDemoCoordinator(config, debugLogs, sessionStore)
    }
    var state by remember { mutableStateOf<DemoCeremonyState>(DemoCeremonyState.Idle) }
    val canRegister by coordinator.canRegister.collectAsState()
    val actionsEnabled = areCeremonyActionsEnabled(state)
```

## Integration rules

- Construct platform-dependent objects only when their host is ready.
- Launch ceremonies from a user gesture in a lifecycle-aware coroutine.
- Let coroutine cancellation propagate; do not remap it to a platform failure.
- Prevent concurrent register/sign-in calls for the same screen state.
- Keep raw WebAuthn responses, PRF outputs, and session secrets out of snapshots and analytics.
- Treat previews as static UI contracts, not platform-prompt proof.

For a runnable host, open the staged [Compose passkey sample](../guides/samples/compose-passkey.md). For deeper state guidance, see [Compose lifecycle and UI state](../guides/compose-lifecycle.md).
