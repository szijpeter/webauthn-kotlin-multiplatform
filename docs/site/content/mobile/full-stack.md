# Full mobile + backend sample

The repository includes a Compose Multiplatform app, Android and iOS hosts, and a Ktor backend. This is the fastest way to observe the complete registration and authentication boundary before integrating individual modules.

## Topology

<!-- diagram: public-full-stack-topology-1 -->
<a href="../../../diagrams/assets/public-full-stack-topology-1-desktop-light.svg">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../../diagrams/assets/public-full-stack-topology-1-desktop-dark.svg">
  <img alt="Full-stack topology. The mobile flow connects platform credential APIs to the relying-party backend." src="../../../diagrams/assets/public-full-stack-topology-1-desktop-light.svg" width="640" loading="lazy">
</picture>
</a>
<details>
<summary>Diagram text: Full-stack topology</summary>
<p>Phone view: <a href="../../../diagrams/assets/public-full-stack-topology-1-mobile-light.svg">light</a> · <a href="../../../diagrams/assets/public-full-stack-topology-1-mobile-dark.svg">dark</a>.</p>
<p>The mobile flow connects platform credential APIs to the relying-party backend.</p>
<p>Nodes: Compose shared UI and flow; Android Credential Manager; iOS Authentication Services; Ktor sample backend; Registration and authentication services; Ceremony and credential stores; Association endpoints.</p>
<p>1. Compose shared UI and flow → Android Credential Manager.</p>
<p>2. Compose shared UI and flow → iOS Authentication Services.</p>
<p>3. Compose shared UI and flow ↔ Ktor sample backend.</p>
<p>4. Ktor sample backend → Registration and authentication services.</p>
<p>5. Registration and authentication services → Ceremony and credential stores.</p>
<p>6. Ktor sample backend → Association endpoints.</p>
</details>
<!-- /diagram -->

## Local Android path

Start the backend:

<!-- doc-example: id=site-full-stack-bash-1; owner=markdown; verify=syntax; audience=consumer -->
```bash
./gradlew :sample:backend-ktor:run
```

Install the Android host against the emulator's host alias. On Android 17, direct private-network endpoints require the platform's local-network permission; the committed sample requests it only when the flag below is enabled.

<!-- doc-example: id=site-full-stack-bash-2; owner=markdown; verify=syntax; audience=consumer -->
```bash
WEBAUTHN_DEMO_ENDPOINT=http://10.0.2.2:8080 \
WEBAUTHN_DEMO_REQUEST_LOCAL_NETWORK_PERMISSION=true \
./gradlew :sample:compose-passkey-android:installDebug
```

The base libraries and the PRF-enabled sample intentionally have different Android minimums. Read the generated [platform support matrix](../reference/platform-support.md).

## Physical-device path

Use the repository helper to start the server with a public HTTPS tunnel and synchronize local sample settings:

<!-- doc-example: id=site-full-stack-bash-3; owner=markdown; verify=syntax; audience=consumer -->
```bash
./sample/backend-ktor/start-server.sh
```

For iOS, open the committed Xcode project, configure your signing team and bundle ID, and run it on a physical device. Complete ceremonies require a domain association that matches that signed identity.

## What to exercise

1. Register a new passkey.
2. Sign out locally and authenticate with the registered passkey.
3. Cancel a prompt and confirm the UI returns to idle.
4. Repeat or replay a finish request and confirm the server rejects it.
5. Observe capability results before enabling PRF-dependent actions.
6. Review logs without enabling sensitive HTTP body logging.

Detailed operational notes live in the staged [Compose app guide](../guides/samples/compose-passkey.md) and [backend sample guide](../guides/samples/backend-ktor.md).
