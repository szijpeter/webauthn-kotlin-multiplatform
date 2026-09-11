# Sample UI gallery

The Compose Android, Compose iOS, and native SwiftUI samples share the same information hierarchy,
with Material controls on Android, Calf adaptive controls in Compose iOS, and native SwiftUI controls.
All three use neutral surfaces in light and dark appearance, tinted secondary actions, and red sign-out
buttons. Status icons, explicit capability values, and disabled actions communicate state without
relying on color alone.

These screenshots use deterministic Debug fixtures with public example data. Success, capability,
and encrypted-message states demonstrate rendering; they do not represent a captured live ceremony
or prove authenticator support. The live app uses the existing client, backend, and session wiring.

## Phone appearance

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Authentication · light | <img width="190" alt="Compose Android: Authentication · light" src="https://github.com/user-attachments/assets/5b586a88-4625-44d7-9f93-97ff8f1f477f"> | <img width="190" alt="Compose iOS: Authentication · light" src="https://github.com/user-attachments/assets/6f54a934-2ae2-4bda-b17e-c4861f820ebf"> | <img width="190" alt="Native SwiftUI: Authentication · light" src="https://github.com/user-attachments/assets/520256f9-f71c-4ed3-b6f1-4ced8dd686db"> |
| Authentication · dark | <img width="190" alt="Compose Android: Authentication · dark" src="https://github.com/user-attachments/assets/c49f8035-892d-4dd9-a616-bd7796e90fc7"> | <img width="190" alt="Compose iOS: Authentication · dark" src="https://github.com/user-attachments/assets/273d23c8-ff95-4c1a-892b-311af74e7caf"> | <img width="190" alt="Native SwiftUI: Authentication · dark" src="https://github.com/user-attachments/assets/0b7377a1-cf71-4efb-9d71-90a4385f20eb"> |
| PRF encryption · light | <img width="190" alt="Compose Android: PRF encryption · light" src="https://github.com/user-attachments/assets/a80ffff8-3d81-46e2-aea5-937f885be106"> | <img width="190" alt="Compose iOS: PRF encryption · light" src="https://github.com/user-attachments/assets/47af4f51-28ff-4446-aedc-409be123daf6"> | <img width="190" alt="Native SwiftUI: PRF encryption · light" src="https://github.com/user-attachments/assets/9d790952-62fd-47c5-ae36-08608f64118e"> |
| PRF encryption · dark | <img width="190" alt="Compose Android: PRF encryption · dark" src="https://github.com/user-attachments/assets/598342b6-7d09-4fd6-a9af-616123794f1a"> | <img width="190" alt="Compose iOS: PRF encryption · dark" src="https://github.com/user-attachments/assets/01613db4-ecdb-475f-b2a1-ccc9db9808d4"> | <img width="190" alt="Native SwiftUI: PRF encryption · dark" src="https://github.com/user-attachments/assets/828a4c8a-93bf-4e07-afa7-6113014d5adf"> |

## Status, capability, and diagnostic states

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Busy authentication | <img width="190" alt="Compose Android: Busy authentication" src="https://github.com/user-attachments/assets/004f0a63-a297-4915-ad53-89021c0d6f16"> | <img width="190" alt="Compose iOS: Busy authentication" src="https://github.com/user-attachments/assets/244a414b-45d5-4312-be01-97e38a4eb608"> | <img width="190" alt="Native SwiftUI: Busy authentication" src="https://github.com/user-attachments/assets/327e7f3c-0bfa-409b-bb3d-72842e8e07a9"> |
| Registration complete | <img width="190" alt="Compose Android: Registration complete" src="https://github.com/user-attachments/assets/69186011-520e-4925-a4ce-6909ede1dc8b"> | <img width="190" alt="Compose iOS: Registration complete" src="https://github.com/user-attachments/assets/c3f5f72b-9afb-4260-91cd-eb53b9c45b1e"> | <img width="190" alt="Native SwiftUI: Registration complete" src="https://github.com/user-attachments/assets/ccc8382b-d3b0-4cf0-acc9-1f4165c0db73"> |
| Cancelled sign-in | <img width="190" alt="Compose Android: Cancelled sign-in" src="https://github.com/user-attachments/assets/012af9d6-4db3-465b-8a51-5a794dc180f6"> | <img width="190" alt="Compose iOS: Cancelled sign-in" src="https://github.com/user-attachments/assets/59840a37-23d0-43a4-8f8d-981e27a12f91"> | <img width="190" alt="Native SwiftUI: Cancelled sign-in" src="https://github.com/user-attachments/assets/cb407009-b5a3-4c63-bb5c-ab5e731daaf3"> |
| Server rejection | <img width="190" alt="Compose Android: Server rejection" src="https://github.com/user-attachments/assets/236bc3d6-9985-4547-b8d4-017e7b92d58c"> | <img width="190" alt="Compose iOS: Server rejection" src="https://github.com/user-attachments/assets/ada87e0e-7777-49cd-8db9-f54977281700"> | <img width="190" alt="Native SwiftUI: Server rejection" src="https://github.com/user-attachments/assets/eb7d13d1-e438-4c04-bf41-8da2dbb42194"> |
| Connection error | <img width="190" alt="Compose Android: Connection error" src="https://github.com/user-attachments/assets/b02ceae8-b593-4457-bf39-99f90b467b87"> | <img width="190" alt="Compose iOS: Connection error" src="https://github.com/user-attachments/assets/e02f2fde-d7dc-45e2-a151-89a1627778c9"> | <img width="190" alt="Native SwiftUI: Connection error" src="https://github.com/user-attachments/assets/911f6c66-42db-45e2-8d2c-62c5b846a358"> |
| PRF unavailable | <img width="190" alt="Compose Android: PRF unavailable" src="https://github.com/user-attachments/assets/9451e2dd-6091-4cb3-8c90-6a5bfaa2ddeb"> | <img width="190" alt="Compose iOS: PRF unavailable" src="https://github.com/user-attachments/assets/5bf1da53-c13f-47b9-b57c-b14704e9873f"> | <img width="190" alt="Native SwiftUI: PRF unavailable" src="https://github.com/user-attachments/assets/5252ffa7-be17-4103-a2ad-b0b4dd5a8e7b"> |
| Debug logs · dark | <img width="190" alt="Compose Android: Debug logs · dark" src="https://github.com/user-attachments/assets/996265e3-59f6-414a-9fc5-caa99c46d01d"> | <img width="190" alt="Compose iOS: Debug logs · dark" src="https://github.com/user-attachments/assets/a98e5ed8-f569-452f-8ad0-319c34a91bbd"> | <img width="190" alt="Native SwiftUI: Debug logs · dark" src="https://github.com/user-attachments/assets/e98f32e8-3c49-4b14-a835-9af3124acbee"> |

## Large layouts

The Android capture uses a 1200 × 1600 dp emulator viewport; the iOS captures use an iPad simulator.
Both layouts keep the PRF workspace beside capabilities, configuration, and session actions when space
permits. Increasing font size returns the content to a scrolling single column.

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Large layout with capabilities and expanded configuration | <img width="240" alt="Compose Android: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/2874b21e-1808-4c86-b555-d9155e70c982"> | <img width="240" alt="Compose iOS: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/996f12f1-6fd9-4285-8047-a76f046607b3"> | <img width="240" alt="Native SwiftUI: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/d48193dd-ab29-4159-a4c4-0581cacd8f9b"> |

## Reproduce the states

Use a Debug build and select a gallery state through the host's launch mechanism:

- **Compose Android:** intent string extra `sample-gallery`, for example `auth` or `encrypted`.
- **Compose iOS and native SwiftUI:** launch arguments `--sample-gallery` followed by the state.
- **Appearance and text size:** use the operating system's light/dark and accessibility settings.

Available states are `auth`, `busy`, `success`, `cancelled`, `rejected`, `error`, `session`, `encrypted`,
`unsupported`, `prf-busy`, and `logs`. Release hosts ignore the gallery entry point. Fixtures render
the actual screen components without creating a backend client, passkey, or PRF session.

See the [shared Compose sample](compose-passkey/README.md#appearance-accessibility-and-screenshot-fixtures),
[Compose iOS host](compose-passkey-ios/README.md), and
[native SwiftUI sample](swift-passkey/README.md#appearance-and-deterministic-gallery) for setup and tests.

The UI checks cover busy and terminal action availability, session-dependent crypto controls, editable
message state, log dismissal, and reaching configuration with large text. Live registration,
authentication, and PRF validation remain separate device checks described in the
[Compose readiness checklist](compose-passkey/READINESS_CHECKLIST.md).
