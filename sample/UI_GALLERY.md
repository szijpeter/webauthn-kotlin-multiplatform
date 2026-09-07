# Sample UI gallery

The Compose Android, Compose iOS, and native SwiftUI samples share the same information hierarchy,
with Material 3 controls in Compose and native controls in SwiftUI. All three follow system light and
dark appearance. Status text, explicit capability values, and disabled actions communicate state
without relying on color alone.

These screenshots use deterministic Debug fixtures with public example data. Success, capability,
and encrypted-message states demonstrate rendering; they do not represent a captured live ceremony
or prove authenticator support. The live app uses the existing client, backend, and session wiring.

## Phone appearance

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Authentication · light | <img width="190" alt="Compose Android: Authentication · light" src="https://github.com/user-attachments/assets/19f05916-6c8e-41a9-a2f5-b9baa3d59767"> | <img width="190" alt="Compose iOS: Authentication · light" src="https://github.com/user-attachments/assets/88668c27-0882-439e-a769-b4c484ef6acf"> | <img width="190" alt="Native SwiftUI: Authentication · light" src="https://github.com/user-attachments/assets/e87f7492-05eb-4186-9d00-5999ab90e273"> |
| Authentication · dark | <img width="190" alt="Compose Android: Authentication · dark" src="https://github.com/user-attachments/assets/3f6ec8f6-16f9-41f3-90de-d49f62004b03"> | <img width="190" alt="Compose iOS: Authentication · dark" src="https://github.com/user-attachments/assets/4adb5bc6-2665-4e73-8a2d-d4749e185640"> | <img width="190" alt="Native SwiftUI: Authentication · dark" src="https://github.com/user-attachments/assets/33a1627f-95f2-45e8-90a8-19d8df99fbf8"> |
| PRF encryption · light | <img width="190" alt="Compose Android: PRF encryption · light" src="https://github.com/user-attachments/assets/6493a2c6-a469-45f3-8639-7c79d515220e"> | <img width="190" alt="Compose iOS: PRF encryption · light" src="https://github.com/user-attachments/assets/0ab978ed-039c-4453-b0a3-905183610492"> | <img width="190" alt="Native SwiftUI: PRF encryption · light" src="https://github.com/user-attachments/assets/13e1a71a-a68b-46c3-bb2a-fcbf7ad35097"> |
| PRF encryption · dark | <img width="190" alt="Compose Android: PRF encryption · dark" src="https://github.com/user-attachments/assets/7be574d5-bc0b-458e-bedc-0892666a32ea"> | <img width="190" alt="Compose iOS: PRF encryption · dark" src="https://github.com/user-attachments/assets/0b5ecab2-f68e-4727-93f8-5178ccfa1ef3"> | <img width="190" alt="Native SwiftUI: PRF encryption · dark" src="https://github.com/user-attachments/assets/456ea577-f813-4944-aad3-af4863d6e365"> |

## Status, capability, and diagnostic states

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Busy authentication | <img width="190" alt="Compose Android: Busy authentication" src="https://github.com/user-attachments/assets/b2052814-a342-4173-9512-7bdf4014486f"> | <img width="190" alt="Compose iOS: Busy authentication" src="https://github.com/user-attachments/assets/2c90b0a8-5caa-4256-9f1e-7dc9e1eab51a"> | <img width="190" alt="Native SwiftUI: Busy authentication" src="https://github.com/user-attachments/assets/ca0b3dc7-b673-4939-b73c-c11b0fe20809"> |
| Registration complete | <img width="190" alt="Compose Android: Registration complete" src="https://github.com/user-attachments/assets/b9393101-98cb-466a-a419-e6c911bd6817"> | <img width="190" alt="Compose iOS: Registration complete" src="https://github.com/user-attachments/assets/8bfc1ef6-3af2-4861-af4a-70640b01c915"> | <img width="190" alt="Native SwiftUI: Registration complete" src="https://github.com/user-attachments/assets/412cfd42-706c-45fc-9e09-5d16ab218d66"> |
| Cancelled sign-in | <img width="190" alt="Compose Android: Cancelled sign-in" src="https://github.com/user-attachments/assets/323757f0-a486-4009-a232-d2eef184c0ab"> | <img width="190" alt="Compose iOS: Cancelled sign-in" src="https://github.com/user-attachments/assets/01a3ef2d-6416-45e8-865c-b2f3c043f4e5"> | <img width="190" alt="Native SwiftUI: Cancelled sign-in" src="https://github.com/user-attachments/assets/91551509-bfbb-4b35-9140-f3ac8bed7bb2"> |
| Server rejection | <img width="190" alt="Compose Android: Server rejection" src="https://github.com/user-attachments/assets/32abeffe-c556-4f5a-a4e3-c14215f2a825"> | <img width="190" alt="Compose iOS: Server rejection" src="https://github.com/user-attachments/assets/ef64b08f-98aa-40e0-879f-ea8240264d32"> | <img width="190" alt="Native SwiftUI: Server rejection" src="https://github.com/user-attachments/assets/71374cbf-19ec-479b-a442-4c5f95da2ccd"> |
| Connection error | <img width="190" alt="Compose Android: Connection error" src="https://github.com/user-attachments/assets/b821bdd7-0a4d-419d-95df-fcb56d0fcd9e"> | <img width="190" alt="Compose iOS: Connection error" src="https://github.com/user-attachments/assets/6cfd976e-d309-4454-987e-15e037f4dc7b"> | <img width="190" alt="Native SwiftUI: Connection error" src="https://github.com/user-attachments/assets/bf7a779a-ec28-42cb-8567-1a3da933bf72"> |
| PRF unavailable | <img width="190" alt="Compose Android: PRF unavailable" src="https://github.com/user-attachments/assets/6ac03de2-5d1c-40ee-83fd-bbadf2dd89bb"> | <img width="190" alt="Compose iOS: PRF unavailable" src="https://github.com/user-attachments/assets/295ab131-222d-4586-aa70-c7b54dfb6a52"> | <img width="190" alt="Native SwiftUI: PRF unavailable" src="https://github.com/user-attachments/assets/5fe8fd66-89ad-4091-a2f2-eaf843acc92c"> |
| Debug logs · dark | <img width="190" alt="Compose Android: Debug logs · dark" src="https://github.com/user-attachments/assets/5e14d83b-df5d-47af-bd31-c130fba91d02"> | <img width="190" alt="Compose iOS: Debug logs · dark" src="https://github.com/user-attachments/assets/60ad095e-603a-45b5-8d40-e901febdbf2b"> | <img width="190" alt="Native SwiftUI: Debug logs · dark" src="https://github.com/user-attachments/assets/b6cf52e4-9f99-4723-8321-b548d3f69a4c"> |

## Large layouts

The Android capture uses a 1200 × 1600 dp emulator viewport; the iOS captures use an iPad simulator.
Both layouts keep the PRF workspace beside capabilities, configuration, and session actions when space
permits. Increasing font size returns the content to a scrolling single column.

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Large layout with capabilities and expanded configuration | <img width="240" alt="Compose Android: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/b5ec60c4-dbb8-47c4-86c1-953b2155d1b2"> | <img width="240" alt="Compose iOS: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/dd3a324a-53f5-4d0f-b176-6a7abee30487"> | <img width="240" alt="Native SwiftUI: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/89e3f22b-bbfb-43f5-82f1-f4cc5358c4b2"> |

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
