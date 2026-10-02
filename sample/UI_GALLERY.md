# Sample UI gallery

The Compose Android, Compose iOS, and native SwiftUI samples share the same information hierarchy,
with Material controls on Android, Calf adaptive controls in Compose iOS, and native SwiftUI controls.
All three use neutral surfaces in light and dark appearance, tinted secondary actions, and red sign-out
buttons. Status icons, explicit capability values, and disabled actions communicate state without
relying on color alone. Intro headings fit the standard phone width and still wrap with larger text;
Encrypt/Decrypt are compact, centered text-only actions. Compose retains an accessible shared toolbar
and uses Calf for adaptive controls and native iOS sheet presentation.

These screenshots use deterministic Debug fixtures with public example data. Success, capability,
and encrypted-message states demonstrate rendering; they do not represent a captured live ceremony
or prove authenticator support. The live app uses the existing client, backend, and session wiring.

## Phone appearance

Compose iOS and SwiftUI use the same iPhone 17 simulator viewport (402 × 874 points) and standard
text size. Android uses its native phone viewport; images preserve their full aspect ratios.

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Authentication · light | <img width="190" alt="Compose Android: Authentication · light" src="https://github.com/user-attachments/assets/f5aba9c0-36cc-4338-ae11-237685505e0a"> | <img width="190" alt="Compose iOS: Authentication · light" src="https://github.com/user-attachments/assets/3e033c1c-d09a-4267-a7f6-ef8c6184af43"> | <img width="190" alt="Native SwiftUI: Authentication · light" src="https://github.com/user-attachments/assets/fddc8a34-6972-499d-ab9e-0f53b7a1372f"> |
| Authentication · dark | <img width="190" alt="Compose Android: Authentication · dark" src="https://github.com/user-attachments/assets/198ab9e0-8cc2-4a81-b324-ce65c2d018b1"> | <img width="190" alt="Compose iOS: Authentication · dark" src="https://github.com/user-attachments/assets/1d543dbb-f94e-4e7b-bbba-41bca7f08125"> | <img width="190" alt="Native SwiftUI: Authentication · dark" src="https://github.com/user-attachments/assets/d452f459-b813-4019-a0cc-167b9563d666"> |
| PRF encryption · light | <img width="190" alt="Compose Android: PRF encryption · light" src="https://github.com/user-attachments/assets/76e12b0d-d9d5-4c1f-a5c5-851107b976af"> | <img width="190" alt="Compose iOS: PRF encryption · light" src="https://github.com/user-attachments/assets/a622494e-dcba-41f8-a85c-62c58daa7e12"> | <img width="190" alt="Native SwiftUI: PRF encryption · light" src="https://github.com/user-attachments/assets/c9de2cd0-ee13-4b04-bcd3-e316c15ccca7"> |
| PRF encryption · dark | <img width="190" alt="Compose Android: PRF encryption · dark" src="https://github.com/user-attachments/assets/bf1c0143-ac62-431e-be1f-baac9effbe3b"> | <img width="190" alt="Compose iOS: PRF encryption · dark" src="https://github.com/user-attachments/assets/abda149a-d160-4b6c-9cc7-35f48176b216"> | <img width="190" alt="Native SwiftUI: PRF encryption · dark" src="https://github.com/user-attachments/assets/a9a43dea-4c0d-41ff-9db1-584e24980943"> |

## Status, capability, and diagnostic states

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Busy authentication | <img width="190" alt="Compose Android: Busy authentication" src="https://github.com/user-attachments/assets/3dbfde6f-c0ba-48f3-94cc-358f8996cdc1"> | <img width="190" alt="Compose iOS: Busy authentication" src="https://github.com/user-attachments/assets/670b10ed-33cc-4a36-90ac-df7664405739"> | <img width="190" alt="Native SwiftUI: Busy authentication" src="https://github.com/user-attachments/assets/641c70e8-9627-4bf5-8873-cb7d9cf15db4"> |
| Registration complete | <img width="190" alt="Compose Android: Registration complete" src="https://github.com/user-attachments/assets/be68d191-a44e-4d2a-a3c9-62999f4ba15d"> | <img width="190" alt="Compose iOS: Registration complete" src="https://github.com/user-attachments/assets/cc7556d9-9efd-418d-9f55-cedb5e9004b9"> | <img width="190" alt="Native SwiftUI: Registration complete" src="https://github.com/user-attachments/assets/84a3cb08-459c-48d8-9142-b3e50857e58f"> |
| Cancelled sign-in | <img width="190" alt="Compose Android: Cancelled sign-in" src="https://github.com/user-attachments/assets/00ad517d-59af-4fba-9763-54c52f800f7b"> | <img width="190" alt="Compose iOS: Cancelled sign-in" src="https://github.com/user-attachments/assets/3c670a6c-3510-4cca-a76f-140a680ec722"> | <img width="190" alt="Native SwiftUI: Cancelled sign-in" src="https://github.com/user-attachments/assets/8c252baa-1842-4fd1-83df-1d3054f5bcc6"> |
| Server rejection | <img width="190" alt="Compose Android: Server rejection" src="https://github.com/user-attachments/assets/2a07f3c3-0c19-4204-81a3-8135e778c3dd"> | <img width="190" alt="Compose iOS: Server rejection" src="https://github.com/user-attachments/assets/6f85f750-982c-4abd-bd4b-04a06ba511a9"> | <img width="190" alt="Native SwiftUI: Server rejection" src="https://github.com/user-attachments/assets/656d84af-8d59-4ac2-86e5-18db8bf36f13"> |
| Connection error | <img width="190" alt="Compose Android: Connection error" src="https://github.com/user-attachments/assets/afd9f59d-420a-4f72-8ce6-bab98d2de4d3"> | <img width="190" alt="Compose iOS: Connection error" src="https://github.com/user-attachments/assets/f7ca9f62-5e1d-4054-88ab-7853bfbf7d90"> | <img width="190" alt="Native SwiftUI: Connection error" src="https://github.com/user-attachments/assets/fd3bfb36-abd3-4090-9b27-90d54d1f715d"> |
| PRF unavailable | <img width="190" alt="Compose Android: PRF unavailable" src="https://github.com/user-attachments/assets/4162bc20-b620-486f-a367-e37c3d1b984e"> | <img width="190" alt="Compose iOS: PRF unavailable" src="https://github.com/user-attachments/assets/5d69b43e-f831-4345-9ba4-22bd87e061bd"> | <img width="190" alt="Native SwiftUI: PRF unavailable" src="https://github.com/user-attachments/assets/6d79294d-583b-4f01-9949-8497dc3a1490"> |
| Debug logs · dark | <img width="190" alt="Compose Android: Debug logs · dark" src="https://github.com/user-attachments/assets/0b97be9a-4279-4018-87a6-cec09fa8f178"> | <img width="190" alt="Compose iOS: Debug logs · dark" src="https://github.com/user-attachments/assets/15f7783b-b9db-41c0-888f-5971d8dc6834"> | <img width="190" alt="Native SwiftUI: Debug logs · dark" src="https://github.com/user-attachments/assets/38fb3a3c-bad3-4f02-9acd-92cff5dbf142"> |

## Large layouts

The Android capture uses a 1200 × 1600 dp emulator viewport; the iOS captures use an iPad simulator.
Both layouts keep the PRF workspace beside capabilities, configuration, and session actions when space
permits. Increasing font size returns the content to a scrolling single column.

| Sample state | Compose Android | Compose iOS | Native SwiftUI |
| --- | --- | --- | --- |
| Large layout with capabilities and expanded configuration | <img width="240" alt="Compose Android: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/b066f2f8-d673-4368-8b7e-293fb3d29311"> | <img width="240" alt="Compose iOS: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/725b4148-3b08-4a8a-9961-673adce2385a"> | <img width="240" alt="Native SwiftUI: Large layout with capabilities and expanded configuration" src="https://github.com/user-attachments/assets/6e65ea7b-9d49-455a-874e-e81ab895dc1e"> |

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
