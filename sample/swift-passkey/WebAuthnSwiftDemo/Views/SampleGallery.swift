#if DEBUG
import SwiftUI
import WebAuthn

// Rendering fixtures only; these views never construct a client, backend, or crypto session.
struct SampleGallery: View {
    let scenario: String
    @State private var plaintext = "The answer is 42"
    @State private var showsLogs = false

    static var launchScenario: String? {
        let args = ProcessInfo.processInfo.arguments
        guard let index = args.firstIndex(of: "--sample-gallery"), args.indices.contains(index + 1) else { return nil }
        return args[index + 1]
    }

    private let config = DemoConfiguration(
        endpoint: URL(string: "https://passkeys.example.test")!, rpID: "passkeys.example.test",
        origin: "https://passkeys.example.test", userHandle: "gallery-user", userName: "Avery Example"
    )

    var body: some View {
        NavigationStack {
            Group {
                if ["session", "encrypted", "unsupported", "prf-busy"].contains(scenario) {
                    SessionContent(
                        config: config,
                        capabilities: PasskeyCapabilities(support: [
                            .prf: scenario == "unsupported" ? .unsupported : .supported,
                            .largeBlob: .unknown, .securityKey: .supported
                        ]),
                        sessionState: sessionState, busy: scenario == "prf-busy", status: prfStatus,
                        plaintext: $plaintext, decryptedText: scenario == "encrypted" ? "The answer is 42" : nil,
                        onSignInWithPRF: {}, onEncrypt: {}, onDecrypt: {}, onClear: {}, onSignOut: {}
                    )
                } else {
                    AuthenticationContent(config: config, status: status, actionsEnabled: scenario != "busy", onRegister: {}, onSignIn: {})
                }
            }
            .navigationTitle("Passkey Lab")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showsLogs = true } label: { Image(systemName: "terminal") }
                        .accessibilityLabel("Debug logs").accessibilityIdentifier("debug-logs-button")
                }
            }
        }
        .onAppear { showsLogs = scenario == "logs" }
        .tint(Color.demoAccent)
        .sheet(isPresented: $showsLogs) {
            DebugLogContent(entries: Self.logs, onClear: {})
        }
    }

    private var sessionState: PrfSessionState {
        switch scenario {
        case "session": .sessionReady
        case "encrypted": .ciphertextReady
        default: .noSession
        }
    }

    private var prfStatus: String {
        switch scenario {
        case "encrypted": "Decrypt succeeded."
        case "session": "PRF session ready. Encrypt a message to try it out."
        case "prf-busy": "Complete the passkey prompt to unlock your encryption key."
        default: "Run Sign In + PRF to derive an in-memory AES session key."
        }
    }

    private var status: DemoStatus {
        switch scenario {
        case "busy": CeremonyState.inProgress(action: .signIn, phase: .platformPrompt).status
        case "success": CeremonyState.success(action: .register).status
        case "cancelled": CeremonyState.failure(action: .signIn, failure: DemoFailure(kind: .userCancelled, message: "Nothing was changed. Sign in again when you're ready.")).status
        case "rejected": CeremonyState.failure(action: .signIn, failure: DemoFailure(kind: .rejected, message: "The server could not verify this passkey response. Try signing in again.")).status
        case "error": CeremonyState.failure(action: .signIn, failure: DemoFailure(kind: .backend, message: "Check your connection and the configured endpoint, then try again.")).status
        default: CeremonyState.idle.status
        }
    }

    private static let logs: [DebugLogEntry] = [
        DebugLogEntry(id: 1, timestamp: Date(timeIntervalSince1970: 1_788_514_860), level: .info, source: "action", message: "Sign In tapped"),
        DebugLogEntry(id: 2, timestamp: Date(timeIntervalSince1970: 1_788_514_861), level: .info, source: "ceremony", message: "Sign In platformPrompt"),
        DebugLogEntry(id: 3, timestamp: Date(timeIntervalSince1970: 1_788_514_862), level: .info, source: "http", message: "POST /webauthn/authentication/finish: 200 OK"),
        DebugLogEntry(id: 4, timestamp: Date(timeIntervalSince1970: 1_788_514_862), level: .info, source: "ceremony", message: "Sign In success")
    ]
}

#Preview("Authentication") { SampleGallery(scenario: "auth") }
#Preview("Dark appearance") { SampleGallery(scenario: "auth").preferredColorScheme(.dark) }
#Preview("Busy") { SampleGallery(scenario: "busy") }
#Preview("Success") { SampleGallery(scenario: "success") }
#Preview("Cancellation") { SampleGallery(scenario: "cancelled") }
#Preview("Rejection") { SampleGallery(scenario: "rejected") }
#Preview("Error") { SampleGallery(scenario: "error") }
#Preview("Active session") { SampleGallery(scenario: "session") }
#Preview("Encrypted") { SampleGallery(scenario: "encrypted") }
#Preview("PRF unavailable") { SampleGallery(scenario: "unsupported") }
#Preview("Large type") { SampleGallery(scenario: "auth").dynamicTypeSize(.accessibility3) }
#endif
