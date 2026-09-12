import SwiftUI
import WebAuthn

struct MainView: View {
    @ObservedObject var viewModel: DemoViewModel

    var body: some View {
        SessionContent(
            config: viewModel.config,
            capabilities: viewModel.capabilities,
            sessionState: viewModel.prfSessionState,
            busy: viewModel.prfBusy,
            status: viewModel.prfStatus,
            plaintext: $viewModel.plaintext,
            decryptedText: viewModel.decryptedText,
            onSignInWithPRF: { Task { await viewModel.signInWithPRF() } },
            onEncrypt: { Task { await viewModel.encrypt() } },
            onDecrypt: { Task { await viewModel.decrypt() } },
            onClear: { Task { await viewModel.clearPrfSession() } },
            onSignOut: { Task { await viewModel.signOut() } }
        )
    }
}

struct SessionContent: View {
    let config: DemoConfiguration
    let capabilities: PasskeyCapabilities
    let sessionState: PrfSessionState
    let busy: Bool
    let status: String
    @Binding var plaintext: String
    let decryptedText: String?
    let onSignInWithPRF: () -> Void
    let onEncrypt: () -> Void
    let onDecrypt: () -> Void
    let onClear: () -> Void
    let onSignOut: () -> Void

    var body: some View {
        DemoPage { wide in
            IntroCard(title: "Signed in", detail: config.userName)
            DemoPanels(wide: wide) {
                PrfCryptoCard(
                    supportsPRF: capabilities.supports(.prf), sessionState: sessionState,
                    busy: busy, status: status, plaintext: $plaintext, decryptedText: decryptedText,
                    onSignInWithPRF: onSignInWithPRF, onEncrypt: onEncrypt, onDecrypt: onDecrypt, onClear: onClear
                )
            } secondary: {
                CapabilitiesCard(capabilities: capabilities)
                ConfigurationCard(config: config)
                DemoCard {
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Session").font(.headline)
                        Text("Signing out clears the in-memory encryption key. Your passkey stays on your device.")
                            .font(.subheadline).foregroundStyle(Color.demoSecondary)
                        Button(role: .destructive, action: onSignOut) {
                            Label("Sign Out", systemImage: "rectangle.portrait.and.arrow.right")
                                .foregroundStyle(busy ? Color.demoSecondary.opacity(0.45) : Color.demoNegative)
                                .frame(maxWidth: .infinity, minHeight: 32)
                        }
                        .buttonStyle(.bordered)
                        .tint(.demoNegative)
                        .disabled(busy)
                        .accessibilityIdentifier("sign-out-button")
                    }
                }
            }
        }
    }
}

private struct CapabilitiesCard: View {
    let capabilities: PasskeyCapabilities

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 16) {
                Label("Device capabilities", systemImage: "checkmark.shield")
                    .font(.headline).accessibilityAddTraits(.isHeader)
                CapabilityRow(label: "PRF encryption", support: capabilities.support(for: .prf))
                CapabilityRow(label: "Large blob", support: capabilities.support(for: .largeBlob))
                CapabilityRow(label: "Security key", support: capabilities.support(for: .securityKey))
                Text("Reported by your platform. Individual passkey providers may differ.")
                    .font(.footnote).foregroundStyle(Color.demoSecondary)
            }
        }
        .accessibilityIdentifier("capabilities-card")
    }
}

private struct CapabilityRow: View {
    let label: String
    let support: CapabilitySupport

    private var supportLabel: String {
        switch support {
        case .supported: "✓ Supported"
        case .unsupported: "Unavailable"
        case .unknown: "Not reported"
        @unknown default: "Not reported"
        }
    }

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack { Text(label); Spacer(); value }
            VStack(alignment: .leading, spacing: 4) { Text(label); value }
        }
        .font(.subheadline)
        .accessibilityElement(children: .combine)
    }

    private var value: some View {
        Text(supportLabel).foregroundStyle(support == .supported ? Color.demoPositive : Color.demoSecondary)
    }
}

private struct PrfCryptoCard: View {
    let supportsPRF: Bool
    let sessionState: PrfSessionState
    let busy: Bool
    let status: String
    @Binding var plaintext: String
    let decryptedText: String?
    let onSignInWithPRF: () -> Void
    let onEncrypt: () -> Void
    let onDecrypt: () -> Void
    let onClear: () -> Void

    private var hasSession: Bool { sessionState != .noSession }

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 16) {
                Text("PRF encryption")
                    .font(.title2.bold()).accessibilityAddTraits(.isHeader)
                Text("Derive a temporary AES-GCM key using the PRF extension.")
                    .font(.subheadline).foregroundStyle(Color.demoSecondary)
                StatusCard(status: DemoStatus(
                    tone: busy ? .working : .idle,
                    headline: busy ? "Processing" : sessionState.rawValue,
                    detail: !supportsPRF && !hasSession
                        ? "PRF is unavailable on this platform or provider. You can still use ordinary passkey sign-in."
                        : status
                ))
                .accessibilityIdentifier("prf-status")
                Button(action: onSignInWithPRF) {
                    Label("Sign In + PRF", systemImage: "key.horizontal")
                        .foregroundStyle(Color.demoOnAccent)
                        .frame(maxWidth: .infinity, minHeight: 32)
                }
                .buttonStyle(.borderedProminent)
                .disabled(busy || !supportsPRF)
                .accessibilityIdentifier("prf-sign-in-button")
                VStack(alignment: .leading, spacing: 8) {
                    Text("Message to encrypt").font(.caption).foregroundStyle(Color.demoSecondary)
                    TextField("Message to encrypt", text: $plaintext, axis: .vertical)
                        .lineLimit(2...5)
                        .textFieldStyle(.roundedBorder)
                        .foregroundStyle(busy || !hasSession ? Color.demoSecondary.opacity(0.45) : Color.primary)
                        .disabled(busy || !hasSession)
                        .accessibilityIdentifier("prf-plaintext-field")
                    Text(hasSession ? "Your message stays in this sample session." : "Unlock a PRF session to start encrypting.")
                        .font(.caption).foregroundStyle(Color.demoSecondary)
                }
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: 12) { cryptoActions }
                    VStack(spacing: 12) { cryptoActions }
                }
                .frame(maxWidth: .infinity, alignment: .center)
                if let decryptedText {
                    StatusCard(status: DemoStatus(tone: .success, headline: "Decrypted message", detail: decryptedText))
                        .textSelection(.enabled)
                        .accessibilityIdentifier("decrypted-text")
                }
                Button("Clear encryption session", role: .destructive, action: onClear)
                    .foregroundStyle(busy || !hasSession ? Color.demoSecondary.opacity(0.45) : Color.demoNegative)
                    .frame(minHeight: 44)
                    .disabled(busy || !hasSession)
                    .accessibilityIdentifier("clear-session-button")
                Text("This demo keeps the salt and key in memory. Removing your passkey makes its encrypted data unrecoverable.")
                    .font(.footnote).foregroundStyle(Color.demoSecondary)
            }
        }
    }

    @ViewBuilder private var cryptoActions: some View {
        Button("Encrypt", action: onEncrypt)
            .frame(minHeight: 44).buttonStyle(.bordered)
            .disabled(busy || !hasSession).accessibilityIdentifier("encrypt-button")
        Button("Decrypt", action: onDecrypt)
            .frame(minHeight: 44).buttonStyle(.bordered)
            .disabled(busy || sessionState != .ciphertextReady).accessibilityIdentifier("decrypt-button")
    }
}
