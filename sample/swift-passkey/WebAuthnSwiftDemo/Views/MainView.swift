import SwiftUI
import WebAuthn

struct MainView: View {
    @ObservedObject var viewModel: DemoViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                IntroCard(
                    title: "Signed in as \(viewModel.config.userName)",
                    detail: "Inspect platform capabilities and exercise the PRF-derived, in-memory AES-GCM session."
                )
                CapabilitiesCard(capabilities: viewModel.capabilities)
                PrfCryptoCard(viewModel: viewModel)
                DemoCard {
                    Button(role: .destructive) {
                        Task { await viewModel.signOut() }
                    } label: {
                        Label("Sign Out", systemImage: "rectangle.portrait.and.arrow.right")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                    .accessibilityIdentifier("sign-out-button")
                }
            }
            .padding()
        }
        .background(Color.demoCanvas)
    }
}

private struct CapabilitiesCard: View {
    let capabilities: PasskeyCapabilities

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("Capabilities", systemImage: "checkmark.shield")
                        .font(.headline)
                    Spacer()
                    Text("\(capabilities.reportedCount) reported")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                CapabilityRow(label: "PRF", support: capabilities.support(for: .prf))
                CapabilityRow(label: "Large blob", support: capabilities.support(for: .largeBlob))
                CapabilityRow(label: "Security key", support: capabilities.support(for: .securityKey))
            }
        }
        .accessibilityIdentifier("capabilities-card")
    }
}

private struct CapabilityRow: View {
    let label: String
    let support: CapabilitySupport

    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(support.rawValue.capitalized)
                .foregroundStyle(support == .supported ? Color.green : Color.secondary)
        }
        .font(.subheadline)
    }
}

private struct PrfCryptoCard: View {
    @ObservedObject var viewModel: DemoViewModel

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Label("PRF crypto session", systemImage: "lock.square.stack")
                        .font(.headline)
                    Spacer()
                    Text(viewModel.prfSessionState.rawValue)
                        .font(.caption)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(.thinMaterial, in: Capsule())
                }

                Text(viewModel.prfStatus)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityIdentifier("prf-status")

                Button {
                    Task { await viewModel.signInWithPRF() }
                } label: {
                    Label("Sign In + PRF", systemImage: "key.horizontal")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(viewModel.prfBusy || !viewModel.supportsPRF)
                .accessibilityIdentifier("prf-sign-in-button")

                TextField("Plaintext", text: $viewModel.plaintext, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("prf-plaintext-field")

                HStack {
                    Button("Encrypt") { Task { await viewModel.encrypt() } }
                        .buttonStyle(.bordered)
                        .disabled(viewModel.prfBusy)
                        .accessibilityIdentifier("encrypt-button")
                    Button("Decrypt") { Task { await viewModel.decrypt() } }
                        .buttonStyle(.bordered)
                        .disabled(viewModel.prfBusy)
                        .accessibilityIdentifier("decrypt-button")
                    Button("Clear", role: .destructive) {
                        Task { await viewModel.clearPrfSession() }
                    }
                    .buttonStyle(.bordered)
                    .disabled(viewModel.prfBusy)
                    .accessibilityIdentifier("clear-session-button")
                }

                if let decryptedText = viewModel.decryptedText {
                    LabeledContent("Decrypted", value: decryptedText)
                        .font(.footnote)
                        .accessibilityIdentifier("decrypted-text")
                }
            }
        }
        .accessibilityIdentifier("prf-card")
    }
}
