import SwiftUI

struct AuthenticationView: View {
    @ObservedObject var viewModel: DemoViewModel

    var body: some View {
        AuthenticationContent(
            config: viewModel.config,
            status: viewModel.ceremonyState.status,
            actionsEnabled: viewModel.ceremonyActionsEnabled,
            onRegister: { Task { await viewModel.register() } },
            onSignIn: { Task { await viewModel.signIn() } }
        )
    }
}

struct AuthenticationContent: View {
    let config: DemoConfiguration
    let status: DemoStatus
    let actionsEnabled: Bool
    let onRegister: () -> Void
    let onSignIn: () -> Void

    var body: some View {
        DemoPage { wide in
            DemoPanels(wide: wide) {
                IntroCard(
                    title: "Your passkey.\nYour way in.",
                    detail: "A simpler, safer sign-in. Create a passkey and let your device take care of the rest."
                )
                StatusCard(status: status)
            } secondary: {
                DemoCard {
                    VStack(alignment: .leading, spacing: 16) {
                        Text("Welcome to Passkey Lab")
                            .font(.title2.bold())
                            .accessibilityAddTraits(.isHeader)
                        Text("New here? Register a passkey, then sign in to explore.")
                            .font(.subheadline)
                            .foregroundStyle(Color.demoSecondary)
                        Button(action: onRegister) {
                            Label("Register", systemImage: "person.badge.plus")
                                .foregroundStyle(Color.demoOnAccent)
                                .frame(maxWidth: .infinity, minHeight: 32)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!actionsEnabled)
                        .accessibilityIdentifier("register-button")
                        Button(action: onSignIn) {
                            Label("Sign In", systemImage: "person.crop.circle.badge.checkmark")
                                .frame(maxWidth: .infinity, minHeight: 32)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!actionsEnabled)
                        .accessibilityIdentifier("sign-in-button")
                    }
                }
                ConfigurationCard(config: config)
            }
        }
    }
}

struct ConfigurationCard: View {
    let config: DemoConfiguration

    var body: some View {
        DemoCard {
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 14) {
                    value("Endpoint", config.endpoint.absoluteString)
                    value("Relying party", config.rpID)
                    value("Origin", config.origin)
                    value("User", config.userName)
                }
                .padding(.top, 12)
            } label: {
                Label("Configuration", systemImage: "gearshape.2")
                    .font(.headline)
                    .frame(minHeight: 44)
            }
            .accessibilityIdentifier("configuration-disclosure")
        }
    }

    private func value(_ label: String, _ text: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.caption).foregroundStyle(Color.demoSecondary)
            Text(text).font(.subheadline).textSelection(.enabled)
        }
    }
}
