import SwiftUI

struct AuthenticationView: View {
    @ObservedObject var viewModel: DemoViewModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                IntroCard(
                    title: "Native Swift, Kotlin core",
                    detail: "Exercise registration and authentication through a Swift-first API backed by the same validated WebAuthn implementation."
                )
                StatusCard(status: viewModel.ceremonyState.status)
                actionCard
                ConfigurationCard(config: viewModel.config)
            }
            .padding()
        }
        .background(Color.demoCanvas)
    }

    private var actionCard: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 12) {
                Label("Passkey round trip", systemImage: "person.badge.key")
                    .font(.headline)
                Text("Options come from the sample backend; credential responses return there for verification.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button {
                    Task { await viewModel.register() }
                } label: {
                    Label("Register", systemImage: "person.badge.plus")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .disabled(!viewModel.ceremonyActionsEnabled)
                .accessibilityIdentifier("register-button")

                Button {
                    Task { await viewModel.signIn() }
                } label: {
                    Label("Sign In", systemImage: "person.crop.circle.badge.checkmark")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(!viewModel.ceremonyActionsEnabled)
                .accessibilityIdentifier("sign-in-button")
            }
        }
    }
}

private struct ConfigurationCard: View {
    let config: DemoConfiguration

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 8) {
                Label("Configuration", systemImage: "gearshape.2")
                    .font(.headline)
                LabeledContent("Endpoint", value: config.endpoint.host ?? config.endpoint.absoluteString)
                LabeledContent("RP ID", value: config.rpID)
                LabeledContent("Origin", value: config.origin)
                LabeledContent("User", value: config.userName)
            }
            .font(.footnote)
        }
    }
}
