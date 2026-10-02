import SwiftUI
import UIKit

@main
struct WebAuthnSwiftDemoApp: App {
    @StateObject private var viewModel: DemoViewModel

    @MainActor
    init() {
        let config = DemoConfiguration.load()
        let passkeys = LivePasskeyService {
            UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .filter { $0.activationState == .foregroundActive }
                .flatMap(\.windows)
                .first(where: \.isKeyWindow)
        }
        _viewModel = StateObject(
            wrappedValue: DemoViewModel(
                config: config,
                passkeys: passkeys,
                backend: URLSessionPasskeyBackend(endpoint: config.endpoint)
            )
        )
    }

    var body: some Scene {
        WindowGroup {
            RootView(viewModel: viewModel)
        }
    }
}
