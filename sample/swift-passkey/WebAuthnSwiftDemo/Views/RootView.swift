import SwiftUI

struct RootView: View {
    @ObservedObject var viewModel: DemoViewModel
    @State private var showsLogs = false

    var body: some View {
        NavigationStack {
            Group {
                switch viewModel.route {
                case .authentication:
                    AuthenticationView(viewModel: viewModel)
                case .main:
                    MainView(viewModel: viewModel)
                }
            }
            .navigationTitle("Passkey Lab")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("Passkey Lab")
                        .font(.headline)
                        .accessibilityIdentifier("demo-title")
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        showsLogs = true
                    } label: {
                        Image(systemName: "terminal")
                    }
                    .accessibilityLabel("Debug logs")
                    .accessibilityIdentifier("debug-logs-button")
                }
            }
        }
        .tint(Color.demoAccent)
        .sheet(isPresented: $showsLogs) {
            DebugLogSheet(logs: viewModel.logs)
        }
    }
}
