import SwiftUI

struct DemoCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(16)
            .background(Color.demoCard, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .stroke(Color.primary.opacity(0.08))
            }
    }
}

struct IntroCard: View {
    let title: String
    let detail: String

    var body: some View {
        DemoCard {
            VStack(alignment: .leading, spacing: 8) {
                Text(title)
                    .font(.title2.bold())
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct StatusCard: View {
    let status: DemoStatus

    var body: some View {
        DemoCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: status.tone.symbol)
                    .foregroundStyle(status.tone.color)
                    .font(.title3)
                VStack(alignment: .leading, spacing: 4) {
                    Text(status.headline)
                        .font(.headline)
                    Text(status.detail)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if status.tone == .working {
                    ProgressView()
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("ceremony-status")
    }
}

struct DebugLogSheet: View {
    @ObservedObject var logs: DebugLogStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List(logs.entries.reversed()) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(entry.level.rawValue)
                            .font(.caption.bold())
                            .foregroundStyle(entry.level.color)
                        Text(entry.source)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(entry.timestamp, style: .time)
                            .font(.caption2)
                            .foregroundStyle(.tertiary)
                    }
                    Text(entry.message)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }
            .overlay {
                if logs.entries.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "terminal")
                            .font(.title2)
                        Text("No debug events")
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Debug logs")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .destructiveAction) {
                    Button("Clear", role: .destructive) { logs.clear() }
                }
            }
        }
    }
}

private extension StatusTone {
    var color: Color {
        switch self {
        case .idle: .secondary
        case .working: .blue
        case .success: .green
        case .warning: .orange
        case .error: .red
        }
    }

    var symbol: String {
        switch self {
        case .idle: "circle.dotted"
        case .working: "clock.arrow.circlepath"
        case .success: "checkmark.circle.fill"
        case .warning: "exclamationmark.triangle.fill"
        case .error: "xmark.octagon.fill"
        }
    }
}

private extension DebugLogLevel {
    var color: Color {
        switch self {
        case .info: .blue
        case .warning: .orange
        case .error: .red
        }
    }
}

extension Color {
    static let demoCanvas = Color(uiColor: .systemGroupedBackground)
    static let demoCard = Color(uiColor: .secondarySystemGroupedBackground)
}

#Preview("Status states") {
    ScrollView {
        VStack {
            StatusCard(status: CeremonyState.idle.status)
            StatusCard(status: CeremonyState.inProgress(action: .signIn, phase: .platformPrompt).status)
            StatusCard(status: CeremonyState.success(action: .register).status)
            StatusCard(
                status: CeremonyState.failure(
                    action: .signIn,
                    failure: DemoFailure(kind: .userCancelled, message: "The prompt was cancelled.")
                ).status
            )
        }
        .padding()
    }
    .background(Color.demoCanvas)
}
