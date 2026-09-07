import SwiftUI

struct DemoCard<Content: View>: View {
    @ViewBuilder let content: Content

    var body: some View {
        content
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(20)
            .background(Color.demoCard, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 24, style: .continuous)
                    .stroke(Color.primary.opacity(0.08))
            }
    }
}

struct DemoPage<Content: View>: View {
    @Environment(\.dynamicTypeSize) private var typeSize
    @ViewBuilder let content: (Bool) -> Content

    var body: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    content(geometry.size.width >= 880 && !typeSize.isAccessibilitySize)
                }
                .frame(maxWidth: 1120)
                .padding(20)
                .frame(maxWidth: .infinity)
            }
            .scrollDismissesKeyboard(.interactively)
            .background(Color.demoCanvas)
        }
    }
}

struct DemoPanels<Primary: View, Secondary: View>: View {
    let wide: Bool
    @ViewBuilder let primary: Primary
    @ViewBuilder let secondary: Secondary

    var body: some View {
        if wide {
            HStack(alignment: .top, spacing: 20) {
                VStack(alignment: .leading, spacing: 16) { primary }
                    .frame(maxWidth: .infinity)
                VStack(alignment: .leading, spacing: 16) { secondary }
                    .frame(maxWidth: .infinity)
            }
        } else {
            VStack(alignment: .leading, spacing: 16) {
                primary
                secondary
            }
        }
    }
}

struct IntroCard: View {
    let title: String
    let detail: String
    var eyebrow = "NATIVE SWIFT · KOTLIN CORE"

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(eyebrow)
                .font(.caption.weight(.semibold))
                .foregroundStyle(Color.demoAccent)
            Text(title)
                .font(.largeTitle.bold())
                .accessibilityAddTraits(.isHeader)
            Text(detail)
                .font(.body)
                .foregroundStyle(Color.demoSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 8)
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
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(status.headline)
                        .font(.headline)
                    Text(status.detail)
                        .font(.subheadline)
                        .foregroundStyle(Color.demoSecondary)
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
    var body: some View {
        DebugLogContent(entries: logs.entries, onClear: logs.clear)
    }
}

struct DebugLogContent: View {
    let entries: [DebugLogEntry]
    let onClear: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List(entries.reversed()) { entry in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(entry.level.rawValue)
                            .font(.caption.bold())
                            .foregroundStyle(entry.level.color)
                        Text(entry.source)
                            .font(.caption)
                            .foregroundStyle(Color.demoSecondary)
                        Spacer()
                        Text(entry.timestamp, style: .time)
                            .font(.caption2)
                            .foregroundStyle(Color.demoSecondary)
                    }
                    Text(entry.message)
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                }
            }
            .overlay {
                if entries.isEmpty {
                    VStack(spacing: 8) {
                        Image(systemName: "terminal")
                            .font(.title2)
                        Text("No debug events")
                            .foregroundStyle(Color.demoSecondary)
                    }
                }
            }
            .navigationTitle("Debug logs")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Done") { dismiss() }
                }
                ToolbarItem(placement: .destructiveAction) {
                    Button("Clear", role: .destructive, action: onClear)
                        .foregroundStyle(Color.demoNegative)
                }
            }
        }
    }
}

private extension StatusTone {
    var color: Color {
        switch self {
        case .idle: .demoSecondary
        case .working: .demoAccent
        case .success: .demoPositive
        case .warning: .demoWarning
        case .error: .demoNegative
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
        case .info: .demoAccent
        case .warning: .demoWarning
        case .error: .demoNegative
        }
    }
}

extension Color {
    static let demoAccent = adaptive(light: 0x2855B8, dark: 0xB4C9FF)
    static let demoOnAccent = adaptive(light: 0xFFFFFF, dark: 0x082E74)
    static let demoSecondary = adaptive(light: 0x526077, dark: 0xBDCADB)
    static let demoPositive = adaptive(light: 0x226D51, dark: 0x82D6B1)
    static let demoWarning = adaptive(light: 0x7A5500, dark: 0xF1CD78)
    static let demoNegative = adaptive(light: 0xA93231, dark: 0xFFB4AB)
    static let demoCanvas = Color(uiColor: .systemGroupedBackground)
    static let demoCard = Color(uiColor: .secondarySystemGroupedBackground)

    private static func adaptive(light: UInt32, dark: UInt32) -> Color {
        Color(uiColor: UIColor { traits in
            let rgb = traits.userInterfaceStyle == .dark ? dark : light
            return UIColor(
                red: CGFloat((rgb >> 16) & 0xFF) / 255,
                green: CGFloat((rgb >> 8) & 0xFF) / 255,
                blue: CGFloat(rgb & 0xFF) / 255,
                alpha: 1
            )
        })
    }
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
