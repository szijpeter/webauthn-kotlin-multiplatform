import Combine
import Foundation

enum DebugLogLevel: String {
    case info = "INFO"
    case warning = "WARN"
    case error = "ERROR"
}

struct DebugLogEntry: Identifiable {
    let id: UInt64
    let timestamp: Date
    let level: DebugLogLevel
    let source: String
    let message: String
}

@MainActor
final class DebugLogStore: ObservableObject {
    @Published private(set) var entries: [DebugLogEntry] = []

    private var nextID: UInt64 = 0
    private let capacity: Int

    init(capacity: Int = 200) {
        self.capacity = capacity
    }

    func info(_ source: String, _ message: String) {
        append(level: .info, source: source, message: message)
    }

    func warning(_ source: String, _ message: String) {
        append(level: .warning, source: source, message: message)
    }

    func error(_ source: String, _ message: String) {
        append(level: .error, source: source, message: message)
    }

    func clear() {
        entries.removeAll(keepingCapacity: true)
    }

    private func append(level: DebugLogLevel, source: String, message: String) {
        nextID &+= 1
        entries.append(
            DebugLogEntry(
                id: nextID,
                timestamp: Date(),
                level: level,
                source: source,
                message: message
            )
        )
        if entries.count > capacity {
            entries.removeFirst(entries.count - capacity)
        }
    }
}
