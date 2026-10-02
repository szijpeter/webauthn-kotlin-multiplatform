import Foundation

/// Errors produced by the native Swift passkey and PRF APIs.
public enum PasskeyClientError: Error, Equatable, LocalizedError, Sendable {
    /// The user dismissed the platform passkey prompt.
    case userCancelled
    /// No credential was available for an assertion.
    case noCredential
    /// The supplied request or crypto input was invalid.
    case invalidOptions(message: String)
    /// The platform passkey provider failed.
    case platform(message: String)
    /// The Kotlin-owned WebAuthn codec failed.
    case codec(message: String)
    /// JSON input was not UTF-8.
    case invalidUTF8
    /// No foreground presentation window was available.
    case unavailablePresentationAnchor
    /// Another ceremony is already active on this client.
    case operationInProgress
    /// The internal binary bridge violated its contract.
    case bridgeContract(message: String)
    /// A PRF crypto session was used after it was cleared.
    case sessionCleared
    /// A PRF crypto operation failed.
    case crypto(message: String)

    /// Human-readable description suitable for local UI and diagnostics.
    public var errorDescription: String? {
        switch self {
        case .userCancelled:
            return "The passkey prompt was cancelled."
        case .noCredential:
            return "No passkey credential was available."
        case let .invalidOptions(message),
             let .platform(message),
             let .codec(message),
             let .bridgeContract(message),
             let .crypto(message):
            return message
        case .invalidUTF8:
            return "WebAuthn JSON must be valid UTF-8."
        case .unavailablePresentationAnchor:
            return "No foreground window is available for the passkey prompt."
        case .operationInProgress:
            return "Another passkey ceremony is already in progress."
        case .sessionCleared:
            return "The PRF crypto session has been cleared."
        }
    }
}

extension PasskeyClientError {
    static func bridge(code: String?, message: String?) -> PasskeyClientError {
        let safeMessage = message ?? "The internal passkey bridge failed."
        switch code {
        case "userCancelled":
            return .userCancelled
        case "noCredential":
            return .noCredential
        case "invalidOptions":
            return .invalidOptions(message: safeMessage)
        case "platform":
            return .platform(message: safeMessage)
        case "codec":
            return .codec(message: safeMessage)
        case "operationInProgress":
            return .operationInProgress
        case "sessionCleared":
            return .sessionCleared
        case "crypto":
            return .crypto(message: safeMessage)
        default:
            return .bridgeContract(message: safeMessage)
        }
    }
}
