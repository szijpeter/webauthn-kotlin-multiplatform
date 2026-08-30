import Foundation
import WebAuthn

enum DemoRoute: Equatable {
    case authentication
    case main
}

enum DemoAction: String, Equatable {
    case register = "Register"
    case signIn = "Sign In"
}

enum CeremonyPhase: String, Equatable {
    case starting
    case platformPrompt
    case finishing

    var detail: String {
        switch self {
        case .starting: "Loading server options."
        case .platformPrompt: "Waiting for the platform passkey prompt."
        case .finishing: "Verifying the passkey response."
        }
    }
}

enum DemoFailureKind: Equatable {
    case userCancelled
    case noCredential
    case invalidOptions
    case platform
    case codec
    case backend
    case rejected
    case alreadyInProgress
    case internalContract

    var label: String {
        switch self {
        case .userCancelled: "User Cancelled"
        case .noCredential: "No Credential"
        case .invalidOptions: "Invalid Options"
        case .platform: "Platform"
        case .codec: "Codec"
        case .backend: "Backend"
        case .rejected: "Rejected"
        case .alreadyInProgress: "Already In Progress"
        case .internalContract: "Internal Contract"
        }
    }
}

struct DemoFailure: Error, Equatable {
    let kind: DemoFailureKind
    let message: String

    static func platform(_ error: Error) -> DemoFailure {
        guard let error = error as? PasskeyClientError else {
            return DemoFailure(kind: .platform, message: error.localizedDescription)
        }
        switch error {
        case .userCancelled:
            return DemoFailure(kind: .userCancelled, message: error.localizedDescription)
        case .noCredential:
            return DemoFailure(kind: .noCredential, message: error.localizedDescription)
        case let .invalidOptions(message):
            return DemoFailure(kind: .invalidOptions, message: message)
        case let .platform(message):
            return DemoFailure(kind: .platform, message: message)
        case let .codec(message):
            return DemoFailure(kind: .codec, message: message)
        case .operationInProgress:
            return DemoFailure(kind: .alreadyInProgress, message: error.localizedDescription)
        case let .bridgeContract(message):
            return DemoFailure(kind: .internalContract, message: message)
        case .invalidUTF8, .unavailablePresentationAnchor, .sessionCleared, .crypto:
            return DemoFailure(kind: .platform, message: error.localizedDescription)
        @unknown default:
            return DemoFailure(kind: .internalContract, message: error.localizedDescription)
        }
    }
}

enum CeremonyState: Equatable {
    case idle
    case inProgress(action: DemoAction, phase: CeremonyPhase)
    case success(action: DemoAction)
    case failure(action: DemoAction, failure: DemoFailure)

    var actionsEnabled: Bool {
        if case .inProgress = self { return false }
        return true
    }
}

enum StatusTone: Equatable {
    case idle
    case working
    case success
    case warning
    case error
}

struct DemoStatus {
    let tone: StatusTone
    let headline: String
    let detail: String
}

extension CeremonyState {
    var status: DemoStatus {
        switch self {
        case .idle:
            return DemoStatus(
                tone: .idle,
                headline: "Ready",
                detail: "Run Register or Sign In to exercise the end-to-end passkey flow."
            )
        case let .inProgress(action, phase):
            return DemoStatus(
                tone: .working,
                headline: "\(action.rawValue) in progress",
                detail: phase.detail
            )
        case let .success(action):
            return DemoStatus(
                tone: .success,
                headline: "\(action.rawValue) complete",
                detail: action == .register
                    ? "Passkey created. Run Sign In to verify the round trip."
                    : "Authenticated successfully. Opening the extension demo."
            )
        case let .failure(_, failure):
            return DemoStatus(
                tone: failure.kind == .userCancelled ? .warning : .error,
                headline: failure.kind.label,
                detail: "[\(failure.kind.label)] \(failure.message)"
            )
        }
    }
}

enum PrfSessionState: String, Equatable {
    case noSession = "No session"
    case sessionReady = "Session ready"
    case ciphertextReady = "Ciphertext ready"
}

enum FinishOutcome: Equatable {
    case verified
    case rejected(String)
}

struct DemoPrfCiphertext: Equatable, Sendable {
    let nonce: Data
    let ciphertext: Data
    let authenticationTag: Data
    let associatedData: Data?
}
