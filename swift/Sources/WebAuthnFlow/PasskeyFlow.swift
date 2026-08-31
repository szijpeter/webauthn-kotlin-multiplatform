import Foundation
import WebAuthn

/// Server-owned continuation state and options returned when a ceremony starts.
public struct CeremonyStart<State> {
    /// Opaque backend state forwarded unchanged to the finish operation.
    public let state: State

    /// UTF-8 WebAuthn options JSON passed to the platform client.
    public let optionsJSON: Data

    public init(state: State, optionsJSON: Data) {
        self.state = state
        self.optionsJSON = optionsJSON
    }
}

extension CeremonyStart: Equatable where State: Equatable {}
extension CeremonyStart: Sendable where State: Sendable {}

/// Application-owned backend contract for a registration ceremony.
@MainActor
public protocol RegistrationBackend {
    associatedtype Input
    associatedtype State
    associatedtype Output

    /// Starts registration and returns opaque continuation state plus creation options.
    func start(input: Input) async throws -> CeremonyStart<State>

    /// Finishes registration with the unchanged state and platform response.
    func finish(state: State, responseJSON: Data) async throws -> Output
}

/// Application-owned backend contract for an authentication ceremony.
@MainActor
public protocol AuthenticationBackend {
    associatedtype Input
    associatedtype State
    associatedtype Output

    /// Starts authentication and returns opaque continuation state plus request options.
    func start(input: Input) async throws -> CeremonyStart<State>

    /// Finishes authentication with the unchanged state and platform response.
    func finish(state: State, responseJSON: Data) async throws -> Output
}

/// Lifecycle phase of a passkey ceremony.
public enum PasskeyPhase: Equatable, Sendable {
    case starting
    case platformPrompt
    case finishing
}

/// Failures classified by the application-neutral flow.
public enum CeremonyFailure: Equatable, Sendable {
    /// Another ceremony is already using this flow instance.
    case alreadyInProgress

    /// The platform client returned a typed passkey failure.
    case platform(PasskeyClientError)
}

/// Completion value or a failure classified by the application-neutral flow.
public enum CeremonyResult<Output> {
    case success(Output)
    case failure(CeremonyFailure)
}

extension CeremonyResult: Equatable where Output: Equatable {}
extension CeremonyResult: Sendable where Output: Sendable {}

/// Registration and authentication start-prompt-finish orchestration.
///
/// Backend and phase-callback errors deliberately propagate to the caller. The flow classifies only its own
/// concurrent-use rejection and typed ``PasskeyClientError`` values returned by the platform client.
@MainActor
public final class PasskeyFlow {
    private let client: any PasskeyClientProtocol
    private var ceremonyInProgress = false

    public init(client: any PasskeyClientProtocol) {
        self.client = client
    }

    /// Runs registration while preserving backend state and application-defined output.
    public func register<Backend: RegistrationBackend>(
        _ input: Backend.Input,
        backend: Backend,
        onPhaseChanged: (PasskeyPhase) throws -> Void = { _ in }
    ) async throws -> CeremonyResult<Backend.Output> {
        try await runCeremony(
            start: { try await backend.start(input: input) },
            prompt: { try await self.client.createCredential(optionsJSON: $0) },
            finish: { try await backend.finish(state: $0, responseJSON: $1) },
            onPhaseChanged: onPhaseChanged
        )
    }

    /// Runs authentication while preserving backend state and application-defined output.
    public func signIn<Backend: AuthenticationBackend>(
        _ input: Backend.Input,
        backend: Backend,
        onPhaseChanged: (PasskeyPhase) throws -> Void = { _ in }
    ) async throws -> CeremonyResult<Backend.Output> {
        try await runCeremony(
            start: { try await backend.start(input: input) },
            prompt: { try await self.client.getAssertion(optionsJSON: $0) },
            finish: { try await backend.finish(state: $0, responseJSON: $1) },
            onPhaseChanged: onPhaseChanged
        )
    }

    private func runCeremony<State, Output>(
        start: () async throws -> CeremonyStart<State>,
        prompt: (Data) async throws -> Data,
        finish: (State, Data) async throws -> Output,
        onPhaseChanged: (PasskeyPhase) throws -> Void
    ) async throws -> CeremonyResult<Output> {
        guard !ceremonyInProgress else {
            return .failure(.alreadyInProgress)
        }
        ceremonyInProgress = true
        defer { ceremonyInProgress = false }

        try Task.checkCancellation()
        try onPhaseChanged(.starting)
        let ceremony = try await start()

        try Task.checkCancellation()
        try onPhaseChanged(.platformPrompt)
        let response: Data
        do {
            response = try await prompt(ceremony.optionsJSON)
        } catch let error as PasskeyClientError {
            return .failure(.platform(error))
        }

        try Task.checkCancellation()
        try onPhaseChanged(.finishing)
        return .success(try await finish(ceremony.state, response))
    }
}
