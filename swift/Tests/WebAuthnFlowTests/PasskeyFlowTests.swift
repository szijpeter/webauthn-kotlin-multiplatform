import Foundation
import WebAuthn
import WebAuthnFlow
import XCTest

@MainActor
final class PasskeyFlowTests: XCTestCase {
    func testRegistrationPreservesResponseStateOutputAndPhases() async throws {
        let client = FakePasskeyClient()
        client.registrationResponse = Data("registration-response".utf8)
        let backend = RegistrationFixtureBackend()
        let flow = PasskeyFlow(client: client)
        var phases: [PasskeyPhase] = []

        let result = try await flow.register(
            "user",
            backend: backend,
            onPhaseChanged: { phases.append($0) }
        )

        XCTAssertEqual(result, .success("registered"))
        XCTAssertEqual(backend.finishedState, "continuation:user")
        XCTAssertEqual(backend.finishedResponse, client.registrationResponse)
        XCTAssertEqual(phases, [.starting, .platformPrompt, .finishing])
    }

    func testAuthenticationPreservesResponseStateAndOutput() async throws {
        let client = FakePasskeyClient()
        client.authenticationResponse = Data("authentication-response".utf8)
        let backend = AuthenticationFixtureBackend()
        let flow = PasskeyFlow(client: client)

        let result = try await flow.signIn(42, backend: backend)

        XCTAssertEqual(result, .success(7))
        XCTAssertEqual(backend.finishedState, 42)
        XCTAssertEqual(backend.finishedResponse, client.authenticationResponse)
    }

    func testPlatformFailureIsClassifiedAndBackendFailurePropagates() async throws {
        let client = FakePasskeyClient()
        client.registrationError = PasskeyClientError.userCancelled
        let flow = PasskeyFlow(client: client)

        let platformResult = try await flow.register("user", backend: RegistrationFixtureBackend())
        XCTAssertEqual(platformResult, .failure(.platform(.userCancelled)))

        do {
            _ = try await flow.register("user", backend: ThrowingRegistrationBackend(stage: .start))
            XCTFail("Expected backend error to propagate")
        } catch let error as FixtureError {
            XCTAssertEqual(error, .backend)
        }
    }

    func testConcurrentCeremonyIsRejectedAndLockIsReleased() async throws {
        let client = FakePasskeyClient()
        client.suspendRegistration = true
        let flow = PasskeyFlow(client: client)
        let backend = RegistrationFixtureBackend()
        let first = Task { @MainActor in
            try await flow.register("first", backend: backend)
        }
        while !client.registrationIsSuspended {
            await Task.yield()
        }

        let second = try await flow.register("second", backend: backend)
        XCTAssertEqual(second, .failure(.alreadyInProgress))

        client.resumeRegistration(returning: Data("first-response".utf8))
        let firstResult = try await first.value
        let thirdResult = try await flow.register("third", backend: backend)
        XCTAssertEqual(firstResult, .success("registered"))
        XCTAssertEqual(thirdResult, .success("registered"))
    }

    func testCallbackAndFinishErrorsPropagateAndReleaseLock() async throws {
        let flow = PasskeyFlow(client: FakePasskeyClient())

        do {
            _ = try await flow.register(
                "user",
                backend: RegistrationFixtureBackend(),
                onPhaseChanged: { _ in throw FixtureError.callback }
            )
            XCTFail("Expected callback error to propagate")
        } catch let error as FixtureError {
            XCTAssertEqual(error, .callback)
        }

        do {
            _ = try await flow.register("user", backend: ThrowingRegistrationBackend(stage: .finish))
            XCTFail("Expected finish error to propagate")
        } catch let error as FixtureError {
            XCTAssertEqual(error, .backend)
        }

        let retryResult = try await flow.register("user", backend: RegistrationFixtureBackend())
        XCTAssertEqual(retryResult, .success("registered"))
    }

    func testCancellationPropagatesAndReleasesLock() async throws {
        let client = FakePasskeyClient()
        client.suspendRegistration = true
        let flow = PasskeyFlow(client: client)
        let backend = RegistrationFixtureBackend()
        let operation = Task { @MainActor in
            try await flow.register("user", backend: backend)
        }
        while !client.registrationIsSuspended {
            await Task.yield()
        }

        operation.cancel()
        client.resumeRegistration(returning: Data("late-response".utf8))

        do {
            _ = try await operation.value
            XCTFail("Expected cancellation to propagate")
        } catch is CancellationError {
            // Expected.
        }

        let retryResult = try await flow.register("next", backend: backend)
        XCTAssertEqual(retryResult, .success("registered"))
    }
}

private enum FixtureError: Error, Equatable {
    case backend
    case callback
}

@MainActor
private final class FakePasskeyClient: PasskeyClientProtocol {
    var registrationResponse = Data("registration".utf8)
    var authenticationResponse = Data("authentication".utf8)
    var registrationError: Error?
    var suspendRegistration = false
    private var registrationContinuation: CheckedContinuation<Data, Error>?

    var registrationIsSuspended: Bool { registrationContinuation != nil }

    func createCredential(optionsJSON: Data) async throws -> Data {
        if let registrationError {
            throw registrationError
        }
        if suspendRegistration {
            suspendRegistration = false
            return try await withCheckedThrowingContinuation { continuation in
                registrationContinuation = continuation
            }
        }
        return registrationResponse
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        authenticationResponse
    }

    func capabilities() async throws -> PasskeyCapabilities {
        PasskeyCapabilities()
    }

    func resumeRegistration(returning response: Data) {
        let continuation = registrationContinuation
        registrationContinuation = nil
        continuation?.resume(returning: response)
    }
}

@MainActor
private final class RegistrationFixtureBackend: RegistrationBackend {
    private(set) var finishedState: String?
    private(set) var finishedResponse: Data?

    func start(input: String) async throws -> CeremonyStart<String> {
        CeremonyStart(state: "continuation:\(input)", optionsJSON: Data("registration-options".utf8))
    }

    func finish(state: String, responseJSON: Data) async throws -> String {
        finishedState = state
        finishedResponse = responseJSON
        return "registered"
    }
}

@MainActor
private final class AuthenticationFixtureBackend: AuthenticationBackend {
    private(set) var finishedState: Int?
    private(set) var finishedResponse: Data?

    func start(input: Int) async throws -> CeremonyStart<Int> {
        CeremonyStart(state: input, optionsJSON: Data("authentication-options".utf8))
    }

    func finish(state: Int, responseJSON: Data) async throws -> Int {
        finishedState = state
        finishedResponse = responseJSON
        return 7
    }
}

@MainActor
private struct ThrowingRegistrationBackend: RegistrationBackend {
    enum Stage: Equatable {
        case start
        case finish
    }

    let stage: Stage

    func start(input: String) async throws -> CeremonyStart<Void> {
        if stage == .start {
            throw FixtureError.backend
        }
        return CeremonyStart(state: (), optionsJSON: Data("registration-options".utf8))
    }

    func finish(state: Void, responseJSON: Data) async throws -> Void {
        if stage == .finish {
            throw FixtureError.backend
        }
    }
}
