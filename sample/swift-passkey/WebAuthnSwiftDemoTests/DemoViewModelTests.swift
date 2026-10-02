import WebAuthn
import XCTest
@testable import WebAuthnSwiftDemo

@MainActor
final class DemoViewModelTests: XCTestCase {
    func testRegistrationRunsAllPhasesAndRemainsSignedOut() async {
        let fixture = Fixture()

        await fixture.viewModel.register()

        XCTAssertEqual(fixture.viewModel.ceremonyState, .success(action: .register))
        XCTAssertEqual(fixture.viewModel.route, .authentication)
        XCTAssertEqual(fixture.backend.registrationStarts, 1)
        XCTAssertEqual(fixture.backend.registrationFinishes, 1)
        XCTAssertEqual(fixture.passkeys.registrationCalls, 1)
        XCTAssertEqual(
            fixture.viewModel.logs.entries.map(\.message).filter { $0.hasPrefix("Register ") },
            ["Register starting", "Register platformPrompt", "Register finishing", "Register success"]
        )
    }

    func testSignInOpensMainOnlyAfterBackendVerification() async {
        let fixture = Fixture()

        await fixture.viewModel.signIn()

        XCTAssertEqual(fixture.viewModel.ceremonyState, .success(action: .signIn))
        XCTAssertEqual(fixture.viewModel.route, .main)
        XCTAssertEqual(fixture.backend.authenticationStarts, 1)
        XCTAssertEqual(fixture.backend.authenticationFinishes, 1)
    }

    func testRejectedSignInStaysOnAuthenticationRoute() async {
        let fixture = Fixture()
        fixture.backend.authenticationFinish = .rejected("not verified")

        await fixture.viewModel.signIn()

        XCTAssertEqual(
            fixture.viewModel.ceremonyState,
            .failure(
                action: .signIn,
                failure: DemoFailure(kind: .rejected, message: "not verified")
            )
        )
        XCTAssertEqual(fixture.viewModel.route, .authentication)
    }

    func testPlatformCancellationRemainsTyped() async {
        let fixture = Fixture()
        fixture.passkeys.assertionError = PasskeyClientError.userCancelled

        await fixture.viewModel.signIn()

        guard case let .failure(_, failure) = fixture.viewModel.ceremonyState else {
            return XCTFail("Expected typed ceremony failure")
        }
        XCTAssertEqual(failure.kind, .userCancelled)
        XCTAssertEqual(fixture.viewModel.ceremonyState.status.tone, .warning)
    }

    func testConcurrentCeremonyUsesFlowFailureAndFirstOperationCanFinish() async {
        let passkeys = SuspendingCeremonyPasskeyService()
        let backend = FakePasskeyBackend()
        let viewModel = DemoViewModel(
            config: .testValue,
            passkeys: passkeys,
            backend: backend,
            loadCapabilitiesImmediately: false
        )
        let first = Task { @MainActor in await viewModel.signIn() }
        while !passkeys.assertionIsSuspended {
            await Task.yield()
        }

        await viewModel.register()
        guard case let .failure(_, failure) = viewModel.ceremonyState else {
            return XCTFail("Expected concurrent-use failure")
        }
        XCTAssertEqual(failure.kind, .alreadyInProgress)

        passkeys.resumeAssertion()
        await first.value
        XCTAssertEqual(viewModel.ceremonyState, .success(action: .signIn))
        XCTAssertEqual(viewModel.route, .main)
    }

    func testCapabilitiesAndPrfSessionLifecycle() async throws {
        let fixture = Fixture()
        fixture.passkeys.capabilityValue = PasskeyCapabilities(support: [.prf: .supported])
        await fixture.viewModel.loadCapabilities()

        await fixture.viewModel.signInWithPRF()
        XCTAssertEqual(fixture.viewModel.prfSessionState, .sessionReady)
        XCTAssertEqual(
            fixture.viewModel.prfStatus,
            "PRF session ready. Caller-owned salt is available."
        )

        fixture.viewModel.plaintext = "secret"
        await fixture.viewModel.encrypt()
        XCTAssertEqual(fixture.viewModel.prfSessionState, .ciphertextReady)

        await fixture.viewModel.decrypt()
        XCTAssertEqual(fixture.viewModel.decryptedText, "secret")

        let firstSalt = try XCTUnwrap(fixture.passkeys.lastPrfSalt)
        let ciphertext = try XCTUnwrap(fixture.passkeys.session.lastCiphertext)
        let surfacedDiagnostics = (
            [fixture.viewModel.prfStatus] + fixture.viewModel.logs.entries.map(\.message)
        ).joined(separator: "\n")
        let sensitiveValues = [
            fixture.viewModel.config.userHandle,
            "\(fixture.viewModel.config.rpID):\(fixture.viewModel.config.userHandle)",
            firstSalt.base64EncodedString(),
            firstSalt.map { String(format: "%02x", $0) }.joined(),
            fixture.passkeys.prfOutputMarker.base64EncodedString(),
            String(decoding: fixture.passkeys.assertionResponseJSON, as: UTF8.self),
            fixture.passkeys.session.keyFingerprint,
            ciphertext.ciphertext.base64EncodedString(),
        ]
        for value in sensitiveValues {
            XCTAssertFalse(surfacedDiagnostics.contains(value), "Surfaced sensitive diagnostic value: \(value)")
        }

        await fixture.viewModel.clearPrfSession()
        XCTAssertEqual(fixture.viewModel.prfSessionState, .noSession)
        XCTAssertEqual(fixture.passkeys.session.clearCalls, 1)
    }

    func testRejectedPrfAuthenticationClearsDerivedSession() async {
        let fixture = Fixture()
        fixture.passkeys.capabilityValue = PasskeyCapabilities(support: [.prf: .supported])
        fixture.backend.authenticationFinish = .rejected("no")
        await fixture.viewModel.loadCapabilities()

        await fixture.viewModel.signInWithPRF()

        XCTAssertEqual(fixture.viewModel.prfSessionState, .noSession)
        XCTAssertEqual(fixture.passkeys.session.clearCalls, 1)
    }

    func testSignOutInvalidatesAnInFlightPrfSession() async {
        let passkeys = SuspendingPasskeyService()
        let backend = FakePasskeyBackend()
        let viewModel = DemoViewModel(
            config: .testValue,
            passkeys: passkeys,
            backend: backend,
            loadCapabilitiesImmediately: false
        )
        await viewModel.loadCapabilities()
        let operation = Task { await viewModel.signInWithPRF() }
        while !passkeys.isAuthenticationSuspended {
            await Task.yield()
        }

        await viewModel.signOut()
        passkeys.resumeAuthentication()
        await operation.value

        XCTAssertEqual(viewModel.route, .authentication)
        XCTAssertEqual(viewModel.prfSessionState, .noSession)
        XCTAssertFalse(viewModel.prfBusy)
        XCTAssertEqual(passkeys.session.clearCalls, 1)
    }

    func testSignOutInvalidatesInFlightEncryption() async {
        let session = SuspendingCryptoSession()
        let passkeys = FixedSessionPasskeyService(session: session)
        let viewModel = DemoViewModel(
            config: .testValue,
            passkeys: passkeys,
            backend: FakePasskeyBackend(),
            loadCapabilitiesImmediately: false
        )
        await viewModel.loadCapabilities()
        await viewModel.signInWithPRF()
        viewModel.plaintext = "secret"
        let operation = Task { await viewModel.encrypt() }
        while !session.isEncryptionSuspended {
            await Task.yield()
        }

        await viewModel.signOut()
        session.resumeEncryption()
        await operation.value

        XCTAssertEqual(viewModel.route, .authentication)
        XCTAssertEqual(viewModel.prfSessionState, .noSession)
        XCTAssertFalse(viewModel.prfBusy)
        XCTAssertNil(viewModel.decryptedText)
        XCTAssertEqual(session.clearCalls, 1)
    }
}

@MainActor
private struct Fixture {
    let passkeys = FakePasskeyService()
    let backend = FakePasskeyBackend()
    let viewModel: DemoViewModel

    init() {
        viewModel = DemoViewModel(
            config: .testValue,
            passkeys: passkeys,
            backend: backend,
            loadCapabilitiesImmediately: false
        )
    }
}

@MainActor
private final class FakePasskeyService: PasskeyServing {
    let session = FakeCryptoSession()
    let assertionResponseJSON = Data("{\"authentication\":\"fixture-assertion-response\"}".utf8)
    let prfOutputMarker = Data("fixture-prf-output".utf8)
    var capabilityValue = PasskeyCapabilities()
    var assertionError: Error?
    var registrationCalls = 0
    private(set) var lastPrfSalt: Data?

    func createCredential(optionsJSON: Data) async throws -> Data {
        registrationCalls += 1
        return Data("{\"registration\":true}".utf8)
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        if let assertionError { throw assertionError }
        return assertionResponseJSON
    }

    func capabilities() async throws -> PasskeyCapabilities {
        capabilityValue
    }

    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication {
        lastPrfSalt = firstSalt
        return DemoPrfAuthentication(
            responseJSON: assertionResponseJSON,
            session: session
        )
    }
}

@MainActor
private final class SuspendingPasskeyService: PasskeyServing {
    let session = FakeCryptoSession()
    private var continuation: CheckedContinuation<DemoPrfAuthentication, Error>?
    var isAuthenticationSuspended: Bool { continuation != nil }

    func createCredential(optionsJSON: Data) async throws -> Data {
        Data("{}".utf8)
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        Data("{}".utf8)
    }

    func capabilities() async throws -> PasskeyCapabilities {
        PasskeyCapabilities(support: [.prf: .supported])
    }

    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
        }
    }

    func resumeAuthentication() {
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(
            returning: DemoPrfAuthentication(
                responseJSON: Data("{}".utf8),
                session: session
            )
        )
    }
}

@MainActor
private final class SuspendingCeremonyPasskeyService: PasskeyServing {
    private var assertionContinuation: CheckedContinuation<Data, Error>?
    var assertionIsSuspended: Bool { assertionContinuation != nil }

    func createCredential(optionsJSON: Data) async throws -> Data {
        Data("{}".utf8)
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            assertionContinuation = continuation
        }
    }

    func capabilities() async throws -> PasskeyCapabilities {
        PasskeyCapabilities()
    }

    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication {
        throw PasskeyClientError.noCredential
    }

    func resumeAssertion() {
        let continuation = assertionContinuation
        assertionContinuation = nil
        continuation?.resume(returning: Data("{}".utf8))
    }
}

@MainActor
private final class FixedSessionPasskeyService: PasskeyServing {
    private let session: any DemoCryptoSession

    init(session: any DemoCryptoSession) {
        self.session = session
    }

    func createCredential(optionsJSON: Data) async throws -> Data { Data("{}".utf8) }
    func getAssertion(optionsJSON: Data) async throws -> Data { Data("{}".utf8) }

    func capabilities() async throws -> PasskeyCapabilities {
        PasskeyCapabilities(support: [.prf: .supported])
    }

    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication {
        DemoPrfAuthentication(responseJSON: Data("{}".utf8), session: session)
    }
}

@MainActor
private final class SuspendingCryptoSession: DemoCryptoSession {
    let keyFingerprint = "0123456789abcdef"
    private var continuation: CheckedContinuation<DemoPrfCiphertext, Error>?
    private(set) var clearCalls = 0
    var isEncryptionSuspended: Bool { continuation != nil }

    func encrypt(_ plaintext: Data, associatedData: Data?) async throws -> DemoPrfCiphertext {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation
        }
    }

    func decrypt(_ ciphertext: DemoPrfCiphertext) async throws -> Data { ciphertext.ciphertext }

    func clear() async {
        clearCalls += 1
    }

    func resumeEncryption() {
        let continuation = continuation
        self.continuation = nil
        continuation?.resume(
            returning: DemoPrfCiphertext(
                nonce: Data(repeating: 1, count: 12),
                ciphertext: Data("late".utf8),
                authenticationTag: Data(repeating: 2, count: 16),
                associatedData: nil
            )
        )
    }
}

@MainActor
private final class FakeCryptoSession: DemoCryptoSession {
    let keyFingerprint = "0123456789abcdef"
    var clearCalls = 0
    private(set) var lastCiphertext: DemoPrfCiphertext?

    func encrypt(_ plaintext: Data, associatedData: Data?) async throws -> DemoPrfCiphertext {
        let value = DemoPrfCiphertext(
            nonce: Data(repeating: 1, count: 12),
            ciphertext: plaintext,
            authenticationTag: Data(repeating: 2, count: 16),
            associatedData: associatedData
        )
        lastCiphertext = value
        return value
    }

    func decrypt(_ ciphertext: DemoPrfCiphertext) async throws -> Data {
        ciphertext.ciphertext
    }

    func clear() async {
        clearCalls += 1
    }
}

@MainActor
private final class FakePasskeyBackend: PasskeyBackend {
    var registrationStarts = 0
    var registrationFinishes = 0
    var authenticationStarts = 0
    var authenticationFinishes = 0
    var registrationFinish: FinishOutcome = .verified
    var authenticationFinish: FinishOutcome = .verified

    func startRegistration(config: DemoConfiguration) async throws -> Data {
        registrationStarts += 1
        return Data("{}".utf8)
    }

    func finishRegistration(responseJSON: Data) async throws -> FinishOutcome {
        registrationFinishes += 1
        return registrationFinish
    }

    func startAuthentication(config: DemoConfiguration, prfSalt: Data?) async throws -> Data {
        authenticationStarts += 1
        return Data("{}".utf8)
    }

    func finishAuthentication(responseJSON: Data) async throws -> FinishOutcome {
        authenticationFinishes += 1
        return authenticationFinish
    }
}
