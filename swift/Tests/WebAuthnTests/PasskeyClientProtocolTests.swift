import Foundation
import UIKit
import WebAuthn
import XCTest

@MainActor
final class PasskeyClientProtocolTests: XCTestCase {
    func testConsumerFakeCanDriveApplicationCode() async throws {
        let fake = ConsumerFakePasskeyClient(
            registrationResponse: Data("{\"id\":\"registered\"}".utf8),
            authenticationResponse: Data("{\"id\":\"authenticated\"}".utf8),
            capabilitySnapshot: PasskeyCapabilities(support: [.prf: .supported])
        )

        let registration = try await register(using: fake, optionsJSON: Data("{}".utf8))
        let authentication = try await authenticate(using: fake, optionsJSON: Data("{}".utf8))
        let capabilities = try await fake.capabilities()

        XCTAssertEqual(registration, Data("{\"id\":\"registered\"}".utf8))
        XCTAssertEqual(authentication, Data("{\"id\":\"authenticated\"}".utf8))
        XCTAssertTrue(capabilities.supports(.prf))
        XCTAssertEqual(fake.registrationCalls, 1)
        XCTAssertEqual(fake.authenticationCalls, 1)
        XCTAssertEqual(fake.capabilityCalls, 1)
    }

    func testConcreteClientSatisfiesPublicContract() {
        let client: any PasskeyClientProtocol = PasskeyClient(presentationAnchor: UIWindow())

        acceptSendable(client)
    }
}

@MainActor
private func register(
    using client: any PasskeyClientProtocol,
    optionsJSON: Data
) async throws -> Data {
    try await client.createCredential(optionsJSON: optionsJSON)
}

@MainActor
private func authenticate(
    using client: any PasskeyClientProtocol,
    optionsJSON: Data
) async throws -> Data {
    try await client.getAssertion(optionsJSON: optionsJSON)
}

private func acceptSendable<T: Sendable>(_ value: T) {}

@MainActor
private final class ConsumerFakePasskeyClient: PasskeyClientProtocol {
    private let registrationResponse: Data
    private let authenticationResponse: Data
    private let capabilitySnapshot: PasskeyCapabilities

    private(set) var registrationCalls = 0
    private(set) var authenticationCalls = 0
    private(set) var capabilityCalls = 0

    init(
        registrationResponse: Data,
        authenticationResponse: Data,
        capabilitySnapshot: PasskeyCapabilities
    ) {
        self.registrationResponse = registrationResponse
        self.authenticationResponse = authenticationResponse
        self.capabilitySnapshot = capabilitySnapshot
    }

    func createCredential(optionsJSON: Data) async throws -> Data {
        registrationCalls += 1
        return registrationResponse
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        authenticationCalls += 1
        return authenticationResponse
    }

    func capabilities() async throws -> PasskeyCapabilities {
        capabilityCalls += 1
        return capabilitySnapshot
    }
}
