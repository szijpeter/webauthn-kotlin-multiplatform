import Foundation
import UIKit
import WebAuthn

@MainActor
protocol DemoCryptoSession: AnyObject {
    var keyFingerprint: String { get }
    func encrypt(_ plaintext: Data, associatedData: Data?) async throws -> DemoPrfCiphertext
    func decrypt(_ ciphertext: DemoPrfCiphertext) async throws -> Data
    func clear() async
}

struct DemoPrfAuthentication {
    let responseJSON: Data
    let session: any DemoCryptoSession
}

@MainActor
protocol PasskeyServing: PasskeyClientProtocol {
    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication
}

@MainActor
final class LivePasskeyService: PasskeyServing {
    private let passkeyClient: PasskeyClient
    private let prfClient: PrfCryptoClient

    init(presentationAnchorProvider: @escaping PasskeyClient.PresentationAnchorProvider) {
        let passkeyClient = PasskeyClient(presentationAnchorProvider: presentationAnchorProvider)
        self.passkeyClient = passkeyClient
        self.prfClient = PrfCryptoClient(passkeyClient: passkeyClient)
    }

    func createCredential(optionsJSON: Data) async throws -> Data {
        try await passkeyClient.createCredential(optionsJSON: optionsJSON)
    }

    func getAssertion(optionsJSON: Data) async throws -> Data {
        try await passkeyClient.getAssertion(optionsJSON: optionsJSON)
    }

    func capabilities() async throws -> PasskeyCapabilities {
        try await passkeyClient.capabilities()
    }

    func authenticateWithPrf(optionsJSON: Data, firstSalt: Data) async throws -> DemoPrfAuthentication {
        let result = try await prfClient.authenticate(
            optionsJSON: optionsJSON,
            firstSalt: firstSalt,
            context: "samples.swift-passkey.prf.v1"
        )
        return DemoPrfAuthentication(
            responseJSON: result.responseJSON,
            session: LiveCryptoSession(session: result.session)
        )
    }
}

@MainActor
private final class LiveCryptoSession: DemoCryptoSession {
    private let session: PrfCryptoSession

    init(session: PrfCryptoSession) {
        self.session = session
    }

    var keyFingerprint: String { session.keyFingerprint }

    func encrypt(_ plaintext: Data, associatedData: Data?) async throws -> DemoPrfCiphertext {
        let value = try await session.encrypt(plaintext, associatedData: associatedData)
        return DemoPrfCiphertext(
            nonce: value.nonce,
            ciphertext: value.ciphertext,
            authenticationTag: value.authenticationTag,
            associatedData: value.associatedData
        )
    }

    func decrypt(_ ciphertext: DemoPrfCiphertext) async throws -> Data {
        try await session.decrypt(
            PrfCiphertext(
                nonce: ciphertext.nonce,
                ciphertext: ciphertext.ciphertext,
                authenticationTag: ciphertext.authenticationTag,
                associatedData: ciphertext.associatedData
            )
        )
    }

    func clear() async {
        await session.clear()
    }
}
