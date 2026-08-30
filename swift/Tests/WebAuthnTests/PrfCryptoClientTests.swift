import XCTest
@testable import WebAuthn

@MainActor
final class PrfCryptoClientTests: XCTestCase {
    func testAuthenticationReturnsSwiftValuesAndSession() async throws {
        let bridge = FakePasskeyCoreBridge()
        bridge.prfResult = BridgePrfAuthenticationResult(
            responseJSON: "{\"assertion\":true}",
            firstResult: Data(repeating: 1, count: 32).base64URLEncodedString(),
            secondResult: Data(repeating: 2, count: 32).base64URLEncodedString(),
            errorCode: nil,
            errorMessage: nil
        )
        let passkeyClient = PasskeyClient(bridge: bridge) { UIWindow() }
        let client = PrfCryptoClient(passkeyClient: passkeyClient)

        let result = try await client.authenticate(
            optionsJSON: Data("{}".utf8),
            firstSalt: Data(repeating: 7, count: 32),
            secondSalt: Data(repeating: 8, count: 32),
            context: "test.context",
            outputSelection: .second
        )

        XCTAssertEqual(result.responseJSON, Data("{\"assertion\":true}".utf8))
        XCTAssertEqual(result.results.first, Data(repeating: 1, count: 32))
        XCTAssertEqual(result.results.second, Data(repeating: 2, count: 32))
        XCTAssertEqual(result.session.keyFingerprint, "1bcd4415749d3c0f")
    }

    func testInvalidContextAndHkdfSaltFailBeforeBridge() async {
        let bridge = FakePasskeyCoreBridge()
        let client = PrfCryptoClient(
            passkeyClient: PasskeyClient(bridge: bridge) { UIWindow() }
        )

        await XCTAssertThrowsErrorAsync(
            try await client.authenticate(
                optionsJSON: Data("{}".utf8),
                firstSalt: Data(repeating: 1, count: 32),
                context: "   "
            )
        ) { error in
            XCTAssertEqual(
                error as? PasskeyClientError,
                .invalidOptions(message: "PRF context must not be blank.")
            )
        }
        await XCTAssertThrowsErrorAsync(
            try await client.authenticate(
                optionsJSON: Data("{}".utf8),
                firstSalt: Data(repeating: 1, count: 32),
                hkdfSalt: Data(repeating: 2, count: 31)
            )
        )
        XCTAssertEqual(bridge.prfCalls, 0)
    }

    func testSessionEncryptDecryptAndClear() async throws {
        let session = PrfCryptoSession(
            keyBytes: Data(repeating: 3, count: 32),
            context: "test.context"
        )
        let plaintext = Data("secret".utf8)
        let associatedData = Data("aad".utf8)

        let ciphertext = try await session.encrypt(plaintext, associatedData: associatedData)
        let decrypted = try await session.decrypt(ciphertext)
        await session.clear()
        await session.clear()
        let isCleared = await session.isCleared

        XCTAssertEqual(decrypted, plaintext)
        XCTAssertEqual(ciphertext.associatedData, associatedData)
        XCTAssertTrue(isCleared)
        await XCTAssertThrowsErrorAsync(
            try await session.encrypt(Data("late".utf8))
        ) { error in
            XCTAssertEqual(error as? PasskeyClientError, .sessionCleared)
        }
    }

    func testSessionRejectsTamperedCiphertext() async throws {
        let session = PrfCryptoSession(
            keyBytes: Data(repeating: 4, count: 32),
            context: "test.context"
        )
        let encrypted = try await session.encrypt(
            Data("secret".utf8),
            associatedData: Data("account-a".utf8)
        )
        let tampered = PrfCiphertext(
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
            authenticationTag: encrypted.authenticationTag,
            associatedData: Data("account-b".utf8)
        )

        await XCTAssertThrowsErrorAsync(
            try await session.decrypt(tampered)
        ) { error in
            XCTAssertEqual(error as? PasskeyClientError, .crypto(message: "PRF decryption failed."))
        }
        await session.clear()
    }

    func testMalformedBridgeOutputIsRejected() async {
        let bridge = FakePasskeyCoreBridge()
        bridge.prfResult = BridgePrfAuthenticationResult(
            responseJSON: "{}",
            firstResult: Data(repeating: 1, count: 31).base64URLEncodedString(),
            secondResult: nil,
            errorCode: nil,
            errorMessage: nil
        )
        let client = PrfCryptoClient(
            passkeyClient: PasskeyClient(bridge: bridge) { UIWindow() }
        )

        await XCTAssertThrowsErrorAsync(
            try await client.authenticate(
                optionsJSON: Data("{}".utf8),
                firstSalt: Data(repeating: 1, count: 32)
            )
        )

        XCTAssertNil(Data(base64URLString: "A"))
    }

    func testKotlinSwiftHkdfParityVector() async throws {
        let bridge = FakePasskeyCoreBridge()
        bridge.prfResult = BridgePrfAuthenticationResult(
            responseJSON: "{}",
            firstResult: Data((0..<32).map(UInt8.init)).base64URLEncodedString(),
            secondResult: nil,
            errorCode: nil,
            errorMessage: nil
        )
        let client = PrfCryptoClient(
            passkeyClient: PasskeyClient(bridge: bridge) { UIWindow() }
        )

        let result = try await client.authenticate(
            optionsJSON: Data("{}".utf8),
            firstSalt: Data(repeating: 1, count: 32),
            context: "webauthn-prf-parity-v1",
            hkdfSalt: Data((32..<64).map(UInt8.init))
        )

        XCTAssertEqual(result.session.keyFingerprint, "a7fb7d362417caf0")
    }
}
