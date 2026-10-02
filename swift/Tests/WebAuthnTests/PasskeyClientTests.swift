import XCTest
@testable import WebAuthn

@MainActor
final class PasskeyClientTests: XCTestCase {
    func testCreateCredentialReturnsExactUTF8Response() async throws {
        let bridge = FakePasskeyCoreBridge()
        bridge.createResult = BridgePasskeyResult(
            responseJSON: "{\"id\":\"credential\"}",
            errorCode: nil,
            errorMessage: nil
        )
        let firstWindow = UIWindow()
        let client = PasskeyClient(bridge: bridge) { firstWindow }

        let response = try await client.createCredential(optionsJSON: Data("{}".utf8))

        XCTAssertEqual(response, Data("{\"id\":\"credential\"}".utf8))
        XCTAssertTrue(bridge.lastAnchor === firstWindow)
    }

    func testInvalidUTF8FailsBeforeBridge() async {
        let bridge = FakePasskeyCoreBridge()
        let client = PasskeyClient(bridge: bridge) { UIWindow() }

        await XCTAssertThrowsErrorAsync(
            try await client.getAssertion(optionsJSON: Data([0xFF]))
        ) { error in
            XCTAssertEqual(error as? PasskeyClientError, .invalidUTF8)
        }
        XCTAssertEqual(bridge.getCalls, 0)
    }

    func testPresentationAnchorIsResolvedForEveryCeremony() async throws {
        let bridge = FakePasskeyCoreBridge()
        let first = UIWindow()
        let second = UIWindow()
        let windows = WindowBox(first)
        let client = PasskeyClient(bridge: bridge) { windows.current }

        _ = try await client.createCredential(optionsJSON: Data("{}".utf8))
        XCTAssertTrue(bridge.lastAnchor === first)
        windows.current = second
        _ = try await client.getAssertion(optionsJSON: Data("{}".utf8))
        XCTAssertTrue(bridge.lastAnchor === second)
    }

    func testMissingPresentationAnchorIsTypedError() async {
        let bridge = FakePasskeyCoreBridge()
        let client = PasskeyClient(bridge: bridge) { nil }

        await XCTAssertThrowsErrorAsync(
            try await client.createCredential(optionsJSON: Data("{}".utf8))
        ) { error in
            XCTAssertEqual(error as? PasskeyClientError, .unavailablePresentationAnchor)
        }
        XCTAssertEqual(bridge.createCalls, 0)
    }

    func testEveryBridgeErrorCodeMapsToSwiftError() {
        let mappings: [(String?, PasskeyClientError)] = [
            ("userCancelled", .userCancelled),
            ("noCredential", .noCredential),
            ("invalidOptions", .invalidOptions(message: "message")),
            ("platform", .platform(message: "message")),
            ("codec", .codec(message: "message")),
            ("operationInProgress", .operationInProgress),
            ("sessionCleared", .sessionCleared),
            ("crypto", .crypto(message: "message")),
            ("futureCode", .bridgeContract(message: "message")),
        ]

        mappings.forEach { code, expected in
            XCTAssertEqual(PasskeyClientError.bridge(code: code, message: "message"), expected)
        }
    }

    func testPlatformErrorMessagesNeverControlErrorTyping() {
        let formerSentinel = "No active iOS presentation anchor available for passkey prompt."

        XCTAssertEqual(
            PasskeyClientError.bridge(code: "platform", message: formerSentinel),
            .platform(message: formerSentinel)
        )
    }

    func testCapabilityDecoderPreservesCollidingDomains() throws {
        let valuesJSON = """
        [
          {"kind":"extension","id":"securityKey","support":"supported"},
          {"kind":"platform","id":"securityKey","support":"unknown"}
        ]
        """

        let capabilities = try KmpPasskeyCoreBridge.decodeCapabilities(
            valuesJSON: valuesJSON,
            reportedCount: 2
        )

        XCTAssertEqual(capabilities.reportedCount, 2)
        XCTAssertEqual(
            capabilities.support(
                for: PasskeyCapability(kind: .webAuthnExtension, id: "securityKey")
            ),
            .supported
        )
        XCTAssertEqual(capabilities.support(for: .securityKey), .unknown)
    }

    func testCapabilityDecoderRejectsDuplicateTypedIdentifiers() {
        let valuesJSON = """
        [
          {"kind":"platform","id":"securityKey","support":"supported"},
          {"kind":"platform","id":"securityKey","support":"unknown"}
        ]
        """

        XCTAssertThrowsError(
            try KmpPasskeyCoreBridge.decodeCapabilities(valuesJSON: valuesJSON, reportedCount: 2)
        ) { error in
            XCTAssertEqual(
                error as? PasskeyClientError,
                .bridgeContract(message: "Capability data from the bridge is duplicated.")
            )
        }
    }

    func testCapabilitiesPreserveUnknownAndCustomValues() async throws {
        let bridge = FakePasskeyCoreBridge()
        bridge.capabilityResult = PasskeyCapabilities(
            support: [
                .prf: .supported,
                .largeBlob: .unknown,
                PasskeyCapability(kind: .platform, id: "futureCapability"): .unsupported,
            ]
        )
        let client = PasskeyClient(bridge: bridge) { UIWindow() }

        let capabilities = try await client.capabilities()

        XCTAssertTrue(capabilities.supports(.prf))
        XCTAssertEqual(capabilities.support(for: .largeBlob), .unknown)
        XCTAssertEqual(capabilities.reportedCount, 3)
    }
}

@MainActor
final class FakePasskeyCoreBridge: PasskeyCoreBridge {
    var createResult = BridgePasskeyResult(responseJSON: "{}", errorCode: nil, errorMessage: nil)
    var getResult = BridgePasskeyResult(responseJSON: "{}", errorCode: nil, errorMessage: nil)
    var capabilityResult = PasskeyCapabilities()
    var prfResult: BridgePrfAuthenticationResult?
    var createCalls = 0
    var getCalls = 0
    var prfCalls = 0
    var lastAnchor: UIWindow?

    func createCredential(
        optionsJSON: String,
        presentationAnchor: UIWindow
    ) async throws -> BridgePasskeyResult {
        createCalls += 1
        lastAnchor = presentationAnchor
        return createResult
    }

    func getAssertion(
        optionsJSON: String,
        presentationAnchor: UIWindow
    ) async throws -> BridgePasskeyResult {
        getCalls += 1
        lastAnchor = presentationAnchor
        return getResult
    }

    func capabilities() async throws -> PasskeyCapabilities {
        capabilityResult
    }

    func authenticateWithPrf(
        optionsJSON: String,
        firstSalt: String,
        secondSalt: String?,
        presentationAnchor: UIWindow
    ) async throws -> BridgePrfAuthenticationResult {
        prfCalls += 1
        lastAnchor = presentationAnchor
        guard let prfResult else {
            throw PasskeyClientError.bridgeContract(message: "Missing fake PRF result")
        }
        return prfResult
    }
}

@MainActor
func XCTAssertThrowsErrorAsync<T: Sendable>(
    _ expression: @autoclosure () async throws -> T,
    _ errorHandler: (Error) -> Void = { _ in },
    file: StaticString = #filePath,
    line: UInt = #line
) async {
    do {
        _ = try await expression()
        XCTFail("Expected expression to throw", file: file, line: line)
    } catch {
        errorHandler(error)
    }
}

@MainActor
private final class WindowBox {
    var current: UIWindow

    init(_ current: UIWindow) {
        self.current = current
    }
}
