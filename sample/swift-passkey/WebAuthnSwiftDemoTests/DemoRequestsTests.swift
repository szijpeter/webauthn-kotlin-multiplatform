import XCTest
@testable import WebAuthnSwiftDemo

final class DemoRequestsTests: XCTestCase {
    func testRegistrationPayloadMatchesBackendContract() throws {
        let data = try DemoRequests.registrationStart(.testValue)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["rpId"] as? String, "example.test")
        XCTAssertEqual(json["rpName"] as? String, "WebAuthn Kotlin MPP Sample Backend")
        XCTAssertEqual(json["origin"] as? String, "https://example.test")
        XCTAssertEqual(json["userName"] as? String, "Sample User")
        XCTAssertEqual(json["residentKey"] as? String, "required")
        XCTAssertEqual(json["userHandle"] as? String, Data("not base64!".utf8).base64URLEncodedString())
    }

    func testRegistrationPayloadEncodesDefaultLikeHandleAsRawText() throws {
        let config = DemoConfiguration(
            endpoint: .testEndpoint,
            rpID: "example.test",
            origin: "https://example.test",
            userHandle: "42",
            userName: "Sample User"
        )

        let data = try DemoRequests.registrationStart(config)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["userHandle"] as? String, "NDI")
    }

    func testRegistrationPayloadDoesNotGuessThatRawTextIsAlreadyEncoded() throws {
        let config = DemoConfiguration(
            endpoint: .testEndpoint,
            rpID: "example.test",
            origin: "https://example.test",
            userHandle: "NDI",
            userName: "Sample User"
        )

        let data = try DemoRequests.registrationStart(config)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])

        XCTAssertEqual(json["userHandle"] as? String, "TkRJ")
    }

    func testPrfAuthenticationPayloadContainsCallerOwnedSalt() throws {
        let salt = Data(repeating: 7, count: 32)
        let data = try DemoRequests.authenticationStart(.testValue, prfSalt: salt)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let extensions = try XCTUnwrap(json["extensions"] as? [String: Any])
        let prf = try XCTUnwrap(extensions["prf"] as? [String: Any])
        let eval = try XCTUnwrap(prf["eval"] as? [String: Any])

        XCTAssertEqual(eval["first"] as? String, salt.base64URLEncodedString())
        XCTAssertNil(json["userName"])
    }

    func testFinishPayloadWrapsResponseWithoutChangingFields() throws {
        let response = Data("{\"id\":\"credential\",\"rawId\":\"AQID\"}".utf8)
        let data = try DemoRequests.finish(responseJSON: response)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let wrapped = try XCTUnwrap(json["response"] as? [String: Any])

        XCTAssertEqual(wrapped["id"] as? String, "credential")
        XCTAssertEqual(wrapped["rawId"] as? String, "AQID")
    }
}

extension DemoConfiguration {
    static let testValue = DemoConfiguration(
        endpoint: URL(string: "https://example.test")!,
        rpID: "example.test",
        origin: "https://example.test",
        userHandle: "not base64!",
        userName: "Sample User"
    )
}

private extension URL {
    static let testEndpoint = URL(string: "https://example.test")!
}
