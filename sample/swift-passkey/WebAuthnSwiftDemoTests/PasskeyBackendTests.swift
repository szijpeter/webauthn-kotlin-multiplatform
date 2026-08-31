import Foundation
import XCTest
@testable import WebAuthnSwiftDemo

@MainActor
final class PasskeyBackendTests: XCTestCase {
    func testFinishAcceptsVerifiedResponse() async throws {
        let outcome = try await backend(fixture: "verified").finishAuthentication(responseJSON: response)

        XCTAssertEqual(outcome, .verified)
    }

    func testFinishPreservesLegacyTwoHundredRejection() async throws {
        let outcome = try await backend(fixture: "legacy-rejection")
            .finishAuthentication(responseJSON: response)

        XCTAssertEqual(outcome, .rejected("Server returned status 'denied'."))
    }

    func testFinishMapsClientValidationFailureToRejected() async throws {
        let outcome = try await backend(fixture: "client-rejection")
            .finishAuthentication(responseJSON: response)

        XCTAssertEqual(outcome, .rejected("challenge mismatch; origin mismatch"))
    }

    func testFinishKeepsServerFailureAsBackendError() async throws {
        do {
            _ = try await backend(fixture: "server-failure")
                .finishAuthentication(responseJSON: response)
            XCTFail("Expected the server failure to remain a transport/backend error")
        } catch let error as BackendError {
            XCTAssertEqual(error, .httpStatus(500, "temporary failure"))
        }
    }

    func testStartClientFailureDoesNotBecomeFinishRejection() async throws {
        do {
            _ = try await backend(fixture: "client-rejection").startRegistration(config: .testValue)
            XCTFail("Expected the invalid start request to throw")
        } catch let error as BackendError {
            XCTAssertEqual(error, .httpStatus(400, "challenge mismatch; origin mismatch"))
        }
    }

    private var response: Data { Data("{}".utf8) }

    private func backend(fixture: String) -> URLSessionPasskeyBackend {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [FixtureURLProtocol.self]
        let endpoint = URL(string: "https://\(fixture).example.test")!
        return URLSessionPasskeyBackend(
            endpoint: endpoint,
            session: URLSession(configuration: configuration)
        )
    }
}

private final class FixtureURLProtocol: URLProtocol, @unchecked Sendable {
    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        let fixture = request.url?.host?.split(separator: ".").first.map(String.init)
        let status: Int
        let payload: String
        switch fixture {
        case "verified":
            status = 200
            payload = #"{"status":"ok"}"#
        case "legacy-rejection":
            status = 200
            payload = #"{"status":"denied"}"#
        case "client-rejection":
            status = 400
            payload = #"{"errors":["challenge mismatch","origin mismatch"]}"#
        case "server-failure":
            status = 500
            payload = #"{"errors":["temporary failure"]}"#
        default:
            status = 404
            payload = #"{"errors":["unknown fixture"]}"#
        }

        let response = HTTPURLResponse(
            url: request.url!,
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        )!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(payload.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
