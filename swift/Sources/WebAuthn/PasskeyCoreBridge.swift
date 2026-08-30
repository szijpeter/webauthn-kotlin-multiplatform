import Foundation
import UIKit

struct BridgePasskeyResult: Sendable {
    let responseJSON: String?
    let errorCode: String?
    let errorMessage: String?
}

struct BridgePrfAuthenticationResult {
    let responseJSON: String?
    let firstResult: String?
    let secondResult: String?
    let errorCode: String?
    let errorMessage: String?
}

@MainActor
protocol PasskeyCoreBridge: AnyObject {
    func createCredential(optionsJSON: String, presentationAnchor: UIWindow) async throws -> BridgePasskeyResult
    func getAssertion(optionsJSON: String, presentationAnchor: UIWindow) async throws -> BridgePasskeyResult
    func capabilities() async throws -> PasskeyCapabilities
    func authenticateWithPrf(
        optionsJSON: String,
        firstSalt: String,
        secondSalt: String?,
        presentationAnchor: UIWindow
    ) async throws -> BridgePrfAuthenticationResult
}
