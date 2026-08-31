import Foundation
import UIKit

/// Native Swift facade for WebAuthn registration and authentication on iOS.
@MainActor
public final class PasskeyClient {
    /// Resolves the foreground window used to present a platform ceremony.
    public typealias PresentationAnchorProvider = @MainActor @Sendable () -> UIWindow?

    private let bridge: any PasskeyCoreBridge
    private let presentationAnchorProvider: PresentationAnchorProvider

    /// Creates a client that resolves its presentation window immediately before each ceremony.
    public init(presentationAnchorProvider: @escaping PresentationAnchorProvider) {
        self.bridge = KmpPasskeyCoreBridge()
        self.presentationAnchorProvider = presentationAnchorProvider
    }

    /// Creates a client for a stable presentation window.
    public convenience init(presentationAnchor: UIWindow) {
        self.init { presentationAnchor }
    }

    init(
        bridge: any PasskeyCoreBridge,
        presentationAnchorProvider: @escaping PresentationAnchorProvider
    ) {
        self.bridge = bridge
        self.presentationAnchorProvider = presentationAnchorProvider
    }

    /// Creates a credential from UTF-8 WebAuthn creation-options JSON.
    ///
    /// The returned data is the exact UTF-8 credential-response JSON produced by the shared codec.
    public func createCredential(optionsJSON: Data) async throws -> Data {
        let request = try Self.utf8String(from: optionsJSON)
        let result = try await bridge.createCredential(
            optionsJSON: request,
            presentationAnchor: try presentationAnchor()
        )
        return try Self.responseData(from: result)
    }

    /// Gets an assertion from UTF-8 WebAuthn request-options JSON.
    ///
    /// The returned data is the exact UTF-8 credential-response JSON produced by the shared codec.
    public func getAssertion(optionsJSON: Data) async throws -> Data {
        let request = try Self.utf8String(from: optionsJSON)
        let result = try await bridge.getAssertion(
            optionsJSON: request,
            presentationAnchor: try presentationAnchor()
        )
        return try Self.responseData(from: result)
    }

    /// Returns the platform's current passkey capability snapshot.
    public func capabilities() async throws -> PasskeyCapabilities {
        try await bridge.capabilities()
    }

    func authenticateWithPrf(
        optionsJSON: Data,
        firstSalt: Data,
        secondSalt: Data?
    ) async throws -> BridgePrfAuthenticationResult {
        return try await bridge.authenticateWithPrf(
            optionsJSON: Self.utf8String(from: optionsJSON),
            firstSalt: firstSalt.base64URLEncodedString(),
            secondSalt: secondSalt?.base64URLEncodedString(),
            presentationAnchor: try presentationAnchor()
        )
    }

    private func presentationAnchor() throws -> UIWindow {
        guard let window = presentationAnchorProvider() else {
            throw PasskeyClientError.unavailablePresentationAnchor
        }
        return window
    }

    private static func utf8String(from data: Data) throws -> String {
        guard let value = String(data: data, encoding: .utf8) else {
            throw PasskeyClientError.invalidUTF8
        }
        return value
    }

    private static func responseData(from result: BridgePasskeyResult) throws -> Data {
        if let response = result.responseJSON,
           result.errorCode == nil,
           result.errorMessage == nil,
           let data = response.data(using: .utf8) {
            return data
        }
        throw PasskeyClientError.bridge(code: result.errorCode, message: result.errorMessage)
    }
}
