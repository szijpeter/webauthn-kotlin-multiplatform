import Foundation

/// Application-facing contract for passkey ceremonies and capability queries.
///
/// Depend on this protocol when application code needs to substitute a deterministic test fake. Use
/// ``PasskeyClient`` as the production implementation.
@MainActor
public protocol PasskeyClientProtocol: Sendable {
    /// Creates a credential from UTF-8 WebAuthn creation-options JSON.
    func createCredential(optionsJSON: Data) async throws -> Data

    /// Gets an assertion from UTF-8 WebAuthn request-options JSON.
    func getAssertion(optionsJSON: Data) async throws -> Data

    /// Returns the platform's current passkey capability snapshot.
    func capabilities() async throws -> PasskeyCapabilities
}

extension PasskeyClient: PasskeyClientProtocol {}
