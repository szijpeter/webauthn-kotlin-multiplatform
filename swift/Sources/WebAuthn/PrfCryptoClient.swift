internal import CryptoKit
import Foundation

/// Selects which authenticator PRF output is used for key derivation.
public enum PrfOutputSelection: String, Sendable {
    case first
    case second
}

/// Raw PRF output values returned by the authenticator.
public struct PrfResults: Equatable, Sendable {
    /// Output for the first PRF input.
    public let first: Data
    /// Output for the optional second PRF input.
    public let second: Data?

    /// Creates a PRF output value.
    public init(first: Data, second: Data? = nil) {
        self.first = first
        self.second = second
    }
}

/// Result of a successful PRF-enabled assertion.
public struct PrfAuthenticationResult: Sendable {
    /// UTF-8 WebAuthn assertion-response JSON to verify with the relying party.
    public let responseJSON: Data
    /// Raw authenticator PRF outputs.
    public let results: PrfResults
    /// In-memory session containing the derived AES key.
    public let session: PrfCryptoSession

    /// Creates a successful PRF authentication result.
    public init(responseJSON: Data, results: PrfResults, session: PrfCryptoSession) {
        self.responseJSON = responseJSON
        self.results = results
        self.session = session
    }
}

/// Executes a PRF-enabled assertion and derives an in-memory CryptoKit session.
@MainActor
public final class PrfCryptoClient {
    /// Domain-separation context used when the caller does not provide one.
    public nonisolated static let defaultContext = "webauthn-prf-crypto"

    private let passkeyClient: PasskeyClient

    /// Creates a PRF facade that uses the supplied passkey client and presentation policy.
    public init(passkeyClient: PasskeyClient) {
        self.passkeyClient = passkeyClient
    }

    /// Runs an assertion with caller-owned PRF inputs and derives a zeroizable AES session.
    ///
    /// Verify `responseJSON` with the relying party before treating the returned session as authenticated.
    public func authenticate(
        optionsJSON: Data,
        firstSalt: Data,
        secondSalt: Data? = nil,
        context: String = PrfCryptoClient.defaultContext,
        hkdfSalt: Data? = nil,
        outputSelection: PrfOutputSelection = .first
    ) async throws -> PrfAuthenticationResult {
        guard !context.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw PasskeyClientError.invalidOptions(message: "PRF context must not be blank.")
        }
        if let hkdfSalt, hkdfSalt.count != 32 {
            throw PasskeyClientError.invalidOptions(message: "HKDF salt must be exactly 32 bytes.")
        }
        let result = try await passkeyClient.authenticateWithPrf(
            optionsJSON: optionsJSON,
            firstSalt: firstSalt,
            secondSalt: secondSalt
        )
        guard result.errorCode == nil, result.errorMessage == nil else {
            throw PasskeyClientError.bridge(code: result.errorCode, message: result.errorMessage)
        }
        guard let response = result.responseJSON,
              let responseData = response.data(using: .utf8),
              let first = result.firstResult.flatMap(Data.init(base64URLString:)),
              first.count == 32
        else {
            throw PasskeyClientError.bridgeContract(message: "The PRF bridge returned invalid output data.")
        }
        let second: Data?
        if let encodedSecond = result.secondResult {
            guard let decodedSecond = Data(base64URLString: encodedSecond), decodedSecond.count == 32 else {
                throw PasskeyClientError.bridgeContract(message: "The PRF bridge returned invalid output data.")
            }
            second = decodedSecond
        } else {
            second = nil
        }

        let selectedOutput: Data
        switch outputSelection {
        case .first:
            selectedOutput = first
        case .second:
            guard let second else {
                throw PasskeyClientError.invalidOptions(
                    message: "PRF output selection is SECOND but authenticator returned only one output."
                )
            }
            selectedOutput = second
        }
        let inputKeyMaterial = SymmetricKey(data: selectedOutput)
        let derivedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: inputKeyMaterial,
            salt: hkdfSalt ?? Data(repeating: 0, count: 32),
            info: Data(context.utf8),
            outputByteCount: 32
        )
        var keyBytes = derivedKey.withUnsafeBytes { Data($0) }
        defer { keyBytes.resetBytes(in: 0..<keyBytes.count) }
        let session = PrfCryptoSession(keyBytes: keyBytes, context: context)

        return PrfAuthenticationResult(
            responseJSON: responseData,
            results: PrfResults(first: first, second: second),
            session: session
        )
    }
}
