internal import CryptoKit
import Foundation

/// Complete AES-GCM payload produced by a PRF-derived session.
public struct PrfCiphertext: Equatable, Sendable {
    /// AES-GCM nonce.
    public let nonce: Data
    /// Encrypted payload bytes.
    public let ciphertext: Data
    /// AES-GCM authentication tag.
    public let authenticationTag: Data
    /// Optional authenticated, unencrypted data.
    public let associatedData: Data?

    /// Creates a complete AES-GCM payload for decryption.
    public init(
        nonce: Data,
        ciphertext: Data,
        authenticationTag: Data,
        associatedData: Data? = nil
    ) {
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.authenticationTag = authenticationTag
        self.associatedData = associatedData
    }
}

/// Actor-isolated, zeroizable session containing a PRF-derived AES key.
public actor PrfCryptoSession {
    private var keyBytes: Data?
    /// Non-secret fingerprint for correlating a derived key during local diagnostics.
    public nonisolated let keyFingerprint: String
    /// Domain-separation context used to derive this session key.
    public nonisolated let context: String

    init(keyBytes: Data, context: String) {
        precondition(keyBytes.count == 32, "A PRF session requires a 256-bit AES key.")
        self.keyBytes = keyBytes
        self.keyFingerprint = Self.fingerprint(keyBytes)
        self.context = context
    }

    deinit {
        guard let count = keyBytes?.count else { return }
        keyBytes?.resetBytes(in: 0..<count)
    }

    /// Whether the in-memory key material has been cleared.
    public var isCleared: Bool {
        get async {
            keyBytes == nil
        }
    }

    /// Encrypts bytes with AES-256-GCM and optional associated data.
    public func encrypt(_ plaintext: Data, associatedData: Data? = nil) async throws -> PrfCiphertext {
        let key = try symmetricKey()
        do {
            let sealed = try AES.GCM.seal(
                plaintext,
                using: key,
                authenticating: associatedData ?? Data()
            )
            return PrfCiphertext(
                nonce: Data(sealed.nonce),
                ciphertext: sealed.ciphertext,
                authenticationTag: sealed.tag,
                associatedData: associatedData
            )
        } catch {
            throw PasskeyClientError.crypto(message: "PRF encryption failed.")
        }
    }

    /// Authenticates and decrypts an AES-256-GCM payload.
    public func decrypt(_ ciphertext: PrfCiphertext) async throws -> Data {
        let key = try symmetricKey()
        do {
            let nonce = try AES.GCM.Nonce(data: ciphertext.nonce)
            let sealed = try AES.GCM.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext.ciphertext,
                tag: ciphertext.authenticationTag
            )
            return try AES.GCM.open(
                sealed,
                using: key,
                authenticating: ciphertext.associatedData ?? Data()
            )
        } catch {
            throw PasskeyClientError.crypto(message: "PRF decryption failed.")
        }
    }

    /// Idempotently zeroizes the derived key bytes.
    public func clear() async {
        guard let count = keyBytes?.count else { return }
        keyBytes?.resetBytes(in: 0..<count)
        keyBytes = nil
    }

    private func symmetricKey() throws -> SymmetricKey {
        guard let keyBytes else {
            throw PasskeyClientError.sessionCleared
        }
        return SymmetricKey(data: keyBytes)
    }

    private nonisolated static func fingerprint(_ keyBytes: Data) -> String {
        SHA256.hash(data: keyBytes)
            .prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}
