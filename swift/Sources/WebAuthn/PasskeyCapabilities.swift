import Foundation

/// Confidence with which the platform reports a passkey capability.
public enum CapabilitySupport: String, Codable, Sendable {
    case supported
    case unsupported
    case unknown
}

/// Namespace for a reported passkey capability.
public enum PasskeyCapabilityKind: String, Codable, Sendable {
    /// A W3C WebAuthn extension identifier.
    case webAuthnExtension = "extension"
    /// An operating-system or authenticator platform feature.
    case platform
}

/// Extensible, namespace-safe passkey capability identifier.
public struct PasskeyCapability: Hashable, Codable, Sendable {
    /// Capability namespace preserved across the Kotlin-to-Swift boundary.
    public let kind: PasskeyCapabilityKind
    /// Stable identifier within ``kind``.
    public let id: String

    /// Creates an identifier for a known or future capability.
    public init(kind: PasskeyCapabilityKind, id: String) {
        self.kind = kind
        self.id = id
    }

    /// WebAuthn PRF extension support.
    public static let prf = PasskeyCapability(kind: .webAuthnExtension, id: "prf")
    /// WebAuthn large-blob extension support.
    public static let largeBlob = PasskeyCapability(kind: .webAuthnExtension, id: "largeBlob")
    /// Cross-platform security-key support.
    public static let securityKey = PasskeyCapability(kind: .platform, id: "securityKey")
}

/// Immutable capability snapshot returned by ``PasskeyClient``.
public struct PasskeyCapabilities: Equatable, Sendable {
    /// Explicit support states reported by the platform.
    public let support: [PasskeyCapability: CapabilitySupport]

    /// Creates an immutable capability snapshot.
    public init(support: [PasskeyCapability: CapabilitySupport] = [:]) {
        self.support = support
    }

    /// Returns `.unknown` when the platform did not report the capability.
    public func support(for capability: PasskeyCapability) -> CapabilitySupport {
        support[capability] ?? .unknown
    }

    /// Returns `true` only for an explicitly supported capability.
    public func supports(_ capability: PasskeyCapability) -> Bool {
        support(for: capability) == .supported
    }

    /// Number of capability identifiers explicitly reported by the platform.
    public var reportedCount: Int {
        support.count
    }
}
