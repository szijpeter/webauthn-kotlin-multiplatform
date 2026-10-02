import Foundation
import UIKit
@preconcurrency import WebAuthnBridge

@MainActor
final class KmpPasskeyCoreBridge: PasskeyCoreBridge {
    private let bridge = SwiftPasskeyBridge()

    func createCredential(
        optionsJSON: String,
        presentationAnchor: UIWindow
    ) async throws -> BridgePasskeyResult {
        bridge.updatePresentationAnchor(window: presentationAnchor)
        return try await translateCancellation {
            let result = try await bridge.createCredential(requestJson: optionsJSON)
            return BridgePasskeyResult(
                responseJSON: result.responseJson,
                errorCode: result.errorCode,
                errorMessage: result.errorMessage
            )
        }
    }

    func getAssertion(
        optionsJSON: String,
        presentationAnchor: UIWindow
    ) async throws -> BridgePasskeyResult {
        bridge.updatePresentationAnchor(window: presentationAnchor)
        return try await translateCancellation {
            let result = try await bridge.getAssertion(requestJson: optionsJSON)
            return BridgePasskeyResult(
                responseJSON: result.responseJson,
                errorCode: result.errorCode,
                errorMessage: result.errorMessage
            )
        }
    }

    func capabilities() async throws -> PasskeyCapabilities {
        let result = try await translateCancellation {
            try await bridge.capabilities()
        }
        return try Self.decodeCapabilities(
            valuesJSON: result.valuesJson,
            reportedCount: Int(result.reportedCount)
        )
    }

    func authenticateWithPrf(
        optionsJSON: String,
        firstSalt: String,
        secondSalt: String?,
        presentationAnchor: UIWindow
    ) async throws -> BridgePrfAuthenticationResult {
        bridge.updatePresentationAnchor(window: presentationAnchor)
        return try await translateCancellation {
            let result = try await bridge.authenticateWithPrf(
                requestJson: optionsJSON,
                firstSaltBase64Url: firstSalt,
                secondSaltBase64Url: secondSalt
            )
            return BridgePrfAuthenticationResult(
                responseJSON: result.responseJson,
                firstResult: result.firstResultBase64Url,
                secondResult: result.secondResultBase64Url,
                errorCode: result.errorCode,
                errorMessage: result.errorMessage
            )
        }
    }

    static func decodeCapabilities(valuesJSON: String, reportedCount: Int) throws -> PasskeyCapabilities {
        guard let data = valuesJSON.data(using: .utf8),
              let records = try? JSONDecoder().decode([BridgeCapabilityRecord].self, from: data),
              records.count == reportedCount
        else {
            throw PasskeyClientError.bridgeContract(message: "Capability data from the bridge is invalid.")
        }
        var support: [PasskeyCapability: CapabilitySupport] = [:]
        for record in records {
            let capability = PasskeyCapability(kind: record.kind, id: record.id)
            guard support.updateValue(record.support, forKey: capability) == nil else {
                throw PasskeyClientError.bridgeContract(message: "Capability data from the bridge is duplicated.")
            }
        }
        return PasskeyCapabilities(support: support)
    }
}

private struct BridgeCapabilityRecord: Decodable {
    let kind: PasskeyCapabilityKind
    let id: String
    let support: CapabilitySupport
}

@MainActor
private func translateCancellation<T>(_ operation: @MainActor () async throws -> T) async throws -> T {
    do {
        return try await operation()
    } catch is CancellationError {
        throw CancellationError()
    } catch {
        if Task.isCancelled {
            throw CancellationError()
        }
        throw PasskeyClientError.bridgeContract(message: "The internal passkey bridge failed.")
    }
}
