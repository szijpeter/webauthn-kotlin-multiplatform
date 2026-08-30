import Foundation

enum DemoRequests {
    static func registrationStart(_ config: DemoConfiguration) throws -> Data {
        try encoder.encode(
            RegistrationStartRequest(
                rpId: config.rpID,
                rpName: "WebAuthn Kotlin MPP Sample Backend",
                origin: config.origin,
                userName: config.userName,
                userDisplayName: config.userName,
                userHandle: encodedUserHandle(config.userHandle),
                residentKey: "required"
            )
        )
    }

    static func authenticationStart(_ config: DemoConfiguration, prfSalt: Data? = nil) throws -> Data {
        try encoder.encode(
            AuthenticationStartRequest(
                rpId: config.rpID,
                origin: config.origin,
                userName: nil,
                extensions: prfSalt.map {
                    Extensions(prf: PrfInput(eval: PrfValues(first: $0.base64URLEncodedString())))
                }
            )
        )
    }

    static func finish(responseJSON: Data) throws -> Data {
        let response = try JSONSerialization.jsonObject(with: responseJSON)
        guard JSONSerialization.isValidJSONObject(response) else {
            throw DemoFailure(kind: .internalContract, message: "Passkey response JSON is invalid.")
        }
        return try JSONSerialization.data(withJSONObject: ["response": response], options: [.sortedKeys])
    }

    private static func encodedUserHandle(_ configured: String) -> String {
        let candidate = configured.trimmingCharacters(in: .whitespacesAndNewlines)
        let rawValue = candidate.isEmpty ? "demo-user" : candidate
        return Data(rawValue.utf8).base64URLEncodedString()
    }

    private static let encoder = JSONEncoder()
}

private struct RegistrationStartRequest: Encodable {
    let rpId: String
    let rpName: String
    let origin: String
    let userName: String
    let userDisplayName: String
    let userHandle: String
    let residentKey: String
}

private struct AuthenticationStartRequest: Encodable {
    let rpId: String
    let origin: String
    let userName: String?
    let extensions: Extensions?
}

private struct Extensions: Encodable {
    let prf: PrfInput
}

private struct PrfInput: Encodable {
    let eval: PrfValues
}

private struct PrfValues: Encodable {
    let first: String
}

extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
