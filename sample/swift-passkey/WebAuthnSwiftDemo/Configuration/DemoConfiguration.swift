import Foundation

struct DemoConfiguration: Equatable, Sendable {
    let endpoint: URL
    let rpID: String
    let origin: String
    let userHandle: String
    let userName: String

    static func load(from bundle: Bundle = .main) -> DemoConfiguration {
        let endpointValue = bundle.value(for: "WEBAUTHN_DEMO_ENDPOINT") ?? "http://127.0.0.1:8080"
        let endpoint = URL(string: endpointValue) ?? URL(string: "http://127.0.0.1:8080")!
        let configuredRPID = bundle.value(for: "WEBAUTHN_DEMO_RP_ID") ?? "localhost"
        let rpID = resolvedRPID(configuredRPID, endpoint: endpoint)
        return DemoConfiguration(
            endpoint: endpoint,
            rpID: rpID,
            origin: resolvedOrigin(bundle.value(for: "WEBAUTHN_DEMO_ORIGIN"), rpID: rpID),
            userHandle: bundle.value(for: "WEBAUTHN_DEMO_USER_ID") ?? "42",
            userName: bundle.value(for: "WEBAUTHN_DEMO_USER_NAME") ?? "Zaphod Beeblebrox"
        )
    }

    private static func resolvedRPID(_ configured: String, endpoint: URL) -> String {
        let value = configured.trimmingCharacters(in: .whitespacesAndNewlines)
        let host = endpoint.host?.trimmingCharacters(in: .whitespacesAndNewlines)
        if (value.isEmpty || value == "localhost"), let host, host != "127.0.0.1", host != "localhost" {
            return host
        }
        return value.isEmpty ? (host ?? "localhost") : value
    }

    private static func resolvedOrigin(_ configured: String?, rpID: String) -> String {
        let value = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !value.isEmpty, value != "https://localhost", value != "http://localhost" {
            return value
        }
        return "https://\(rpID)"
    }
}

private extension Bundle {
    func value(for key: String) -> String? {
        (object(forInfoDictionaryKey: key) as? String)?
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .nilIfEmpty
    }
}

private extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
