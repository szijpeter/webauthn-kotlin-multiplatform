import Foundation

@MainActor
protocol PasskeyBackend {
    func startRegistration(config: DemoConfiguration) async throws -> Data
    func finishRegistration(responseJSON: Data) async throws -> FinishOutcome
    func startAuthentication(config: DemoConfiguration, prfSalt: Data?) async throws -> Data
    func finishAuthentication(responseJSON: Data) async throws -> FinishOutcome
}

@MainActor
final class URLSessionPasskeyBackend: PasskeyBackend {
    private let endpoint: URL
    private let session: URLSession

    init(endpoint: URL, session: URLSession = .shared) {
        self.endpoint = endpoint
        self.session = session
    }

    func startRegistration(config: DemoConfiguration) async throws -> Data {
        try await post(path: "/webauthn/registration/start", body: DemoRequests.registrationStart(config))
    }

    func finishRegistration(responseJSON: Data) async throws -> FinishOutcome {
        try await finish(
            path: "/webauthn/registration/finish",
            responseJSON: responseJSON
        )
    }

    func startAuthentication(config: DemoConfiguration, prfSalt: Data?) async throws -> Data {
        try await post(
            path: "/webauthn/authentication/start",
            body: DemoRequests.authenticationStart(config, prfSalt: prfSalt)
        )
    }

    func finishAuthentication(responseJSON: Data) async throws -> FinishOutcome {
        try await finish(
            path: "/webauthn/authentication/finish",
            responseJSON: responseJSON
        )
    }

    private func finish(path: String, responseJSON: Data) async throws -> FinishOutcome {
        do {
            let data = try await post(path: path, body: DemoRequests.finish(responseJSON: responseJSON))
            let payload = try JSONDecoder().decode(FinishResponse.self, from: data)
            return payload.status == "ok"
                ? .verified
                : .rejected("Server returned status '\(payload.status)'.")
        } catch let error as BackendError {
            if case let .httpStatus(status, message) = error, (400..<500).contains(status) {
                return .rejected(message ?? "The backend rejected the credential response.")
            }
            throw error
        }
    }

    private func post(path: String, body: Data) async throws -> Data {
        let url = endpoint.appending(path: path.trimmingCharacters(in: CharacterSet(charactersIn: "/")))
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else {
            throw BackendError.invalidResponse
        }
        guard (200..<300).contains(response.statusCode) else {
            let message = (try? JSONDecoder().decode(ServerErrorResponse.self, from: data))?
                .errors?
                .filter { !$0.isEmpty }
                .joined(separator: "; ")
            throw BackendError.httpStatus(response.statusCode, message)
        }
        return data
    }
}

enum BackendError: LocalizedError, Equatable {
    case invalidResponse
    case httpStatus(Int, String?)

    var errorDescription: String? {
        switch self {
        case .invalidResponse:
            "The backend returned an invalid HTTP response."
        case let .httpStatus(status, message):
            message ?? "The backend returned HTTP \(status)."
        }
    }
}

private struct FinishResponse: Decodable {
    let status: String
}

private struct ServerErrorResponse: Decodable {
    let errors: [String]?
}
