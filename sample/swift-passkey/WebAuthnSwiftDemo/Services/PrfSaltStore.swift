import Foundation
import Security

@MainActor
final class PrfSaltStore {
    private var salts: [String: Data] = [:]

    func loadOrCreate(scope: String) throws -> Data {
        if let salt = salts[scope] {
            return salt
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw DemoFailure(kind: .platform, message: "Secure random salt generation failed.")
        }
        let salt = Data(bytes)
        salts[scope] = salt
        return salt
    }
}
