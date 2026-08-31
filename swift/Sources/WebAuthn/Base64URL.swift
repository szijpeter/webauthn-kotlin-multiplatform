import Foundation

extension Data {
    init?(base64URLString: String) {
        guard !base64URLString.contains("=") else { return nil }
        var encoded = base64URLString
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = encoded.count % 4
        guard remainder != 1 else { return nil }
        if remainder != 0 {
            encoded.append(String(repeating: "=", count: 4 - remainder))
        }
        self.init(base64Encoded: encoded)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
