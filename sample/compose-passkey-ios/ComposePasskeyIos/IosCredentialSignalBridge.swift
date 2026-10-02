import AuthenticationServices
import ComposePasskeyShared
import Foundation

final class AuthenticationServicesCredentialSignalBridge: ComposePasskeyShared.IosCredentialSignalBridge {
    var isAvailable: Bool {
        if #available(iOS 26.2, *) {
            return true
        }
        return false
    }

    func reportCurrentUserDetails(
        relyingPartyIdentifier: String,
        userHandleBase64Url: String,
        name: String,
        displayName: String,
        completion: @escaping (String?) -> Void,
    ) {
        guard let userHandle = Data(base64URLEncoded: userHandleBase64Url) else {
            completion("Invalid base64url user handle for iOS credential signal.")
            return
        }

        if #available(iOS 26.2, *) {
            let completionBox = CredentialSignalCompletionBox(completion)
            Task {
                do {
                    try await ASCredentialDataManager().reportPublicKeyCredentialUpdate(
                        relyingPartyIdentifier: relyingPartyIdentifier,
                        userHandle: userHandle,
                        newName: name,
                    )
                    await completionBox.complete(nil)
                } catch {
                    await completionBox.complete(error.localizedDescription)
                }
            }
        } else {
            completion("iOS credential signals require iOS 26.2+ ASCredentialDataManager.")
        }
    }
}

private final class CredentialSignalCompletionBox: @unchecked Sendable {
    private let completion: (String?) -> Void

    init(_ completion: @escaping (String?) -> Void) {
        self.completion = completion
    }

    @MainActor
    func complete(_ errorMessage: String?) {
        completion(errorMessage)
    }
}

private extension Data {
    init?(base64URLEncoded value: String) {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = base64.count % 4
        if padding > 0 {
            base64.append(String(repeating: "=", count: 4 - padding))
        }
        self.init(base64Encoded: base64)
    }
}
