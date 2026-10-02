import Combine
import Foundation
import WebAuthn

@MainActor
final class DemoViewModel: ObservableObject {
    @Published private(set) var route: DemoRoute = .authentication
    @Published private(set) var ceremonyState: CeremonyState = .idle
    @Published private(set) var capabilities = PasskeyCapabilities()
    @Published private(set) var prfSessionState: PrfSessionState = .noSession
    @Published private(set) var decryptedText: String?
    @Published private(set) var prfStatus = "Run Sign In + PRF to derive an in-memory AES session key."
    @Published private(set) var prfBusy = false
    @Published var plaintext = "The answer is 42"

    let config: DemoConfiguration
    let logs: DebugLogStore

    private let passkeys: any PasskeyServing
    private let backend: any PasskeyBackend
    private let saltStore: PrfSaltStore
    private var prfSession: (any DemoCryptoSession)?
    private var ciphertext: DemoPrfCiphertext?
    private var activePrfOperation: UUID?

    var supportsPRF: Bool { capabilities.supports(.prf) }
    var ceremonyActionsEnabled: Bool { ceremonyState.actionsEnabled }

    init(
        config: DemoConfiguration,
        passkeys: any PasskeyServing,
        backend: any PasskeyBackend,
        logs: DebugLogStore = DebugLogStore(),
        saltStore: PrfSaltStore = PrfSaltStore(),
        loadCapabilitiesImmediately: Bool = true
    ) {
        self.config = config
        self.passkeys = passkeys
        self.backend = backend
        self.logs = logs
        self.saltStore = saltStore

        let endpointHost = config.endpoint.host ?? "unavailable"
        logs.info(
            "config",
            "endpointHost=\(endpointHost) rpId=\(config.rpID) origin=\(config.origin)"
        )
        if loadCapabilitiesImmediately {
            Task { await loadCapabilities() }
        }
    }

    func register() async {
        guard begin(.register) else { return }
        do {
            let options = try await backend.startRegistration(config: config)
            transition(.register, to: .platformPrompt)
            let response = try await passkeys.createCredential(optionsJSON: options)
            transition(.register, to: .finishing)
            switch try await backend.finishRegistration(responseJSON: response) {
            case .verified:
                succeed(.register)
            case let .rejected(message):
                fail(.register, DemoFailure(kind: .rejected, message: message))
            }
        } catch is CancellationError {
            ceremonyState = .idle
        } catch {
            failCurrent(.register, error: error)
        }
    }

    func signIn() async {
        guard begin(.signIn) else { return }
        do {
            let options = try await backend.startAuthentication(config: config, prfSalt: nil)
            transition(.signIn, to: .platformPrompt)
            let response = try await passkeys.getAssertion(optionsJSON: options)
            transition(.signIn, to: .finishing)
            switch try await backend.finishAuthentication(responseJSON: response) {
            case .verified:
                succeed(.signIn)
                route = .main
            case let .rejected(message):
                fail(.signIn, DemoFailure(kind: .rejected, message: message))
            }
        } catch is CancellationError {
            ceremonyState = .idle
        } catch {
            failCurrent(.signIn, error: error)
        }
    }

    func loadCapabilities() async {
        logs.info("capabilities", "Loading capability hints")
        do {
            capabilities = try await passkeys.capabilities()
            logs.info(
                "capabilities",
                "loaded PRF=\(supportsPRF) reported=\(capabilities.reportedCount)"
            )
        } catch {
            capabilities = PasskeyCapabilities()
            logs.error("capabilities", "load failed: \(safeMessage(error))")
        }
    }

    func signInWithPRF() async {
        guard !prfBusy else { return }
        guard supportsPRF else {
            applyPrfFailure("This device does not report PRF support.")
            return
        }
        let operationID = UUID()
        activePrfOperation = operationID
        prfBusy = true
        logs.info("prf", "Sign In + PRF tapped")
        defer {
            if activePrfOperation == operationID {
                activePrfOperation = nil
                prfBusy = false
            }
        }

        do {
            let saltScope = "\(config.rpID):\(config.userHandle)"
            let salt = try saltStore.loadOrCreate(scope: saltScope)
            let options = try await backend.startAuthentication(config: config, prfSalt: salt)
            let authenticated = try await passkeys.authenticateWithPrf(
                optionsJSON: options,
                firstSalt: salt
            )
            guard activePrfOperation == operationID else {
                await authenticated.session.clear()
                return
            }
            do {
                switch try await backend.finishAuthentication(responseJSON: authenticated.responseJSON) {
                case .verified:
                    guard activePrfOperation == operationID else {
                        await authenticated.session.clear()
                        return
                    }
                    guard await replaceSession(with: authenticated.session, operationID: operationID) else {
                        return
                    }
                    prfStatus = "PRF session ready. Caller-owned salt is available."
                    logs.info("prf", "PRF session ready after backend verification.")
                case let .rejected(message):
                    await authenticated.session.clear()
                    applyPrfFailure("PRF sign-in verification rejected: \(message)")
                }
            } catch {
                await authenticated.session.clear()
                guard activePrfOperation == operationID else { return }
                applyPrfFailure("PRF sign-in finish failed: \(safeMessage(error))")
            }
        } catch is CancellationError {
            guard activePrfOperation == operationID else { return }
            prfStatus = "PRF sign-in cancelled."
            logs.warning("prf", prfStatus)
        } catch {
            guard activePrfOperation == operationID else { return }
            applyPrfFailure("PRF sign-in failed: \(safeMessage(error))")
        }
    }

    func encrypt() async {
        guard !prfBusy else { return }
        guard let prfSession else {
            applyPrfFailure("No PRF session. Run Sign In + PRF first.")
            return
        }
        guard !plaintext.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            applyPrfFailure("Enter plaintext before encryption.")
            return
        }
        let operationID = UUID()
        activePrfOperation = operationID
        prfBusy = true
        defer {
            if activePrfOperation == operationID {
                activePrfOperation = nil
                prfBusy = false
            }
        }
        do {
            let value = try await prfSession.encrypt(
                Data(plaintext.utf8),
                associatedData: Data("samples-swift-passkey".utf8)
            )
            guard activePrfOperation == operationID else { return }
            ciphertext = value
            decryptedText = nil
            prfSessionState = .ciphertextReady
            prfStatus = "Encrypted \(plaintext.count) chars to \(value.ciphertext.count) bytes."
            logs.info("prf", prfStatus)
        } catch {
            guard activePrfOperation == operationID else { return }
            applyPrfFailure("Encrypt failed: \(safeMessage(error))")
        }
    }

    func decrypt() async {
        guard !prfBusy else { return }
        guard let prfSession else {
            applyPrfFailure("No PRF session. Run Sign In + PRF first.")
            return
        }
        guard let ciphertext else {
            applyPrfFailure("No ciphertext. Encrypt text first.")
            return
        }
        let operationID = UUID()
        activePrfOperation = operationID
        prfBusy = true
        defer {
            if activePrfOperation == operationID {
                activePrfOperation = nil
                prfBusy = false
            }
        }
        do {
            let plaintext = try await prfSession.decrypt(ciphertext)
            guard activePrfOperation == operationID else { return }
            guard let decoded = String(data: plaintext, encoding: .utf8) else {
                throw DemoFailure(kind: .internalContract, message: "Decrypted bytes are not UTF-8.")
            }
            decryptedText = decoded
            prfStatus = "Decrypt succeeded."
            logs.info("prf", prfStatus)
        } catch {
            guard activePrfOperation == operationID else { return }
            applyPrfFailure("Decrypt failed: \(safeMessage(error))")
        }
    }

    func clearPrfSession() async {
        activePrfOperation = nil
        prfBusy = false
        if let prfSession {
            await prfSession.clear()
        }
        prfSession = nil
        ciphertext = nil
        decryptedText = nil
        prfSessionState = .noSession
        prfStatus = "PRF session key cleared from memory."
        logs.info("session", prfStatus)
    }

    func signOut() async {
        await clearPrfSession()
        ceremonyState = .idle
        route = .authentication
        logs.info("session", "Signed out")
    }

    private func begin(_ action: DemoAction) -> Bool {
        guard ceremonyState.actionsEnabled else {
            logs.warning(
                "ceremony",
                "\(action.rawValue) ignored because another ceremony is already in progress."
            )
            return false
        }
        transition(action, to: .starting)
        return true
    }

    private func transition(_ action: DemoAction, to phase: CeremonyPhase) {
        ceremonyState = .inProgress(action: action, phase: phase)
        logs.info("ceremony", "\(action.rawValue) \(phase.rawValue)")
    }

    private func succeed(_ action: DemoAction) {
        ceremonyState = .success(action: action)
        logs.info("ceremony", "\(action.rawValue) success")
    }

    private func failCurrent(_ action: DemoAction, error: Error) {
        let failure: DemoFailure
        if case .inProgress(_, .platformPrompt) = ceremonyState {
            failure = .platform(error)
        } else if let known = error as? DemoFailure {
            failure = known
        } else {
            failure = DemoFailure(kind: .backend, message: safeMessage(error))
        }
        fail(action, failure)
    }

    private func fail(_ action: DemoAction, _ failure: DemoFailure) {
        ceremonyState = .failure(action: action, failure: failure)
        let message = "\(action.rawValue) failed [\(failure.kind.label)] \(failure.message)"
        if failure.kind == .userCancelled {
            logs.warning("ceremony", message)
        } else {
            logs.error("ceremony", message)
        }
    }

    private func replaceSession(
        with next: any DemoCryptoSession,
        operationID: UUID
    ) async -> Bool {
        if let previous = prfSession, previous !== next {
            await previous.clear()
        }
        guard activePrfOperation == operationID else {
            await next.clear()
            return false
        }
        prfSession = next
        ciphertext = nil
        decryptedText = nil
        prfSessionState = .sessionReady
        return true
    }

    private func applyPrfFailure(_ message: String) {
        prfStatus = message
        logs.warning("prf", message)
    }

    private func safeMessage(_ error: Error) -> String {
        let message = error.localizedDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        return message.isEmpty ? "unknown error" : message
    }
}
