import XCTest

@MainActor
final class ShowcaseUITests: XCTestCase {
    func testLaunchesAndOpensLogs() {
        let app = XCUIApplication()
        defer { captureFailure(app) }
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "Passkey Lab").firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(button(app, "register-button", "Register").isEnabled)
        XCTAssertTrue(button(app, "sign-in-button", "Sign In").isEnabled)
        button(app, "debug-logs-button", "Debug logs").tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 5))
        app.buttons["Done"].tap()
        XCTAssertTrue(button(app, "register-button", "Register").exists)
    }

    func testBusyAndTerminalStatesKeepCorrectActionsAvailable() {
        let app = gallery("busy")
        defer { captureFailure(app) }
        XCTAssertFalse(button(app, "register-button", "Register").isEnabled)
        XCTAssertFalse(button(app, "sign-in-button", "Sign In").isEnabled)
        XCTAssertTrue(button(app, "debug-logs-button", "Debug logs").isEnabled)
        for scenario in ["cancelled", "error", "rejected"] {
            app.terminate()
            app.launchArguments = ["--sample-gallery", scenario]
            app.launch()
            XCTAssertTrue(button(app, "sign-in-button", "Sign In").waitForExistence(timeout: 5))
            XCTAssertTrue(button(app, "sign-in-button", "Sign In").isEnabled)
        }
    }

    func testPRFControlsFollowSessionAndCiphertext() {
        let app = gallery("unsupported")
        defer { captureFailure(app) }
        XCTAssertFalse(button(app, "prf-sign-in-button", "Sign In + PRF").isEnabled)
        XCTAssertFalse(button(app, "encrypt-button", "Encrypt").isEnabled)
        XCTAssertFalse(button(app, "decrypt-button", "Decrypt").isEnabled)
        app.terminate()
        app.launchArguments = ["--sample-gallery", "session"]
        app.launch()
        XCTAssertTrue(button(app, "encrypt-button", "Encrypt").waitForExistence(timeout: 5))
        XCTAssertTrue(button(app, "encrypt-button", "Encrypt").isEnabled)
        XCTAssertFalse(button(app, "decrypt-button", "Decrypt").isEnabled)
        app.terminate()
        app.launchArguments = ["--sample-gallery", "encrypted"]
        app.launch()
        XCTAssertTrue(button(app, "decrypt-button", "Decrypt").waitForExistence(timeout: 5))
        XCTAssertTrue(button(app, "decrypt-button", "Decrypt").isEnabled)
    }

    func testLargeTypeAllowsScrollingToConfigurationAndActions() {
        let app = XCUIApplication()
        defer { captureFailure(app) }
        app.launchArguments = ["--sample-gallery", "auth", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "Passkey Lab").firstMatch.waitForExistence(timeout: 5))
        for _ in 0..<8 where !button(app, "sign-in-button", "Sign In").isHittable { app.swipeUp() }
        XCTAssertTrue(button(app, "sign-in-button", "Sign In").isHittable)
        for _ in 0..<8 where !button(app, "configuration-disclosure", "Configuration").isHittable { app.swipeUp() }
        let configuration = button(app, "configuration-disclosure", "Configuration")
        waitForStableFrame(configuration)
        configuration.tap()
        let relyingParty = app.staticTexts["Relying party"].firstMatch
        for _ in 0..<8 where !relyingParty.isHittable { app.swipeUp() }
        XCTAssertTrue(relyingParty.isHittable)
    }

    func testLongAndBidirectionalTextKeepSessionActionsReachable() {
        let app = XCUIApplication()
        defer { captureFailure(app) }
        for scenario in ["long-text", "rtl"] {
            app.terminate()
            app.launchArguments = ["--sample-gallery", scenario]
            app.launch()
            let text = app.staticTexts.matching(NSPredicate(format: "label CONTAINS %@", "שלום")).firstMatch
            XCTAssertTrue(text.waitForExistence(timeout: 5))
            XCTAssertTrue(text.label.contains("مرحبا"))
            let signOut = button(app, "sign-out-button", "Sign Out")
            for _ in 0..<8 where !signOut.isHittable { app.swipeUp() }
            XCTAssertTrue(signOut.isHittable)
            XCTAssertTrue(signOut.isEnabled)
        }
    }

    private func waitForStableFrame(_ element: XCUIElement) {
        // Compose scrolling can continue after XCTest reports the app idle.
        // A tap during deceleration stops the scroll instead of opening the control.
        var previous: CGRect?
        var stableSamples = 0
        let settled = NSPredicate { _, _ in
            let frame = element.frame
            stableSamples = frame == previous ? stableSamples + 1 : 0
            previous = frame
            return element.isHittable && stableSamples >= 2
        }
        XCTAssertEqual(
            XCTWaiter.wait(for: [XCTNSPredicateExpectation(predicate: settled, object: nil)], timeout: 8),
            .completed,
            "Control did not stop moving after scrolling"
        )
    }

    private func button(_ app: XCUIApplication, _ identifier: String, _ label: String) -> XCUIElement {
        app.buttons.matching(NSPredicate(format: "identifier == %@ OR label == %@", identifier, label)).firstMatch
    }

    private func captureFailure(_ app: XCUIApplication) {
        guard (testRun?.failureCount ?? 0) > 0 else { return }
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = "showcase-failure"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func gallery(_ scenario: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--sample-gallery", scenario]
        app.launch()
        XCTAssertTrue(app.descendants(matching: .any).matching(identifier: "Passkey Lab").firstMatch.waitForExistence(timeout: 5))
        return app
    }
}
