import XCTest

@MainActor
final class WebAuthnSwiftDemoUITests: XCTestCase {
    func testLaunchesAndOpensLogs() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["Passkey Lab"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["register-button"].isEnabled)
        XCTAssertTrue(app.buttons["sign-in-button"].isEnabled)
        app.buttons["debug-logs-button"].tap()
        XCTAssertTrue(app.buttons["Done"].waitForExistence(timeout: 5))
        app.buttons["Done"].tap()
        XCTAssertTrue(app.buttons["register-button"].exists)
    }

    func testBusyAndTerminalStatesKeepCorrectActionsAvailable() {
        let app = gallery("busy")
        XCTAssertFalse(app.buttons["register-button"].isEnabled)
        XCTAssertFalse(app.buttons["sign-in-button"].isEnabled)
        XCTAssertTrue(app.buttons["debug-logs-button"].isEnabled)
        for scenario in ["cancelled", "error", "rejected"] {
            app.terminate()
            app.launchArguments = ["--sample-gallery", scenario]
            app.launch()
            XCTAssertTrue(app.buttons["sign-in-button"].waitForExistence(timeout: 5))
            XCTAssertTrue(app.buttons["sign-in-button"].isEnabled)
        }
    }

    func testPRFControlsFollowSessionAndCiphertext() {
        let app = gallery("unsupported")
        XCTAssertFalse(app.buttons["prf-sign-in-button"].isEnabled)
        XCTAssertFalse(app.buttons["encrypt-button"].isEnabled)
        XCTAssertFalse(app.buttons["decrypt-button"].isEnabled)
        app.terminate()
        app.launchArguments = ["--sample-gallery", "session"]
        app.launch()
        XCTAssertTrue(app.buttons["encrypt-button"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["encrypt-button"].isEnabled)
        XCTAssertFalse(app.buttons["decrypt-button"].isEnabled)
        app.terminate()
        app.launchArguments = ["--sample-gallery", "encrypted"]
        app.launch()
        XCTAssertTrue(app.buttons["decrypt-button"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["decrypt-button"].isEnabled)
    }

    func testLargeTypeAllowsScrollingToConfigurationAndActions() {
        let app = XCUIApplication()
        app.launchArguments = ["--sample-gallery", "auth", "-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        app.launch()
        for _ in 0..<8 where !app.buttons["sign-in-button"].isHittable { app.swipeUp() }
        XCTAssertTrue(app.buttons["sign-in-button"].isHittable)
        for _ in 0..<8 where !app.buttons["configuration-disclosure"].isHittable { app.swipeUp() }
        app.buttons["configuration-disclosure"].tap()
        XCTAssertTrue(app.staticTexts["Relying party"].exists)
    }

    private func gallery(_ scenario: String) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--sample-gallery", scenario]
        app.launch()
        XCTAssertTrue(app.staticTexts["Passkey Lab"].firstMatch.waitForExistence(timeout: 5))
        return app
    }
}
