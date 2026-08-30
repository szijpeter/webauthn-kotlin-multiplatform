import XCTest

@MainActor
final class WebAuthnSwiftDemoUITests: XCTestCase {
    func testLaunches() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["Passkey Lab"].firstMatch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.buttons["register-button"].exists)
        XCTAssertTrue(app.buttons["sign-in-button"].exists)
    }
}
