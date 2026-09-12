import ComposePasskeyShared
import UIKit

@main
final class ComposePasskeyIosApp: UIResponder, UIApplicationDelegate {
    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions,
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(
            name: "Default Configuration",
            sessionRole: connectingSceneSession.role,
        )
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?

    func scene(
        _ scene: UIScene,
        willConnectTo session: UISceneSession,
        options connectionOptions: UIScene.ConnectionOptions,
    ) {
        guard let windowScene = scene as? UIWindowScene else {
            return
        }

        let window = UIWindow(windowScene: windowScene)
        #if DEBUG
        let arguments = ProcessInfo.processInfo.arguments
        if let index = arguments.firstIndex(of: "--sample-gallery"), arguments.indices.contains(index + 1) {
            window.rootViewController = MainViewControllerKt.GalleryViewController(scenario: arguments[index + 1])
        } else {
            window.rootViewController = MainViewControllerKt.MainViewController()
        }
        #else
        window.rootViewController = MainViewControllerKt.MainViewController()
        #endif
        self.window = window
        window.makeKeyAndVisible()
    }
}
