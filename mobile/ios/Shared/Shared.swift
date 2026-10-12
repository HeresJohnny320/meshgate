import Foundation

enum Shared {
    static let appGroup = "group.dev.meshgate"
    static let tunnelBundleID = "dev.meshgate.app.tunnel"

    /// Engine state lives in the App Group so the app (which joins) and the
    /// tunnel extension (which runs the VPN) share one identity.
    static var stateDir: String {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)!
            .appendingPathComponent("mesh").path
    }
}
