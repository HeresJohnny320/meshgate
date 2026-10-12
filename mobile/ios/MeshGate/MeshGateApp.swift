import SwiftUI

@main
struct MeshGateApp: App {
    @StateObject private var tunnel = TunnelController()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnel)
        }
    }
}
