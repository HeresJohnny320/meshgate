import Foundation
import Meshcore
import NetworkExtension

struct PeerStatus: Decodable, Identifiable {
    let id: String
    let name: String
    let kind: String
    let mesh_ip: String
    let path: String
    let last_handshake: Int64
}

struct MeshStatus: Decodable {
    var joined = false
    var running = false
    var name: String?
    var mesh_ip: String?
    var home_relay: String?
    var error: String?
    var peers: [PeerStatus] = []
}

/// Joins the mesh (in the app process) and controls the VPN configuration.
/// Live status comes from the tunnel extension via provider messages.
@MainActor
final class TunnelController: ObservableObject {
    @Published var status = MeshStatus()
    @Published var vpnStatus: NEVPNStatus = .invalid
    @Published var error: String?

    private var manager: NETunnelProviderManager?
    private var timer: Timer?
    private let engine: MeshcoreEngine?

    init() {
        var err: NSError?
        engine = MeshcoreNewEngine(Shared.stateDir, AppPlatform(), &err)
        refreshLocal()
        Task { await loadManager() }
        timer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
        NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.vpnStatus = self?.manager?.connection.status ?? .invalid }
        }
    }

    var joined: Bool { engine?.isJoined() ?? false }

    func join(token: String, name: String) async {
        error = nil
        guard let engine else { return }
        do {
            try await Task.detached { try engine.join(token, deviceName: name) }.value
            refreshLocal()
        } catch {
            self.error = error.localizedDescription
        }
    }

    func setConnected(_ on: Bool) async {
        do {
            let m = try await ensureManager()
            // On-demand keeps the VPN up across network changes; turn it off
            // when the user disconnects or iOS would reconnect immediately.
            if m.isOnDemandEnabled != on {
                m.isOnDemandEnabled = on
                try await m.saveToPreferences()
            }
            if on {
                try m.connection.startVPNTunnel()
            } else {
                m.connection.stopVPNTunnel()
            }
        } catch {
            self.error = error.localizedDescription
        }
    }

    func leave() async {
        await setConnected(false)
        try? await manager?.removeFromPreferences()
        manager = nil
        try? engine?.leave()
        refreshLocal()
    }

    private func refreshLocal() {
        if let json = engine?.statusJSON().data(using: .utf8),
           let s = try? JSONDecoder().decode(MeshStatus.self, from: json) {
            status = s
        }
    }

    private func poll() {
        guard let session = manager?.connection as? NETunnelProviderSession, vpnStatus == .connected else {
            refreshLocal()
            return
        }
        try? session.sendProviderMessage(Data("status".utf8)) { data in
            guard let data, let s = try? JSONDecoder().decode(MeshStatus.self, from: data) else { return }
            Task { @MainActor in self.status = s }
        }
    }

    private func loadManager() async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        manager = all.first
        vpnStatus = manager?.connection.status ?? .invalid
    }

    private func ensureManager() async throws -> NETunnelProviderManager {
        if let manager { return manager }
        let m = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Shared.tunnelBundleID
        proto.serverAddress = "meshgate"
        m.protocolConfiguration = proto
        m.localizedDescription = "meshgate"
        m.isEnabled = true
        // Reconnect automatically whenever the device has a network.
        m.onDemandRules = [NEOnDemandRuleConnect()]
        try await m.saveToPreferences()
        try await m.loadFromPreferences()
        manager = m
        return m
    }
}

/// The app process only joins; it never opens a tunnel.
final class AppPlatform: NSObject, MeshcorePlatformProtocol {
    func protect(_ fd: Int32) -> Bool { true }
    func configureTunnel(_ settingsJSON: String?) -> Int32 { -1 }
    func localAddresses() -> String { "" }
    func log(_ msg: String?) { NSLog("meshgate: %@", msg ?? "") }
}
