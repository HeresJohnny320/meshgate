import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var tunnel: TunnelController

    var body: some View {
        NavigationStack {
            Group {
                if tunnel.status.joined {
                    StatusView()
                } else {
                    JoinView()
                }
            }
            .navigationTitle("meshgate")
        }
    }
}

struct JoinView: View {
    @EnvironmentObject var tunnel: TunnelController
    @State private var token = ""
    @State private var name = UIDevice.current.name
    @State private var scanning = false
    @State private var busy = false

    var body: some View {
        Form {
            Section {
                Button("Scan QR code") { scanning = true }
                TextField("…or paste token", text: $token)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))
            } footer: {
                Text("Create a token in the web UI (Add devices → Phone) or with `sudo meshgate token`.")
            }
            Section("Device name") {
                TextField("Name", text: $name)
            }
            Section {
                Button(busy ? "Joining…" : "Join") {
                    busy = true
                    Task {
                        await tunnel.join(token: token.trimmingCharacters(in: .whitespacesAndNewlines), name: name)
                        busy = false
                    }
                }
                .disabled(busy || !token.hasPrefix("mg1."))
            }
            if let error = tunnel.error {
                Text(error).foregroundStyle(.red)
            }
        }
        .sheet(isPresented: $scanning) {
            QRScannerView { code in
                token = code
                scanning = false
            }
            .ignoresSafeArea()
        }
    }
}

struct StatusView: View {
    @EnvironmentObject var tunnel: TunnelController
    @State private var confirmLeave = false

    private var connected: Bool { tunnel.vpnStatus == .connected }

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(
                    get: { connected || tunnel.vpnStatus == .connecting },
                    set: { on in Task { await tunnel.setConnected(on) } }
                )) {
                    VStack(alignment: .leading) {
                        Text(tunnel.status.name ?? "").font(.headline)
                        Text(tunnel.status.mesh_ip ?? "").font(.system(.footnote, design: .monospaced))
                    }
                }
                Text(stateText).foregroundStyle(connected ? Color.accentColor : .secondary)
                if let e = tunnel.status.error, !e.isEmpty { Text(e).foregroundStyle(.red) }
                if let e = tunnel.error { Text(e).foregroundStyle(.red) }
            }
            Section("Nodes") {
                ForEach(tunnel.status.peers) { p in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(p.name).fontWeight(.semibold)
                            Text("\(p.kind) · \(p.mesh_ip)").font(.system(.caption, design: .monospaced))
                        }
                        Spacer()
                        VStack(alignment: .trailing) {
                            Text(p.path.isEmpty ? "–" : p.path)
                            Text(handshake(p.last_handshake)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section {
                Button("Leave mesh", role: .destructive) { confirmLeave = true }
            }
        }
        .confirmationDialog("Remove this device from the mesh?", isPresented: $confirmLeave) {
            Button("Leave", role: .destructive) { Task { await tunnel.leave() } }
        }
    }

    private var stateText: String {
        switch tunnel.vpnStatus {
        case .connected:
            if let r = tunnel.status.home_relay, !r.isEmpty { return "Connected · relay \(r)" }
            return "Connected"
        case .connecting, .reasserting: return "Connecting…"
        case .disconnecting: return "Disconnecting…"
        default: return "Disconnected"
        }
    }

    private func handshake(_ t: Int64) -> String {
        guard t > 0 else { return "no handshake" }
        let s = Int64(Date().timeIntervalSince1970) - t
        if s < 60 { return "\(s)s ago" }
        if s < 3600 { return "\(s / 60)m ago" }
        return "\(s / 3600)h ago"
    }
}
