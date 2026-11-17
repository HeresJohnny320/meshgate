import Meshcore
import Network
import NetworkExtension
import os

/// Runs the Go engine inside the Packet Tunnel extension. The engine decides
/// addresses and routes; this class applies them as tunnel settings and
/// reports network changes (Wi-Fi <-> cellular).
final class PacketTunnelProvider: NEPacketTunnelProvider, MeshcorePlatformProtocol {
    private var engine: MeshcoreEngine?
    private let monitor = NWPathMonitor()
    private let logger = Logger(subsystem: "dev.meshgate", category: "tunnel")

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        var err: NSError?
        guard let engine = MeshcoreNewEngine(Shared.stateDir, self, &err) else {
            completionHandler(err ?? NSError(domain: "meshgate", code: 1))
            return
        }
        self.engine = engine
        DispatchQueue.global().async {
            do {
                try engine.start()
            } catch {
                completionHandler(error)
                return
            }
            self.monitor.pathUpdateHandler = { [weak self] _ in self?.engine?.networkChanged() }
            self.monitor.start(queue: DispatchQueue(label: "meshgate.path"))
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        monitor.cancel()
        engine?.stop()
        engine = nil
        completionHandler()
    }

    /// The app asks for status by sending any message; we answer with JSON.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        completionHandler?(engine?.statusJSON().data(using: .utf8))
    }

    // MARK: MeshcorePlatformProtocol

    func protect(_ fd: Int32) -> Bool {
        // Sockets opened by the extension itself never use its own tunnel.
        true
    }

    func configureTunnel(_ settingsJSON: String?) -> Int32 {
        guard let data = settingsJSON?.data(using: .utf8),
              let s = try? JSONDecoder().decode(TunnelSettings.self, from: data)
        else { return -1 }

        // The tunnel's remote address is informational for packet tunnels.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let v4 = NEIPv4Settings(addresses: [s.address], subnetMasks: [mask(s.prefix)])
        v4.includedRoutes = s.routes.compactMap { cidr in
            let parts = cidr.split(separator: "/")
            guard parts.count == 2, let bits = Int(parts[1]) else { return nil }
            return NEIPv4Route(destinationAddress: String(parts[0]), subnetMask: mask(bits))
        }
        settings.ipv4Settings = v4
        settings.mtu = NSNumber(value: s.mtu)

        let done = DispatchSemaphore(value: 0)
        var failed = false
        setTunnelNetworkSettings(settings) { error in
            if let error {
                self.logger.error("tunnel settings: \(error.localizedDescription, privacy: .public)")
                failed = true
            }
            done.signal()
        }
        done.wait()
        if failed { return -1 }
        return utunDescriptor() ?? -1
    }

    func localAddresses() -> String {
        var out: [String] = []
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return "" }
        defer { freeifaddrs(ifaddr) }
        for ptr in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: ptr.pointee.ifa_name)
            guard let sa = ptr.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET),
                  !name.hasPrefix("utun"), !name.hasPrefix("lo") else { continue }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                var addr = sin.pointee.sin_addr
                inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
            }
            out.append(String(cString: buf))
        }
        return out.joined(separator: ",")
    }

    func log(_ msg: String?) {
        logger.info("\(msg ?? "", privacy: .public)")
    }

    // MARK: helpers

    private struct TunnelSettings: Decodable {
        let address: String
        let prefix: Int
        let routes: [String]
        let mtu: Int
    }

    private func mask(_ bits: Int) -> String {
        let m: UInt32 = bits == 0 ? 0 : ~UInt32(0) << (32 - UInt32(bits))
        return "\(m >> 24 & 255).\(m >> 16 & 255).\(m >> 8 & 255).\(m & 255)"
    }

    /// Finds the utun socket created for this tunnel.
    private func utunDescriptor() -> Int32? {
        var info = ctl_info()
        withUnsafeMutablePointer(to: &info.ctl_name) {
            $0.withMemoryRebound(to: CChar.self, capacity: MemoryLayout.size(ofValue: $0.pointee)) {
                _ = strcpy($0, "com.apple.net.utun_control")
            }
        }
        for fd: Int32 in 0...1024 {
            var addr = sockaddr_ctl()
            var len = socklen_t(MemoryLayout.size(ofValue: addr))
            let ret = withUnsafeMutablePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(fd, $0, &len) }
            }
            if ret != 0 || addr.sc_family != AF_SYSTEM { continue }
            if info.ctl_id == 0, ioctl(fd, CTLIOCGINFO, &info) != 0 { continue }
            if addr.sc_id == info.ctl_id { return fd }
        }
        return nil
    }
}
