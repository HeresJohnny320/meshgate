import Foundation
import Meshcore // the C API of libmeshcore (rust/meshcore/include/meshcore.h)

// Swift face of the Rust engine with the same names the gomobile framework
// had, so the app and tunnel code did not change when the core moved to Rust.

/// Callbacks the engine makes into the app; called from any thread.
protocol MeshcorePlatformProtocol: AnyObject {
    /// Keeps a socket out of the tunnel.
    func protect(_ fd: Int32) -> Bool
    /// Applies tunnel settings (JSON) and returns the tunnel's descriptor, or -1.
    func configureTunnel(_ settingsJSON: String?) -> Int32
    /// The device's own IPv4 addresses, comma separated.
    func localAddresses() -> String
    func log(_ msg: String?)
}

private final class PlatformBox {
    let p: MeshcorePlatformProtocol
    init(_ p: MeshcorePlatformProtocol) { self.p = p }
}

private func box(_ ctx: UnsafeMutableRawPointer?) -> MeshcorePlatformProtocol {
    Unmanaged<PlatformBox>.fromOpaque(ctx!).takeUnretainedValue().p
}

private func str(_ p: UnsafePointer<CChar>?) -> String? {
    p.map { String(cString: $0) }
}

/// Takes ownership of a string returned by the library.
private func take(_ p: UnsafeMutablePointer<CChar>?) -> String {
    guard let p else { return "" }
    defer { mc_string_free(p) }
    return String(cString: p)
}

private func check(_ ok: Bool, _ err: UnsafeMutablePointer<CChar>?) throws {
    let msg = take(err)
    if !ok { throw NSError(domain: "meshgate", code: 1, userInfo: [NSLocalizedDescriptionKey: msg]) }
}

final class MeshcoreEngine {
    fileprivate let h: OpaquePointer

    fileprivate init(_ h: OpaquePointer) { self.h = h }
    deinit { mc_engine_free(h) }

    func isJoined() -> Bool { mc_engine_is_joined(h) }

    func join(_ token: String?, deviceName: String?) throws {
        var err: UnsafeMutablePointer<CChar>?
        try check(mc_engine_join(h, token ?? "", deviceName ?? "", &err), err)
    }

    func leave() throws {
        var err: UnsafeMutablePointer<CChar>?
        try check(mc_engine_leave(h, &err), err)
    }

    func start() throws {
        var err: UnsafeMutablePointer<CChar>?
        try check(mc_engine_start(h, &err), err)
    }

    func stop() { mc_engine_stop(h) }
    func networkChanged() { mc_engine_network_changed(h) }
    func statusJSON() -> String { take(mc_engine_status_json(h)) }

    func diag(_ kind: String?, target: String?, port: Int64) -> String {
        take(mc_engine_diag(h, kind ?? "", target ?? "", port))
    }

    func setExitChoice(_ id: String?) throws {
        var err: UnsafeMutablePointer<CChar>?
        try check(mc_engine_set_exit_choice(h, id ?? "", &err), err)
    }

    func killSwitch() -> Bool { mc_engine_kill_switch(h) }

    func setKillSwitch(_ on: Bool) throws {
        var err: UnsafeMutablePointer<CChar>?
        try check(mc_engine_set_kill_switch(h, on, &err), err)
    }

    func admin(_ method: String?, path: String?, body: String?) -> String {
        take(mc_engine_admin(h, method ?? "", path ?? "", body ?? ""))
    }

    func updateAvailable(_ appVersion: String?) -> String {
        take(mc_engine_update_available(h, appVersion ?? ""))
    }

    func changelog() -> String { take(mc_engine_changelog(h)) }
}

/// Creates the engine with its state in dir; nil and error set on failure.
func MeshcoreNewEngine(_ dir: String?, _ plat: MeshcorePlatformProtocol?, _ error: NSErrorPointer) -> MeshcoreEngine? {
    guard let plat else {
        error?.pointee = NSError(domain: "meshgate", code: 1, userInfo: [NSLocalizedDescriptionKey: "no platform"])
        return nil
    }
    let ctx = Unmanaged.passRetained(PlatformBox(plat)).toOpaque()
    let p = mc_platform(
        ctx: ctx,
        protect: { ctx, fd in box(ctx).protect(fd) },
        configure_tunnel: { ctx, json in box(ctx).configureTunnel(str(json)) },
        local_addresses: { ctx in strdup(box(ctx).localAddresses()) },
        log: { ctx, msg in box(ctx).log(str(msg)) },
        release: { ctx in Unmanaged<PlatformBox>.fromOpaque(ctx!).release() }
    )
    var err: UnsafeMutablePointer<CChar>?
    guard let h = mc_engine_new(dir ?? "", p, &err) else {
        let msg = take(err)
        error?.pointee = NSError(domain: "meshgate", code: 1, userInfo: [NSLocalizedDescriptionKey: msg])
        return nil
    }
    return MeshcoreEngine(h)
}
