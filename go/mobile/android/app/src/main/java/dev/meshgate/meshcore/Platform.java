package dev.meshgate.meshcore;

/** Implemented by the app: the engine calls it from its own threads. */
public interface Platform {
    /** Keeps a socket outside the VPN (VpnService.protect). */
    boolean protect(int fd);

    /** Applies TunnelSettings JSON; returns the TUN descriptor, -1 on failure. */
    int configureTunnel(String settingsJSON);

    /** This device's non-VPN IPv4 addresses, comma separated. */
    String localAddresses();

    void log(String msg);
}
