package dev.meshgate.meshcore;

/** One device's mesh client (meshgate::mobile::Engine). Blocking calls run off the UI thread. */
public final class Engine {
    private final long h;

    Engine(long handle) {
        this.h = handle;
    }

    public String admin(String method, String path, String body) { return admin(h, method, path, body); }
    public String changelog() { return changelog(h); }
    public String diag(String kind, String target, long port) { return diag(h, kind, target, port); }
    public void downloadAPK(String tag, String path) throws Exception { downloadAPK(h, tag, path); }
    public boolean isJoined() { return isJoined(h); }
    public void join(String token, String deviceName) throws Exception { join(h, token, deviceName); }
    public boolean killSwitch() { return killSwitch(h); }
    public void leave() throws Exception { leave(h); }
    public void networkChanged() { networkChanged(h); }
    public void setExitChoice(String id) throws Exception { setExitChoice(h, id); }
    public void setKillSwitch(boolean on) throws Exception { setKillSwitch(h, on); }
    public void start() throws Exception { start(h); }
    public String statusJSON() { return statusJSON(h); }
    public void stop() { stop(h); }
    public String updateAvailable(String appVersion) { return updateAvailable(h, appVersion); }

    private static native String admin(long h, String method, String path, String body);
    private static native String changelog(long h);
    private static native String diag(long h, String kind, String target, long port);
    private static native void downloadAPK(long h, String tag, String path) throws Exception;
    private static native boolean isJoined(long h);
    private static native void join(long h, String token, String deviceName) throws Exception;
    private static native boolean killSwitch(long h);
    private static native void leave(long h) throws Exception;
    private static native void networkChanged(long h);
    private static native void setExitChoice(long h, String id) throws Exception;
    private static native void setKillSwitch(long h, boolean on) throws Exception;
    private static native void start(long h) throws Exception;
    private static native String statusJSON(long h);
    private static native void stop(long h);
    private static native String updateAvailable(long h, String appVersion);
}
