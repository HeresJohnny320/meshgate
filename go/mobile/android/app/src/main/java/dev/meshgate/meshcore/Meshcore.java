package dev.meshgate.meshcore;

/**
 * Entry point of the native engine (libmeshcore.so, built from rust/meshcore).
 * Same API as the Go core had under gomobile.
 */
public abstract class Meshcore {
    static {
        System.loadLibrary("meshcore");
    }

    private Meshcore() {}

    /** Opens (or prepares) state in dir; one engine per process. */
    public static Engine newEngine(String dir, Platform plat) throws Exception {
        return new Engine(nativeNew(dir, plat));
    }

    private static native long nativeNew(String dir, Platform plat) throws Exception;
}
