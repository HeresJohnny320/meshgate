// The web UI, changelog and pfSense pages are shared files under go/ that
// the binary embeds. MESHGATE_GO_DIR points at that folder; it defaults to
// ../go and is set explicitly for `cross`, whose container only sees rust/
// (Cross.toml mounts the folder at the same path).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MESHGATE_GO_DIR");
    let dir = std::env::var("MESHGATE_GO_DIR").unwrap_or_else(|_| format!("{}/../go", std::env::var("CARGO_MANIFEST_DIR").unwrap()));
    println!("cargo:rustc-env=MESHGATE_GO_DIR={dir}");
}
