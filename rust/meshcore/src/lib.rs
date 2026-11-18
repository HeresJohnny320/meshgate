//! The phone apps' native library. It exposes meshgate's mobile engine
//! (meshgate::mobile) with the same API the Go core had under gomobile, so
//! the apps keep their code:
//!
//! - Android: JNI for the Java classes in dev.meshgate.meshcore (Meshcore,
//!   Engine, Platform), shipped with the app.
//! - iOS (and macOS): a C API (capi.rs, include/meshcore.h) wrapped by Swift
//!   classes of the same names (go/mobile/ios/Shared/Meshcore.swift).

#[cfg(target_os = "android")]
mod android;
// Built everywhere but Android so it is tested on Linux too.
#[cfg(not(target_os = "android"))]
pub mod capi;
