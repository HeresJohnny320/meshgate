//! C API for the iOS (and macOS) apps, declared in include/meshcore.h and
//! wrapped by go/mobile/ios/Shared/Meshcore.swift into the same Swift API the
//! gomobile framework had (MeshcoreEngine, MeshcoreNewEngine,
//! MeshcorePlatformProtocol).
//!
//! Strings passed in are borrowed, NUL-terminated UTF-8. Strings returned are
//! owned by the caller and freed with mc_string_free. A returned error string
//! (out parameter `err`) is NULL on success.

// Every function here takes pointers from C by design; the header documents
// what they must point to.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Arc;

use meshgate::mobile::{Engine, Platform};

/// The app's platform callbacks. `ctx` is passed back to every callback and
/// released through `release` once the engine no longer needs it.
#[repr(C)]
pub struct McPlatform {
    pub ctx: *mut c_void,
    pub protect: extern "C" fn(ctx: *mut c_void, fd: i32) -> bool,
    pub configure_tunnel: extern "C" fn(ctx: *mut c_void, settings_json: *const c_char) -> i32,
    /// Returns a malloc'd string (freed by the library with free()), or NULL.
    pub local_addresses: extern "C" fn(ctx: *mut c_void) -> *mut c_char,
    pub log: extern "C" fn(ctx: *mut c_void, msg: *const c_char),
    pub release: extern "C" fn(ctx: *mut c_void),
}

struct CPlatform(McPlatform);

// SAFETY: the Swift side's callbacks are thread-safe (the gomobile contract
// the apps were already written for: the Go engine called them from any
// goroutine).
unsafe impl Send for CPlatform {}
unsafe impl Sync for CPlatform {}

impl Drop for CPlatform {
    fn drop(&mut self) {
        (self.0.release)(self.0.ctx);
    }
}

fn cstring(s: String) -> CString {
    CString::new(s.replace('\0', "")).unwrap_or_default()
}

impl Platform for CPlatform {
    fn protect(&self, fd: i32) -> bool {
        (self.0.protect)(self.0.ctx, fd)
    }

    fn configure_tunnel(&self, settings_json: String) -> i32 {
        let s = cstring(settings_json);
        (self.0.configure_tunnel)(self.0.ctx, s.as_ptr())
    }

    fn local_addresses(&self) -> String {
        let p = (self.0.local_addresses)(self.0.ctx);
        if p.is_null() {
            return String::new();
        }
        // SAFETY: the callback returns a malloc'd NUL-terminated string.
        let s = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        unsafe { libc::free(p as *mut c_void) };
        s
    }

    fn log(&self, msg: String) {
        let s = cstring(msg);
        (self.0.log)(self.0.ctx, s.as_ptr());
    }
}

/// An engine handle, freed with mc_engine_free.
pub struct McEngine(Arc<Engine>);

fn arg(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the caller passes a NUL-terminated string.
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn ret(s: String) -> *mut c_char {
    cstring(s).into_raw()
}

/// Stores an error for the caller; returns whether the call succeeded.
fn result(r: Result<(), String>, err: *mut *mut c_char) -> bool {
    match r {
        Ok(()) => {
            if !err.is_null() {
                // SAFETY: err points to the caller's out variable.
                unsafe { *err = std::ptr::null_mut() };
            }
            true
        }
        Err(e) => {
            if !err.is_null() {
                // SAFETY: as above.
                unsafe { *err = ret(e) };
            }
            false
        }
    }
}

fn eng<'a>(h: *const McEngine) -> &'a Arc<Engine> {
    // SAFETY: h comes from mc_engine_new and is not freed while in use.
    unsafe { &(*h).0 }
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_string_free(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: s was returned by this library.
        drop(unsafe { CString::from_raw(s) });
    }
}

/// Creates an engine keeping its state in dir. On failure returns NULL and
/// sets *err. The platform is released when the engine is gone.
#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_new(dir: *const c_char, plat: McPlatform, err: *mut *mut c_char) -> *mut McEngine {
    let plat = Arc::new(CPlatform(plat));
    match Engine::new(&arg(dir), plat) {
        Ok(e) => {
            result(Ok(()), err);
            Box::into_raw(Box::new(McEngine(e)))
        }
        Err(e) => {
            result(Err(e), err);
            std::ptr::null_mut()
        }
    }
}

/// Drops the handle (stop the engine first).
#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_free(h: *mut McEngine) {
    if !h.is_null() {
        // SAFETY: h came from mc_engine_new.
        drop(unsafe { Box::from_raw(h) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_is_joined(h: *const McEngine) -> bool {
    eng(h).is_joined()
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_join(h: *const McEngine, token: *const c_char, name: *const c_char, err: *mut *mut c_char) -> bool {
    result(eng(h).join(&arg(token), &arg(name)), err)
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_leave(h: *const McEngine, err: *mut *mut c_char) -> bool {
    result(eng(h).leave(), err)
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_start(h: *const McEngine, err: *mut *mut c_char) -> bool {
    result(eng(h).start(), err)
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_stop(h: *const McEngine) {
    eng(h).stop()
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_network_changed(h: *const McEngine) {
    eng(h).network_changed()
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_status_json(h: *const McEngine) -> *mut c_char {
    ret(eng(h).status_json())
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_diag(h: *const McEngine, kind: *const c_char, target: *const c_char, port: i64) -> *mut c_char {
    ret(eng(h).diag(&arg(kind), &arg(target), port))
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_set_exit_choice(h: *const McEngine, id: *const c_char, err: *mut *mut c_char) -> bool {
    result(eng(h).set_exit_choice(&arg(id)), err)
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_kill_switch(h: *const McEngine) -> bool {
    eng(h).kill_switch()
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_set_kill_switch(h: *const McEngine, on: bool, err: *mut *mut c_char) -> bool {
    result(eng(h).set_kill_switch(on), err)
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_admin(h: *const McEngine, method: *const c_char, path: *const c_char, body: *const c_char) -> *mut c_char {
    ret(eng(h).admin(&arg(method), &arg(path), &arg(body)))
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_update_available(h: *const McEngine, app_version: *const c_char) -> *mut c_char {
    ret(eng(h).update_available(&arg(app_version)))
}

#[unsafe(no_mangle)]
pub extern "C" fn mc_engine_changelog(h: *const McEngine) -> *mut c_char {
    ret(eng(h).changelog())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static RELEASED: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn protect(_: *mut c_void, _: i32) -> bool {
        true
    }
    extern "C" fn configure(_: *mut c_void, _: *const c_char) -> i32 {
        -1
    }
    extern "C" fn addrs(_: *mut c_void) -> *mut c_char {
        // SAFETY: strdup of a literal; the library frees it.
        unsafe { libc::strdup(c"192.0.2.1".as_ptr()) }
    }
    extern "C" fn log(_: *mut c_void, _: *const c_char) {}
    extern "C" fn release(ctx: *mut c_void) {
        assert_eq!(ctx as usize, 0x1234);
        RELEASED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn engine_through_c_api() {
        let dir = std::env::temp_dir().join(format!("meshcore-capi-{}", std::process::id()));
        let cdir = CString::new(dir.to_str().unwrap()).unwrap();
        let plat = McPlatform { ctx: 0x1234 as *mut c_void, protect, configure_tunnel: configure, local_addresses: addrs, log, release };
        let mut err: *mut c_char = std::ptr::null_mut();
        let h = mc_engine_new(cdir.as_ptr(), plat, &mut err);
        assert!(!h.is_null() && err.is_null());
        assert!(!mc_engine_is_joined(h));

        // Errors come back as owned strings.
        assert!(!mc_engine_join(h, c"not-a-token".as_ptr(), c"phone".as_ptr(), &mut err));
        assert!(!err.is_null());
        mc_string_free(err);

        let s = mc_engine_status_json(h);
        let status = arg(s);
        mc_string_free(s);
        assert!(status.starts_with('{'), "{status}");

        assert_eq!(RELEASED.load(Ordering::SeqCst), 0);
        mc_engine_free(h);
        assert_eq!(RELEASED.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(dir);
    }
}
