//! JNI for dev.meshgate.meshcore.{Meshcore,Engine} (Java side:
//! go/mobile/android/app/src/main/java/dev/meshgate/meshcore).

use std::sync::Arc;

use jni::objects::{GlobalRef, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jstring};
use jni::{JNIEnv, JavaVM};
use meshgate::mobile::{Engine, Platform};

/// The app's Platform object, called from any thread.
struct JavaPlatform {
    vm: JavaVM,
    obj: GlobalRef,
}

impl JavaPlatform {
    fn with<R>(&self, f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<R>) -> Option<R> {
        let mut env = self.vm.attach_current_thread_permanently().ok()?;
        let r = f(&mut env, self.obj.as_obj());
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_describe();
            let _ = env.exception_clear();
            return None;
        }
        r.ok()
    }
}

impl Platform for JavaPlatform {
    fn protect(&self, fd: i32) -> bool {
        self.with(|env, o| env.call_method(o, "protect", "(I)Z", &[JValue::Int(fd)])?.z()).unwrap_or(false)
    }

    fn configure_tunnel(&self, settings_json: String) -> i32 {
        self.with(|env, o| {
            let s = env.new_string(&settings_json)?;
            env.call_method(o, "configureTunnel", "(Ljava/lang/String;)I", &[JValue::Object(&s)])?.i()
        })
        .unwrap_or(-1)
    }

    fn local_addresses(&self) -> String {
        self.with(|env, o| {
            let v = env.call_method(o, "localAddresses", "()Ljava/lang/String;", &[])?.l()?;
            let s: String = env.get_string(&JString::from(v))?.into();
            Ok(s)
        })
        .unwrap_or_default()
    }

    fn log(&self, msg: String) {
        self.with(|env, o| {
            let s = env.new_string(&msg)?;
            env.call_method(o, "log", "(Ljava/lang/String;)V", &[JValue::Object(&s)])?;
            Ok(())
        });
    }
}

fn s(env: &mut JNIEnv, v: &JString) -> String {
    env.get_string(v).map(Into::into).unwrap_or_default()
}

fn out(env: &mut JNIEnv, v: String) -> jstring {
    env.new_string(v).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

fn throw(env: &mut JNIEnv, r: Result<(), String>) {
    if let Err(e) = r {
        let _ = env.throw_new("java/lang/Exception", e);
    }
}

/// The engine behind a handle (an Arc leaked into Java, never freed: one
/// engine lives for the app's lifetime, as with gomobile).
fn eng(h: jlong) -> &'static Arc<Engine> {
    // SAFETY: h comes from nativeNew below and is never freed.
    unsafe { &*(h as *const Arc<Engine>) }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Meshcore_nativeNew(mut env: JNIEnv, _c: JClass, dir: JString, plat: JObject) -> jlong {
    let dir = s(&mut env, &dir);
    let (Ok(vm), Ok(obj)) = (env.get_java_vm(), env.new_global_ref(&plat)) else { return 0 };
    match Engine::new(&dir, Arc::new(JavaPlatform { vm, obj })) {
        Ok(e) => Box::into_raw(Box::new(e)) as jlong,
        Err(e) => {
            let _ = env.throw_new("java/lang/Exception", e);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_admin(
    mut env: JNIEnv,
    _c: JClass,
    h: jlong,
    m: JString,
    p: JString,
    b: JString,
) -> jstring {
    let (m, p, b) = (s(&mut env, &m), s(&mut env, &p), s(&mut env, &b));
    let r = eng(h).admin(&m, &p, &b);
    out(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_changelog(mut env: JNIEnv, _c: JClass, h: jlong) -> jstring {
    let r = eng(h).changelog();
    out(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_diag(
    mut env: JNIEnv,
    _c: JClass,
    h: jlong,
    k: JString,
    t: JString,
    port: jlong,
) -> jstring {
    let (k, t) = (s(&mut env, &k), s(&mut env, &t));
    let r = eng(h).diag(&k, &t, port);
    out(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_downloadAPK(mut env: JNIEnv, _c: JClass, h: jlong, tag: JString, path: JString) {
    let (tag, path) = (s(&mut env, &tag), s(&mut env, &path));
    let r = eng(h).download_apk(&tag, &path);
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_isJoined(_env: JNIEnv, _c: JClass, h: jlong) -> jboolean {
    eng(h).is_joined() as jboolean
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_join(mut env: JNIEnv, _c: JClass, h: jlong, tok: JString, name: JString) {
    let (tok, name) = (s(&mut env, &tok), s(&mut env, &name));
    let r = eng(h).join(&tok, &name);
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_killSwitch(_env: JNIEnv, _c: JClass, h: jlong) -> jboolean {
    eng(h).kill_switch() as jboolean
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_leave(mut env: JNIEnv, _c: JClass, h: jlong) {
    let r = eng(h).leave();
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_networkChanged(_env: JNIEnv, _c: JClass, h: jlong) {
    eng(h).network_changed();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_setExitChoice(mut env: JNIEnv, _c: JClass, h: jlong, id: JString) {
    let id = s(&mut env, &id);
    let r = eng(h).set_exit_choice(&id);
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_setKillSwitch(mut env: JNIEnv, _c: JClass, h: jlong, on: jboolean) {
    let r = eng(h).set_kill_switch(on != 0);
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_start(mut env: JNIEnv, _c: JClass, h: jlong) {
    let r = eng(h).start();
    throw(&mut env, r);
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_statusJSON(mut env: JNIEnv, _c: JClass, h: jlong) -> jstring {
    let r = eng(h).status_json();
    out(&mut env, r)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_stop(_env: JNIEnv, _c: JClass, h: jlong) {
    eng(h).stop();
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_meshgate_meshcore_Engine_updateAvailable(mut env: JNIEnv, _c: JClass, h: jlong, v: JString) -> jstring {
    let v = s(&mut env, &v);
    let r = eng(h).update_available(&v);
    out(&mut env, r)
}

#[allow(dead_code)]
fn _unused(_: jint) {}
